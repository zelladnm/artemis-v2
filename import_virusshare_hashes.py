# import_virusshare_hashes.py
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm
import logging
import time
import json

from src.api.vt_client import VirusTotalClient
from src.processing.data_parser import create_document_from_report
from src.knowledge_base.vector_store import VectorStoreManager
from langchain_core.documents import Document
from main import sanitize_metadata

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    load_dotenv()
    config = load_config()

    # --- 配置 ---
    HASH_LIST_DIR = Path("data/external/hash_lists/")
    VT_DAILY_QUOTA = 500
    API_CALL_LIMIT = VT_DAILY_QUOTA - 10
    api_calls_made = 0

    # --- 初始化 ---
    vt_api_key = os.getenv("VT_API_KEY")
    if not vt_api_key:
        raise ValueError("VT_API_KEY not found in .env file.")

    vt_client = VirusTotalClient(api_key=vt_api_key, base_url=config['vt_api_url'])
    vector_store_manager = VectorStoreManager(config)
    raw_vt_path = Path(config['data_paths']['raw_vt_reports'])
    raw_vt_path.mkdir(exist_ok=True)

    logging.info("--- Starting Bulk Import from VirusShare Hash Lists ---")

    # 1. 加载所有要处理的哈希
    all_hashes_from_files = set()
    if not HASH_LIST_DIR.exists() or not any(HASH_LIST_DIR.iterdir()):
        logging.error(f"Hash list directory not found or is empty: {HASH_LIST_DIR}")
        exit()

    for hash_file in HASH_LIST_DIR.glob("*.*"):
        logging.info(f"Reading hashes from {hash_file.name}...")
        with open(hash_file, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    all_hashes_from_files.add(line.strip().lower())

    logging.info(f"Loaded a total of {len(all_hashes_from_files)} unique hashes from files.")

    # 2. 筛选出本地没有的哈希
    existing_hashes = {p.stem.lower() for p in raw_vt_path.glob("*.json")}
    new_hashes_to_process = list(all_hashes_from_files - existing_hashes)

    if not new_hashes_to_process:
        logging.info("All hashes from the lists are already present in the local database. Nothing to do.")
        exit()

    logging.info(f"Found {len(new_hashes_to_process)} new hashes to process.")

    # 3. 下载VT报告
    newly_downloaded_files = []
    for file_hash in tqdm(new_hashes_to_process, desc="Fetching new VT reports"):
        if api_calls_made >= API_CALL_LIMIT:
            logging.warning("Daily API quota limit reached. Halting downloads.")
            break

        # VT API可以处理MD5, SHA1, SHA256，无需转换
        # 我们需要一种方法来知道下载后的文件名（即SHA256）
        # vt_client.download_and_save_report 需要返回最终保存的文件名
        saved_path = vt_client.download_and_save_report(file_hash, raw_vt_path, return_sha256_filename=True)
        api_calls_made += 1
        if saved_path:
            newly_downloaded_files.append(saved_path)

    # 4. 处理并入库
    logging.info(f"\nFinished downloading. A total of {len(newly_downloaded_files)} new reports were fetched.")

    if newly_downloaded_files:
        new_documents = []
        for report_path in tqdm(newly_downloaded_files, desc="Parsing new reports"):
            try:
                # 因为是从哈希列表导入，我们不知道其家族，所以标记为 "Unknown"
                content = create_document_from_report(report_path, family_name="Unknown (from Hashlist)")
                doc = Document(page_content=content,
                               metadata={"source": report_path.name, "family": "unknown_hashlist", "type": "vt_report"})
                new_documents.append(doc)
            except Exception as e:
                logging.error(f"Failed to parse new report {report_path.name}: {e}")

        sanitized_docs = sanitize_metadata(new_documents)
        vectors_added_count = vector_store_manager.add_documents(sanitized_docs)
    else:
        vectors_added_count = 0

    logging.info(f"\n--- Bulk Import Session Summary ---")
    logging.info(f"API Calls Made: {api_calls_made}")
    logging.info(f"New Reports Processed: {len(newly_downloaded_files)}")
    logging.info(f"New Vectors Added to DB: {vectors_added_count}")

    if api_calls_made >= API_CALL_LIMIT:
        logging.info("\nIMPORTANT: Daily API quota reached. Run this script again tomorrow to continue importing.")