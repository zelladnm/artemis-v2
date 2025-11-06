# main.py (Ultimate Version 2.4 - Incremental Update)每周运行一次
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm
import logging
import json
import time

from src.api.bazaar_client import BazaarClient
from src.api.vt_client import VirusTotalClient
from src.processing.data_parser import create_document_from_report
from src.knowledge_base.vector_store import VectorStoreManager

from langchain_core.documents import Document

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def sanitize_metadata(documents: list[Document]) -> list[Document]:
    for doc in documents:
        for key, value in doc.metadata.items():
            if isinstance(value, list):
                doc.metadata[key] = ", ".join(map(str, value))
    return documents


def get_dir_size(path='.'):
    total = 0
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file():
                total += entry.stat().st_size
            elif entry.is_dir():
                total += get_dir_size(entry.path)
    return total


def print_update_summary(source_docs_added: int, vectors_added: int, vector_store_manager: VectorStoreManager,
                         config: dict):
    """打印本次更新的摘要和知识库的总规模"""
    db_path = Path(config['data_paths']['vector_db'])
    total_vectors = vector_store_manager.get_vector_count()
    disk_size_mb = get_dir_size(db_path) / (1024 * 1024)

    print("\n" + "=" * 50)
    print(" KNOWLEDGE BASE UPDATE SUMMARY ".center(50, "="))
    print("=" * 50)
    print("--- This Run ---")
    print(f"  - New Source Documents Processed: {source_docs_added}")
    print(f"  - New Vectors Added to DB:        {vectors_added}")
    print("\n--- Knowledge Base Totals ---")
    print(f"  - Total Vectors in DB:            {total_vectors}")
    print(f"  - Total Disk Space Usage:         {disk_size_mb:.2f} MB")
    print("=" * 50 + "\n")


def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    start_time = time.time()
    load_dotenv()
    config = load_config()

    # --- 初始化客户端和管理器 ---
    vt_api_key = os.getenv("VT_API_KEY")
    bazaar_api_key = os.getenv("BAZAAR_API_KEY")
    vt_client = VirusTotalClient(api_key=vt_api_key, base_url=config['vt_api_url'])
    bazaar_client = BazaarClient(base_url=config['bazaar_api_url'], api_key=bazaar_api_key)
    vector_store_manager = VectorStoreManager(config)

    # --- 增量更新逻辑 ---
    logging.info("--- Starting Daily Knowledge Base Update ---")

    # 1. 扫描本地已有报告哈希
    raw_vt_path = Path(config['data_paths']['raw_vt_reports'])
    raw_vt_path.mkdir(exist_ok=True)  # 确保目录存在
    existing_hashes = {p.stem for p in raw_vt_path.glob("*.json")}
    logging.info(f"Found {len(existing_hashes)} existing VT reports locally.")

    # 2. 从Bazaar获取最新哈希并计算差集
    MALWARE_FAMILIES = ["redline", "qakbot", "agenttesla", "emotet", "stuxnet", "wannacry", "trickbot", "zeus",
                        "lazarus", "cert_wiper"]
    SAMPLES_TO_CHECK = 50  # 每次检查最新的50个样本，确保不会错过

    new_hashes_to_process = []
    for family in MALWARE_FAMILIES:
        logging.info(f"Checking for new samples for family: {family}")
        remote_hashes = bazaar_client.get_hashes_by_family(family, limit=SAMPLES_TO_CHECK)
        new_for_family = [h for h in remote_hashes if h not in existing_hashes]
        if new_for_family:
            logging.info(f"Found {len(new_for_family)} new sample(s) for {family}: {new_for_family}")
            new_hashes_to_process.extend([(family, h) for h in new_for_family])
        time.sleep(1)  # 短暂间隔，避免对Bazaar API请求过快

    # 3. 精确处理新哈希
    new_documents = []
    if new_hashes_to_process:
        for family, file_hash in tqdm(new_hashes_to_process, desc="Processing new samples"):
            # 下载新报告
            success = vt_client.download_and_save_report(file_hash, raw_vt_path)
            if success:
                # 解析新报告
                report_path = raw_vt_path / f"{file_hash}.json"
                try:
                    content = create_document_from_report(report_path, family_name=family)
                    doc = Document(
                        page_content=content,
                        metadata={"source": report_path.name, "family": family, "type": "vt_report"}
                    )
                    new_documents.append(doc)
                except Exception as e:
                    logging.error(f"Failed to parse new report {report_path.name}: {e}")
    else:
        logging.info("No new malware samples found from VirusTotal/Bazaar sources.")

    # 注意：PDF和YARA规则的增量更新逻辑更复杂，通常涉及文件哈希对比或数据库记录。
    # 目前，对于手动添加的PDF/YARA，最简单的“更新”方式是：添加新文件后，删除vector_db并完整重建一次。
    # 本脚本的自动更新主要针对VT报告。

    # 4. 增量入库
    sanitized_docs = sanitize_metadata(new_documents)
    vectors_added_count = vector_store_manager.add_documents(sanitized_docs)

    # 5. 打印总结报告
    print_update_summary(len(new_documents), vectors_added_count, vector_store_manager, config)

    end_time = time.time()
    logging.info(f"Daily update process finished in {end_time - start_time:.2f} seconds.")