# historical_import.py (v3.1 - Goal-Oriented Smart Backfill with Curated List)
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm
import logging
import json
import time
from collections import Counter
import chromadb

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


def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_current_family_counts(config: dict) -> Counter:
    """连接到数据库，统计每个家族已有的向量数量"""
    db_path = str(Path(config['data_paths']['vector_db']))
    collection_name = config['collection_name']
    family_counter = Counter()

    try:
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_collection(name=collection_name)
        metadatas = collection.get(include=["metadatas"]).get('metadatas')
        if metadatas:
            for meta in metadatas:
                if meta.get('type') == 'vt_report':
                    family = meta.get('family', 'Unknown')
                    family_counter[family] += 1
    except Exception as e:
        logging.warning(f"Could not connect to existing DB to get counts (this is normal on first run): {e}")

    return family_counter


if __name__ == "__main__":
    start_time = time.time()
    load_dotenv()
    config = load_config()

    # --- 智能回填配置 ---
    # 1. 这是我们从YARA规则库中提取的、所有需要关注的家族/威胁的完整列表
    # 脚本将自动为这个列表里所有报告数不足200的家族进行补充
    ALL_FAMILIES_TO_MONITOR = [
    "Unknown", "eqgrp_apr17", "agenttesla", "toolkit_redteam_tools_by_guid", "pony", "azorult",
    "plugx", "stealer", "toolkit_thor_hacktools", "emotet", "gozi", "asyncrat", "hancitor",
    "furtim", "icedid", "toolkit_chinese_hacktools", "cerberus", "nanocore", "diamondfox",
    "redline", "cybergate", "adwind", "wannacry", "darkcomet", "njrat", "gafgyt",
    "grizzlybear_uscert", "zeus", "lazarus", "tinba", "cobaltstrike", "trickbot", "cerber",
    "hajime", "equationgrp", "gh0st", "andromeda", "pyinstaller", "citadel", "blackshades",
    "apt1", "empire", "teslacrypt", "toolkit_redteam_tools_by_name", "wildneutron", "kovter",
    "equation", "miscelanea", "upatre", "irontiger", "winnti", "regin", "oilrig", "putterpanda",
    "korplug", "locky", "stuxnet", "malconfscan", "ms17-010_wannacrypt", "mar-10410305.r1.v1.clear.pdf",
    "threatgroup3390", "shifu", "petya", "codoso", "zegost", "snake", "naikon", "ratdecoders",
    "arkei", "jrat", "fiveeyes", "cryptolocker", "maze", "derusbi", "opcleaver", "turla_ruag",
    "surtr", "platinum", "blackenergy", "sauron_extras", "pos", "apt15", "toolkit_passthehash",
    "magento_backend", "duqu2", "predator", "badrabbit", "orcus", "bluetermite_emdivi", "keyboy",
    "mirai", "spora", "hiddencobra", "industroyer", "unit78020", "sendsafe", "tox",
    "toolkit_finfisher_", "samsam", "dubnium", "greenbug", "hackingteam", "moonlightmaze",
    "opduststorm", "exploit_uac_elevators", "keybase", "c16", "hellsing", "passcv", "prikormka",
    "kraken", "apt10", "ponmocup", "cheshirecat", "crashoverride", "deeppanda_anthem", "oppotao",
    "poseidon_group", "sofacy_bundestag", "sphinx_moth", "up007_slserver", "waterbug",
    "woolengoldfish", "atmos", "dirtjumper", "enfal", "athena", "shamoon", "sauron", "terracota",
    "elknot", "magento_frontend", "miscelanea_linux", ".cryptxxx", "ddostf", "purplewave",
    "xtreme", "apt17", "apt29_grizzly_steppe", "casper", "cloudduke", "minidionis",
    "windigo_onimiki", "elex", "fakem", "kins", "kpot", "kwampirs", "linuxmoose", "pe_sections",
    "rebirth_vulcan_elf", "triton_hatman", "cryptonar", "goldeneye", "petya_ms17_010", "gholee",
    "havex", "indetectables", "inocnation", "wabot", "satana", "bestia", "dprk_rokrat",
    "emissary", "grasshopper", "opclandestinewolf", "redleaves", "remsec", "scarab_scieron",
    "shamoon_stonedrill", "sofacy_fysbis", "experimental_beef", "atmpot", "hsdfihdf_banking",
    "httpsd_elf", "iexpl0ree", "jolob_backdoor", "macgyver", "magento_suspicious", "miancha",
    "pittytiger", "quarian", "shifu_shiz", "tinyshell_backdoor_gen", "triton_ics_framework",
    "xdedic_marketplace", "yordanyan_activeagent", "bernhard", "mozart", "comodosec", "petrwrap",
    "revix", "shiva", "poisonivy", "sakula", "xrat20", "toolkit_mandibule", "toolkit_powerstager",
    "toolkit_solarwinds_credential_stealer", "xhide", "erebus", "termite", "netwiredrc",
    "apt9002", "carbanak", "careto", "fvey_shadowbrokers_jan17_screen_strings", "ke3chang_tidepool",
    "sofacy_jun16", "turla_neuron", "almashreq", "chicken", "cloaking", "cookies", "dexter",
    "fareit", "glasses", "imuler", "lurk0", "maccontrol", "msilstealer", "nettraveler",
    "polishbankrat", "rooter", "sayad", "skeleton", "t5000", "torte_elf", "alpha", "locdoor",
    "bolonyokte", "hizor", "toolkit_gen_powerkatz", "fastpos", "sigma", "crimson",
    "000_common_rules", "apt3102", "deputydog", "fancybear_dnc", "kaba", "mirage", "mongall",
    "ngo", "pcclient", "pipcreat", "seaduke", "snowglobe_babar", "tradesecret", "uppercut",
    "gen_powershell", "backdoorssh", "bangat", "blackrev", "blackworm", "buzus_softpulse",
    "cxpid", "ezcob", "favorite", "fudcrypt", "install11", "intel_virtualization", "kelihos",
    "korlia", "lenovo_superfish", "madness", "mailers", "marap", "medusahttp_2019",
    "mirai_okiru_elf", "mirai_satori_elf", "monero_miner_installer", "naspyupdate", "nsfree",
    "odinaff", "olyx", "osx_leverage", "pubsab", "regsubdat", "rockloader", "safenet",
    "scarhikn", "vidgrab", "warp", "wimmie", "yayih", "777", "acroware", "crypren",
    "dmalocker", "doublepulsar_petya", "pico", "screenlocker_5h311_1nj3c706", "crossrat",
    "flyingkitten", "meterpreter_reverse_tcp", "shadowtech", "shim", "terminator",
    "toolkit_exe2hex_payload", "toolkit_pwdump", "cobalt", "backoff", "backspace",
    "energeticbear_backdoored_ssh", "fancybear_downdelph", "hikit", "lotusblossom", "molerats",
    "adwind_rat", "agenttesla_smtp", "alina", "atm_helloworld", "batel", "boouset", "bublik",
    "cap_hookexkeylogger", "corkow", "cythosia", "derkziel", "eicar", "f0xy", "fallchill",
    "genome", "grozlex", "iotreaper", "kirbi_mimikatz", "lateral_movement", "linuxbew",
    "linuxhelios", "lostdoor", "luabot", "luckycat", "miniasp3_mem", "nionspy", "notepad",
    "pyinstaller_osx", "pypi", "rovnix", "sakurel", "sitrof_fortis_scar", "sqlite", "tedroo",
    "treasurehunt", "trumpbot", "urausy", "viotto_keylogger", "virut_fileinfector_unk_version",
    "volgmer", "xmrig_miner", "xor_ddos", "bruteforcingbot", "easterjack", "logpos",
    "malumpos", "gpgqwerty", "jeff_dev", "shrug2", "stampado", "adzok", "bozok", "glass",
    "poetratdoc", "poetratpython", "xrat", "zoxpng", "toolkit_dubrute", "toolkit_wineggdrop"
]
    # 2. 设定每个家族的目标报告数量
    TARGET_REPORTS_PER_FAMILY = 300

    VT_DAILY_QUOTA = 500
    API_CALL_LIMIT = VT_DAILY_QUOTA - 10
    api_calls_made = 0

    vt_client = VirusTotalClient(api_key=os.getenv("VT_API_KEY"), base_url=config['vt_api_url'])
    bazaar_client = BazaarClient(base_url=config['bazaar_api_url'], api_key=os.getenv("BAZAAR_API_KEY"))
    vector_store_manager = VectorStoreManager(config)

    raw_vt_path = Path(config['data_paths']['raw_vt_reports'])
    raw_vt_path.mkdir(exist_ok=True)

    logging.info("--- Starting Goal-Oriented Historical Backfill ---")
    logging.info(f"Target: {TARGET_REPORTS_PER_FAMILY} VT reports per family.")

    current_counts = get_current_family_counts(config)
    logging.info(f"Current VT report counts: {len(current_counts)} families tracked.")

    families_to_backfill = []
    for family in ALL_FAMILIES_TO_MONITOR:
        family_lower = family.lower()
        needed = TARGET_REPORTS_PER_FAMILY - current_counts.get(family_lower, 0)
        if needed > 0:
            families_to_backfill.append({'name': family_lower, 'needed': needed})

    if not families_to_backfill:
        logging.info("Congratulations! All monitored families have reached the target report count. Nothing to do.")
        exit()

    logging.info(f"{len(families_to_backfill)} families need backfilling.")

    newly_downloaded_reports = []

    # 按需获取，优先补充缺口最大的家族
    families_to_backfill.sort(key=lambda x: x['needed'], reverse=True)

    for family_info in families_to_backfill:
        if api_calls_made >= API_CALL_LIMIT:
            logging.warning(f"Approaching daily API quota limit. Halting further downloads for this session.")
            break

        family_name = family_info['name']
        reports_needed = family_info['needed']

        fetch_limit = min(reports_needed * 2, 1000)  # 请求稍多一些以过滤掉已有的

        logging.info(f"--- Processing family: {family_name.upper()}. Need to fetch {reports_needed} new reports. ---")

        historical_hashes = bazaar_client.get_hashes_by_family(family_name, limit=fetch_limit)
        if not historical_hashes:
            logging.warning(f"No samples found for {family_name} on Malware Bazaar. Skipping.")
            continue

        existing_hashes = {p.stem for p in raw_vt_path.glob("*.json")}
        new_hashes = [h for h in historical_hashes if h not in existing_hashes]

        logging.info(f"Found {len(new_hashes)} new unseen samples for {family_name}.")

        # 只下载实际需要的数量
        hashes_to_download = new_hashes[:reports_needed]

        for file_hash in tqdm(hashes_to_download, desc=f"Backfilling {family_name}"):
            if api_calls_made >= API_CALL_LIMIT:
                logging.warning(f"Daily API quota limit reached. Stopping.")
                break

            saved_path = vt_client.download_and_save_report(file_hash, raw_vt_path, return_sha256_filename=True)
            api_calls_made += 1
            if saved_path:
                newly_downloaded_reports.append((family_name, saved_path))

    logging.info(
        f"\nFinished downloading. A total of {len(newly_downloaded_reports)} new reports were fetched in this session.")

    if newly_downloaded_reports:
        new_documents = []
        for family, report_path in tqdm(newly_downloaded_reports, desc="Parsing new reports"):
            try:
                content = create_document_from_report(report_path, family_name=family)
                doc = Document(page_content=content,
                               metadata={"source": report_path.name, "family": family, "type": "vt_report"})
                new_documents.append(doc)
            except Exception as e:
                logging.error(f"Failed to parse new report {report_path.name}: {e}")

        sanitized_docs = sanitize_metadata(new_documents)
        vectors_added_count = vector_store_manager.add_documents(sanitized_docs)
    else:
        vectors_added_count = 0

    logging.info(f"\n--- Historical Backfill Session Summary ---")
    logging.info(f"API Calls Made in This Session: {api_calls_made}")
    logging.info(f"New Reports Downloaded: {len(newly_downloaded_reports)}")
    logging.info(f"New Vectors Added to DB: {vectors_added_count}")
    logging.info(f"Total vectors in DB now: {vector_store_manager.get_vector_count()}")

    end_time = time.time()
    logging.info(f"Backfill session finished in {end_time - start_time:.2f} seconds.")
    if api_calls_made >= API_CALL_LIMIT:
        logging.info("\nIMPORTANT: Daily API quota reached. Run this script again tomorrow to continue backfilling.")