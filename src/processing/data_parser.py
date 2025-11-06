# src/processing/data_parser.py (Final Version)
import json
from pathlib import Path
import logging
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 一个可疑API函数的列表，用于高亮显示。这个列表可以不断扩充。
SUSPICIOUS_API_FUNCTIONS = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "ReadProcessMemory",  # Process Injection
    "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpenRequest", "HttpSendRequestA",  # Downloader
    "CryptEncrypt", "CryptGenKey", "CryptAcquireContext",  # Encryption/Ransomware
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetForegroundWindow",  # Keylogger/Spyware
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",  # Anti-Debug
    "LdrLoadDll", "GetProcAddress",  # Dynamic Loading
    "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"  # Execution
}


def _get_attribute(data: dict, path: list, default=None):
    """安全地从嵌套字典中获取值"""
    temp = data
    for key in path:
        if isinstance(temp, dict):
            temp = temp.get(key)
        else:
            return default
    return temp if temp is not None else default


def _format_list(title: str, items: set, limit: int = 10, code_format=True) -> str:
    """通用列表格式化函数"""
    if not items:
        return ""

    text = f"- **{title}:**\n"
    item_format = "`{}`" if code_format else "{}"
    for item in sorted(list(items))[:limit]:
        text += f"  - {item_format.format(item)}\n"
    return text


def _format_pe_imports(report_json: dict) -> str:
    """格式化PE导入表，高亮可疑函数"""
    text = "### 📥 PE Import Analysis (Function Imports)\n"
    imports = _get_attribute(report_json, ['data', 'attributes', 'pe_info', 'import_list'], [])
    if not imports:
        return text + "No PE import data available.\n"

    suspicious_found = set()
    all_dlls = set()
    total_funcs = 0

    for imp in imports:
        library_name = imp.get('library_name', 'unknown.dll')
        all_dlls.add(library_name)
        for func in imp.get('imported_functions', []):
            total_funcs += 1
            if func in SUSPICIOUS_API_FUNCTIONS:
                suspicious_found.add(f"{library_name} -> {func}")

    text += f"Imports from **{len(all_dlls)}** unique DLLs with a total of **{total_funcs}** functions.\n"
    if suspicious_found:
        text += _format_list("Potentially Suspicious Imported Functions", suspicious_found, limit=20, code_format=False)
    else:
        text += "- No high-suspicion API functions found in the import table.\n"
    return text


def _format_av_detections(report_json: dict) -> str:
    """格式化并聚合AV引擎的检测名称"""
    text = "### 🛡️ Antivirus Detection Analysis\n"
    results = _get_attribute(report_json, ['data', 'attributes', 'last_analysis_results'], {})
    stats = _get_attribute(report_json, ['data', 'attributes', 'last_analysis_stats'], {})

    detection_rate = f"{stats.get('malicious', 0)} / {sum(stats.values())}"
    text += f"- **Detection Rate:** {detection_rate}\n"

    detection_names = [res['result'] for res in results.values() if
                       res.get('result') and res.get('category') == 'malicious']
    if not detection_names:
        text += "- No malicious detections reported by AV engines.\n"
        return text

    cleaned_names = []
    for name in detection_names:
        parts = name.replace('.', ':').split(':')
        meaningful_parts = [p for p in parts if
                            p.lower() not in ['trojan', 'win32', 'win64', 'generic', 'variant', 'heur', 'a', 'b', 'gen',
                                              'w32', 'agent']]
        if meaningful_parts:
            cleaned_names.append(".".join(meaningful_parts))

    name_counts = Counter(cleaned_names).most_common(5)

    text += "- **Top 5 Common Detections:**\n"
    for name, count in name_counts:
        text += f"  - `{name}` (seen {count} times)\n"
    return text


def _format_pe_structure(report_json: dict) -> str:
    """格式化PE文件结构信息, 识别打包特征"""
    text = "### 📦 PE Structure & Packer Analysis\n"
    pe_info = _get_attribute(report_json, ['data', 'attributes', 'pe_info'], {})
    if not pe_info:
        return text + "Not a PE file or no structural info available.\n"

    packers = _get_attribute(report_json, ['data', 'attributes', 'signature_info', 'packer'], [])
    if packers:
        text += f"- **Detected Packer:** `{', '.join(packers)}`\n"

    sections = pe_info.get('sections', [])
    high_entropy_sections = []
    suspicious_names = []
    for section in sections:
        name = section.get('name')
        entropy = section.get('entropy', 0)
        if entropy > 7.5:
            high_entropy_sections.append(f"{name} (Entropy: {entropy:.2f})")
        if name and not name.startswith('.') and name not in ['CODE', 'DATA', 'BSS', 'rsrc']:
            suspicious_names.append(name)

    if high_entropy_sections:
        text += f"- **High-Entropy Sections (possible packing/encryption):** `{', '.join(high_entropy_sections)}`\n"
    if suspicious_names:
        text += f"- **Suspicious Section Names:** `{', '.join(suspicious_names)}`\n"

    if not packers and not high_entropy_sections and not suspicious_names:
        text += "- No obvious signs of packing or obfuscation detected.\n"

    return text


def _format_mitre_ttps(report_json: dict) -> str:
    text = "### ⚔️ MITRE ATT&CK Techniques\n"
    ttps = _get_attribute(report_json, ['data', 'attributes', 'crowdsourced_ids_results'], [])
    if not ttps:
        return text + "No MITRE ATT&CK techniques identified.\n"
    for ttp in ttps:
        technique_id = ttp.get('source_id', 'N/A')
        description = ttp.get('description', 'No description available.')
        text += f"- **{technique_id}**: {description}\n"
    return text


def create_document_from_json(report_json: dict, family_name: str) -> str:
    """
    直接从一个JSON字典对象创建格式化的Markdown文档。
    """
    if not report_json or 'data' not in report_json:
        return "Error: Invalid or empty report JSON provided."

    attributes = _get_attribute(report_json, ['data', 'attributes'], {})
    sha256 = attributes.get("sha256", "N/A")
    names = ", ".join(attributes.get("names", ["N/A"]))

    doc_content = f"""
# Malware Deep Dive Report: {sha256[:12]}...

- **SHA256:** `{sha256}`
- **Suspected Family:** {family_name.capitalize()}
- **Common Names:** {names}

{_format_av_detections(report_json)}
{_format_pe_structure(report_json)}
{_format_pe_imports(report_json)}
{_format_mitre_ttps(report_json)}
"""
    return doc_content


def create_document_from_report(report_path: Path, family_name: str) -> str:
    """
    从单个VT JSON报告文件创建格式化的Markdown文档。
    """
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return create_document_from_json(data, family_name)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error(f"Could not read or parse report file {report_path}: {e}")
        return f"Error processing report file: {report_path.name}"