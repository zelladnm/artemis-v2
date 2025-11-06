# src/tools/vt_lookup_tool.py (Corrected)
from src.api.vt_client import VirusTotalClient
# --- 关键修正：导入新的解析函数 ---
from src.processing.data_parser import create_document_from_json


class VTLiveLookupTool:
    def __init__(self, vt_client: VirusTotalClient):
        self.name = "virustotal_live_lookup"
        self.description = ("Performs a real-time lookup for a given file hash (MD5, SHA1, or SHA256) on VirusTotal "
                            "and returns a summarized analysis report. Use this when the internal knowledge base has no information on a hash.")
        self.vt_client = vt_client

    def execute(self, file_hash: str) -> str:
        if not self.vt_client:
            return "Error: VirusTotal client is not configured."

        report_json = self.vt_client.get_file_report(file_hash)

        if report_json:
            # --- 关键修正：调用正确的函数 ---
            summary = create_document_from_json(report_json, family_name="Unknown (Live Search)")
            return f"Successfully fetched live VirusTotal report.\nAnalysis Summary:\n{summary}"
        else:
            return f"Could not find a report for hash '{file_hash}' on VirusTotal."