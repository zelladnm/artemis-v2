# src/tools/network_tool.py
import whois
import logging

class NetworkAnalysisTool:
    def __init__(self):
        self.name = "network_analyzer"
        self.description = ("Performs a 'whois' lookup on a given IP address or domain to get registration information. "
                            "Use this to investigate suspicious network indicators found in reports.")
        try:
            import whois
        except ImportError:
            raise ImportError("The 'whois' package is required for this tool. Please run 'pip install python-whois'.")


    def execute(self, indicator: str) -> str:
        try:
            w = whois.whois(indicator)
            # 提取关键信息并格式化
            owner = w.org or w.name
            country = w.country
            creation_date = w.creation_date

            # 有些whois结果可能是列表
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            return (f"Whois lookup for '{indicator}':\n"
                    f"- Owner/Organization: {owner}\n"
                    f"- Country: {country}\n"
                    f"- Creation Date: {creation_date.strftime('%Y-%m-%d') if creation_date else 'N/A'}")
        except Exception as e:
            logging.error(f"Whois lookup failed for {indicator}: {e}")
            return f"Error performing whois lookup for '{indicator}': {e}"