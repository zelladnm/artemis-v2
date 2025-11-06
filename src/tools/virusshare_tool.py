# src/tools/virusshare_tool.py
from src.api.virusshare_client import VirusShareClient


class VirusShareTool:
    def __init__(self, vs_client: VirusShareClient):
        self.name = "virusshare_search"
        self.description = ("Checks if a given file hash exists in the massive VirusShare malware database. "
                            "Use this as the FIRST step for a completely unknown hash to verify if it is a known malware. "
                            "Returns a confirmation if the hash is found.")
        self.vs_client = vs_client

    def execute(self, file_hash: str) -> str:
        if not self.vs_client:
            return "Error: VirusShare client is not configured."

        result = self.vs_client.search_hash(file_hash)

        if result.get("found"):
            return f"Confirmation: The hash '{file_hash}' exists in the VirusShare malware database."
        elif "error" in result:
            return f"An error occurred: {result['error']}"
        else:
            return f"Information: The hash '{file_hash}' was NOT found in the VirusShare malware database."