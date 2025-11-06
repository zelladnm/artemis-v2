# src/api/virusshare_client.py
import requests
import logging
import time


class VirusShareClient:
    def __init__(self, api_key: str):
        self.base_url = "https://virusshare.com/apiv2"
        self.api_key = api_key
        # VirusShare API速率限制为每分钟4次
        self.request_interval = 16

    def search_hash(self, file_hash: str) -> dict:
        """
        使用 /file 请求查询VirusShare中关于单个哈希的信息。
        """
        if not self.api_key:
            return {"found": False, "error": "VirusShare API Key is not configured."}

        params = {
            "apikey": self.api_key,
            "hash": file_hash
        }
        try:
            response = requests.get(f"{self.base_url}/file", params=params, timeout=30)

            # 204表示超出速率限制
            if response.status_code == 204:
                logging.warning("VirusShare API rate limit exceeded.")
                return {"found": False, "error": "Rate limit exceeded"}

            response.raise_for_status()

            result = response.json()
            # 根据API文档，response code 1 表示是恶意软件
            if result.get("response") == 1:
                logging.info(f"Hash {file_hash} found in VirusShare database.")
                return {"found": True, "data": result}
            else:
                logging.info(f"Hash {file_hash} not found in VirusShare database.")
                return {"found": False}

        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying VirusShare API: {e}")
            return {"found": False, "error": str(e)}
        finally:
            time.sleep(self.request_interval)  # 遵守API速率限制