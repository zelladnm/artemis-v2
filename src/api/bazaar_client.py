# src/api/bazaar_client.py
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BazaarClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        if not api_key:
            raise ValueError("Malware Bazaar API Key is required.")
        # 正确的认证方式：使用名为 'Auth-Key' 的 HTTP 标头
        self.headers = {
            'Auth-Key': api_key
        }

    def get_hashes_by_family(self, family: str, limit: int = 50):
        """根据恶意软件家族名称获取样本SHA256哈希列表"""
        data = {
            'query': 'get_taginfo',
            'tag': family,
            'limit': limit
        }
        try:
            # 在请求中发送正确的标头
            response = requests.post(self.base_url, data=data, headers=self.headers)
            response.raise_for_status()
            result = response.json()
            if result.get("query_status") == "ok":
                hashes = [item['sha256_hash'] for item in result.get('data', [])]
                logging.info(f"Found {len(hashes)} hashes for family '{family}'")
                return hashes
            else:
                # API有时在找不到标签时也会返回401，这里增加一个日志
                if response.status_code == 401:
                     logging.error(f"Authentication failed. Please check your API Key in the .env file.")
                logging.warning(f"Could not find hashes for family '{family}': {result.get('query_status')}")
                return []
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching data from Malware Bazaar: {e}")
            return []