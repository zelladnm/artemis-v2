# src/api/vt_client.py
import requests
import time
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class VirusTotalClient:
    def __init__(self, api_key: str, base_url: str):
        if not api_key:
            raise ValueError("VirusTotal API key is required.")
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"x-apikey": self.api_key}
        # 公共API限制为每分钟4次
        self.request_interval = 16  # 留一些缓冲

    def get_file_report(self, file_hash: str):
        """获取指定文件哈希的VT报告"""
        url = f"{self.base_url}{file_hash}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()  # 如果请求失败则抛出HTTPError
            logging.info(f"Successfully fetched report for {file_hash}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching report for {file_hash}: {e}")
            return None
        finally:
            # 无论成功与否都等待，以遵守速率限制
            logging.info(f"Waiting for {self.request_interval} seconds due to rate limit...")
            time.sleep(self.request_interval)

    def download_and_save_report(self, file_hash: str, save_path: Path, return_sha256_filename=False):
        # 即使查询的是MD5，VT返回的JSON中也包含SHA256，我们以此为主键
        report = self.get_file_report(file_hash)
        if not report:
            return None  # 下载失败

        sha256 = report.get("data", {}).get("attributes", {}).get("sha256")
        if not sha256:
            logging.error(f"Could not find SHA256 in the report for hash {file_hash}")
            return None

        report_path = save_path / f"{sha256}.json"

        if report_path.exists():
            logging.info(f"Report for {sha256} already exists. Skipping.")
            return report_path if return_sha256_filename else True

        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, 'w', encoding='utf-8') as f:
            import json
            json.dump(report, f, indent=4)
        logging.info(f"Saved report for {file_hash} (as {sha256}) to {report_path}")

        return report_path if return_sha256_filename else True