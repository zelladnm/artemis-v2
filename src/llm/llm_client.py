# src/llm/llm_client.py (v1.1 - with Response Cleaning)
import ollama
import json
import logging


class LLMClient:
    def __init__(self, config: dict):
        self.model_name = config['llm_settings']['model_name']
        self.base_url = config['llm_settings']['base_url']
        logging.info(f"LLM Client initialized for model: {self.model_name} at {self.base_url}")

    def invoke(self, system_prompt: str, user_prompt: str) -> dict:
        try:
            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_prompt},
                ],
                format='json'
            )

            # --- 关键修复：清洗并去除响应字符串两端的空白和换行符 ---
            response_content = response['message']['content'].strip()

            llm_json_output = json.loads(response_content)
            return llm_json_output

        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode LLM JSON response: {e}")
            # 打印出清洗后的内容，便于调试
            logging.error(f"Cleaned response content from LLM: '{response_content}'")
            return {"error": "Failed to decode JSON response.", "raw_response": response_content}
        except Exception as e:
            logging.error(f"An error occurred while invoking LLM: {e}")
            return {"error": str(e)}