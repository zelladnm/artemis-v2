# src/agent/artemis_agent.py (v3.0 - Final Prompt Simplification)
import os
import json
import logging
from datetime import datetime

# ... (其他 imports 保持不变) ...
from src.knowledge_base.vector_store import VectorStoreManager
from src.llm.llm_client import LLMClient
from src.api.vt_client import VirusTotalClient
from src.api.virusshare_client import VirusShareClient
from src.processing.data_parser import create_document_from_report
from src.tools.vt_lookup_tool import VTLiveLookupTool
from src.tools.network_tool import NetworkAnalysisTool
from src.tools.virusshare_tool import VirusShareTool


class ArtemisAgent:
    def __init__(self, config: dict):
        # ... (__init__ 的实现保持不变) ...
        self.config = config
        self.vector_store_manager = VectorStoreManager(config)
        self.llm_client = LLMClient(config)
        self.tools = {}
        vt_api_key = os.getenv("VT_API_KEY")
        vs_api_key = os.getenv("VIRUSSHARE_API_KEY")
        vt_client = VirusTotalClient(api_key=vt_api_key, base_url=config['vt_api_url'])
        self.tools[VTLiveLookupTool(vt_client).name] = VTLiveLookupTool(vt_client)
        vs_client = VirusShareClient(api_key=vs_api_key)
        self.tools[VirusShareTool(vs_client).name] = VirusShareTool(vs_client)
        try:
            network_tool = NetworkAnalysisTool()
            self.tools[network_tool.name] = network_tool
        except ImportError as e:
            logging.warning(f"Could not initialize NetworkAnalysisTool: {e}. This tool will be unavailable.")
        self.tools["final_summary"] = {"name": "final_summary",
                                       "description": "Use this tool ONLY when you have gathered enough information to provide a complete and confident final analysis to the user."}
        logging.info(f"Artemis Agent initialized with tools: {list(self.tools.keys())}")
        self.mcp = {}
        self.system_prompt_template = self._load_system_prompt()

    # --- 核心升级：终极简化的Prompt ---
    def _load_system_prompt(self):
        tool_descriptions = [
            {"tool_name": "virusshare_search",
             "description": "Checks if a hash exists in the VirusShare malware database. Use this first for an unknown hash.",
             "parameters": {"file_hash": "the hash to check"}},
            {"tool_name": "virustotal_live_lookup",
             "description": "Gets a detailed analysis report from VirusTotal for a hash.",
             "parameters": {"file_hash": "the hash to look up"}},
            {"tool_name": "network_analyzer", "description": "Performs a 'whois' lookup on an IP or domain.",
             "parameters": {"indicator": "the IP or domain to investigate"}},
            {"tool_name": "final_summary", "description": "Provides the final, complete analysis summary to the user.",
             "parameters": {"summary_text": "Your detailed analysis.", "confidence_score": "Low, Medium, or High",
                            "analyst_questions": ["A list of further questions."]}}
        ]

        base_prompt = (
            "You are an AI agent that uses tools. Your ONLY task is to analyze the provided context and decide which single tool to use next. "
            "Your response MUST be a single, valid JSON object with ONE key: 'tool_to_use'.\n\n"
            "**Decision Process:**\n"
            "1. Review the 'retrieved_context' and 'analysis_log' to understand what you already know.\n"
            "2. If the 'target_info' is a hash and it hasn't been checked with `virusshare_search`, use that tool.\n"
            "3. If `virusshare_search` was successful, your next step MUST be `virustotal_live_lookup`.\n"
            "4. If all information is gathered, your final step MUST be to call the `final_summary` tool.\n\n"
            f"**Available Tools Schema:**\n{json.dumps(tool_descriptions, indent=2)}\n\n"
            "**Your Response JSON Schema:**\n"
            "```json\n"
            "{\n"
            "  \"tool_to_use\": {\n"
            "    \"tool_name\": \"<tool_name>\",\n"
            "    \"parameters\": {\n"
            "      \"<parameter_name>\": \"<parameter_value>\"\n"
            "    }\n"
            "  }\n"
            "}\n"
            "```"
        )
        return base_prompt

    def _create_mcp_template(self, target_type: str, value: str):
        # (保持不变)
        session_id = f"artemis-session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        return {"session_id": session_id, "target_info": {"type": target_type, "value": value}, "analysis_log": [],
                "retrieved_context": [],
                "llm_workspace": {"current_summary": "", "analyst_questions": [], "confidence_score": "Not Evaluated"},
                "final_report": None}

    def _invoke_llm_with_mcp(self) -> dict:
        # (保持不变)
        user_prompt = f"Current MCP state:\n{json.dumps(self.mcp, indent=2, ensure_ascii=False)}"
        llm_response_json = self.llm_client.invoke(self.system_prompt_template, user_prompt)
        return llm_response_json

    def run(self, initial_query: str, max_steps: int = 5):
        # (run 方法保持不变)
        self.mcp = self._create_mcp_template("file_hash_or_ioc", initial_query)
        retriever = self.vector_store_manager.get_retriever()
        retrieved_docs = retriever.invoke(initial_query)
        self.mcp["analysis_log"].append({"step": 0, "action": "internal_retrieval",
                                         "summary": f"Retrieved {len(retrieved_docs)} documents from internal KB."})
        for doc in retrieved_docs:
            self.mcp["retrieved_context"].append(
                {"source": doc.metadata.get("source"), "type": doc.metadata.get("type"), "content": doc.page_content})
        yield self.mcp
        for i in range(max_steps):
            logging.info(f"--- ReAct Cycle: Step {i + 1} ---")
            llm_decision = self._invoke_llm_with_mcp()
            tool_call = llm_decision.get("tool_to_use")
            if tool_call and "tool_name" in tool_call:
                tool_name = tool_call.get("tool_name")
                parameters = tool_call.get("parameters", {})
                if tool_name == "final_summary":
                    logging.info("LLM decided analysis is complete. Breaking loop.")
                    self.mcp["llm_workspace"]["current_summary"] = parameters.get("summary_text",
                                                                                  "No summary provided.")
                    self.mcp["llm_workspace"]["confidence_score"] = parameters.get("confidence_score", "N/A")
                    self.mcp["llm_workspace"]["analyst_questions"] = parameters.get("analyst_questions", [])
                    self.mcp["analysis_log"].append(
                        {"step": i + 1, "action": "reasoning", "summary": "LLM finalized the analysis."})
                    yield self.mcp
                    break
                if tool_name in self.tools:
                    tool_input = next(iter(parameters.values())) if parameters else None
                    if tool_input:
                        logging.info(f"Executing tool: '{tool_name}' with input: '{tool_input}'")
                        tool = self.tools[tool_name]
                        observation = tool.execute(tool_input)
                        log_entry = {"step": i + 1, "action": f"tool_use:{tool_name}", "input": tool_input,
                                     "output": observation}
                        self.mcp["analysis_log"].append(log_entry)
                        self.mcp["retrieved_context"].append(
                            {"source": "tool_observation", "tool_used": tool_name, "observation": observation})
                        yield self.mcp
                    else:
                        logging.warning(f"LLM called tool '{tool_name}' without parameters.")
                else:
                    logging.warning(f"LLM tried to call an unknown tool: {tool_name}")
            else:
                logging.error(f"LLM response did not follow the tool-calling format: {llm_decision}")
                break