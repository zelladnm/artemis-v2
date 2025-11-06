# app.py (v2.6 - Correct .env Loading)
import gradio as gr
import hashlib
from pathlib import Path
from dotenv import load_dotenv  # <-- 关键修正：导入 load_dotenv
from src.agent.artemis_agent import ArtemisAgent
from main import load_config
import logging

# --- 关键修正：在所有操作之前，首先加载环境变量 ---
load_dotenv()

# --- Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
config = load_config()
agent = ArtemisAgent(config)
logging.info("Artemis Agent (v2.6 - Env Fix) has been initialized for the Gradio App.")

# --- Core Analysis Functions ---
# ( analyze_file, analyze_text_query, format_mcp_to_markdown 等函数保持不变)
def format_mcp_to_markdown(mcp_result, initial_hashes={}):
    # ... (此函数无需修改，直接复用上一版本即可) ...
    if not mcp_result: return "分析失败，未能从Agent获取有效结果。"
    report = "## 🛸 Artemis 深度分析报告\n\n"
    target_info = mcp_result.get("target_info", {})
    if initial_hashes:
        report += "### **文件哈希**\n"
        report += f"- **MD5:** `{initial_hashes.get('md5', 'N/A')}`\n"
        report += f"- **SHA1:** `{initial_hashes.get('sha1', 'N/A')}`\n"
        report += f"- **SHA256:** `{initial_hashes.get('sha256', 'N/A')}`\n"
    elif "value" in target_info:
        report += f"**查询目标:** `{target_info['value']}`\n"
    report += "\n---\n"
    workspace = mcp_result.get("llm_workspace", {})
    confidence = workspace.get("confidence_score", "N/A")
    summary = workspace.get("current_summary", "正在分析中...")
    questions = workspace.get("analyst_questions", [])
    report += f"### **⭐ 分析置信度: {confidence}**\n"
    report += f"### **🧠 最终摘要**\n{summary}\n\n"
    analysis_log = mcp_result.get("analysis_log", [])
    if analysis_log:
        report += "---\n### **🔬 Artemis 分析全过程 (ReAct Log)**\n"
        for i, entry in enumerate(analysis_log):
            action = entry.get('action', 'unknown_action')
            step_num = entry.get('step', i)
            if action.startswith("tool_use:"):
                tool_name = action.split(":")[1]
                tool_input = entry.get('input', 'N/A')
                output = str(entry.get('output', ''))
                report += f"#### **步骤 {step_num}: 行動 (Act)**\n"
                report += f"Artemis决定使用工具 **`{tool_name}`** 对 **`{tool_input}`** 进行调查。\n\n"
                report += f"> **观察结果 (Observation):**\n> ```\n> {output}\n> ```\n\n"
            else:
                 summary = entry.get('summary', '')
                 report += f"#### **步骤 {step_num}: 思考 (Reason)**\n- {summary}\n\n"
    if questions:
        report += "---\n### **💡 建议的进一步调查方向**\n"
        for q in questions:
            report += f"- {q}\n"
    return report

def streaming_analyze(query_or_file):
    # ... (此函数无需修改，直接复用上一版本即可) ...
    try:
        initial_query, initial_hashes = "", {}
        if isinstance(query_or_file, str):
            if not query_or_file or not query_or_file.strip():
                yield "错误：请输入有效的查询内容。"; return
            initial_query = query_or_file.strip()
        else:
            if query_or_file is None:
                yield "错误：请上传一个文件。"; return
            content = query_or_file.read()
            initial_hashes = {"md5": hashlib.md5(content).hexdigest(), "sha1": hashlib.sha1(content).hexdigest(), "sha256": hashlib.sha256(content).hexdigest()}
            initial_query = initial_hashes["sha256"]
        logging.info(f"Triggering streaming agent run with query: {initial_query}")
        for mcp_state in agent.run(initial_query=initial_query):
            yield format_mcp_to_markdown(mcp_state, initial_hashes=initial_hashes)
    except Exception as e:
        logging.error(f"An error occurred during streaming analysis: {e}")
        yield f"分析过程中出现严重错误: {e}"

# --- Gradio Interface Definition ---
if __name__ == "__main__":
    # ... (此部分代码无需修改，直接复用上一版本即可) ...
    with gr.Blocks(theme=gr.themes.Soft(), title="Artemis Agent") as iface:
        gr.Markdown("# Artemis: 智能恶意软件分析智能体")
        gr.Markdown("欢迎使用Artemis。 **点击分析后，Artemis的思考和行动过程将实时展现在下方。**")
        with gr.Tabs():
            with gr.TabItem("通过文件上传分析"):
                file_input = gr.File(label="上传恶意软件样本")
                file_output = gr.Markdown(label="实时分析报告", elem_id="report-box")
                file_button = gr.Button("🚀 一键深度分析", variant="primary")
            with gr.TabItem("通过文本查询分析"):
                text_input = gr.Textbox(lines=1, placeholder="在此处输入恶意软件哈希", label="查询目标")
                text_output = gr.Markdown(label="实时分析报告", elem_id="report-box")
                text_button = gr.Button("🚀 一键深度分析", variant="primary")
        file_button.click(fn=streaming_analyze, inputs=file_input, outputs=file_output)
        text_button.click(fn=streaming_analyze, inputs=text_input, outputs=text_output)
    print("Artemis Web UI (Streaming Edition) 正在启动...")
    print("请在浏览器中打开以下链接: http://127.0.0.1:7860")
    iface.queue().launch()