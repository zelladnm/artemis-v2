# test_agent.py
import json
from src.agent.artemis_agent import ArtemisAgent
from main import load_config  # 复用main.py中的函数


def test():
    print("--- Artemis Agent Test ---")
    config = load_config()

    # 1. 初始化Agent
    agent = ArtemisAgent(config)

    # 2. 选择一个您知识库中确定存在的哈希进行测试
    # 您可以从 query_stats.py 的输出或 data/raw/vt_reports/ 中找一个
    test_hash = "b3d310c2853f8d633be45b6c7bf57f4d1da0ecb11a757096720621db3b1d0b15"
    print(f"Target Hash: {test_hash}\n")

    # 3. 启动分析
    final_mcp = agent.start_analysis(test_hash)

    # 4. 打印LLM的分析结果
    print("\n--- LLM Analysis Result ---")
    if final_mcp and "llm_workspace" in final_mcp:
        workspace = final_mcp.get("llm_workspace", {})
        print("Confidence Score:", workspace.get("confidence_score", "N/A"))
        print("\nSummary:")
        print(workspace.get("current_summary", "No summary generated."))
        print("\nFurther Questions Suggested by Artemis:")
        for q in workspace.get("analyst_questions", []):
            print(f"- {q}")
    else:
        print("Analysis failed to produce a valid result.")

    # print("\n--- Final MCP State ---")
    # print(json.dumps(final_mcp, indent=2))


if __name__ == "__main__":
    test()