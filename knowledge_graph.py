# knowledge_graph.py (概念验证)
import json
from pathlib import Path
from pyvis.network import Network
import webbrowser


def build_knowledge_graph():
    metadata_file = Path("data/external/cisa_reports/metadata.json")
    if not metadata_file.exists():
        print("metadata.json not found!")
        return

    with open(metadata_file, "r", encoding="utf-8") as f:
        metadata_map = json.load(f)

    net = Network(height="800px", width="100%", bgcolor="#222222", font_color="white", notebook=False, directed=True)
    net.force_atlas_2based()  # 使用一种更美观的布局算法

    # 遍历元数据，添加节点和边
    for filename, meta in metadata_map.items():
        report_node = filename.replace(".pdf", "")
        # 添加报告节点 (主节点)
        net.add_node(report_node, label=report_node, color="#FFC300", size=25, title=meta.get("summary", ""))

        # 添加并连接家族节点
        for family in meta.get("families", []):
            net.add_node(family, label=family, color="#C70039", size=15)
            net.add_edge(report_node, family, title="discusses")

        # 添加并连接CVE节点
        for cve in meta.get("cves", []):
            net.add_node(cve, label=cve, color="#581845", size=10)
            net.add_edge(report_node, cve, title="mentions")

        # 添加并连接TTP节点
        for ttp in meta.get("ttps", []):
            net.add_node(ttp, label=ttp, color="#900C3F", size=10)
            net.add_edge(report_node, ttp, title="mentions")

    # 生成HTML文件
    output_filename = "knowledge_graph.html"
    net.show(output_filename, notebook=False)
    print(f"Knowledge graph saved to {output_filename}. Opening in browser...")
    webbrowser.open(output_filename)


if __name__ == "__main__":
    build_knowledge_graph()