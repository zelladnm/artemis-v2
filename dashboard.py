# dashboard.py
import gradio as gr
import pandas as pd
import plotly.express as px
import chromadb
import yaml
from pathlib import Path


def load_config():
    """加载YAML配置文件"""
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def generate_dashboard():
    """连接数据库，生成统计图表"""
    config = load_config()
    db_path = str(Path(config['data_paths']['vector_db']))
    collection_name = config['collection_name']

    try:
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_collection(name=collection_name)
        metadatas = collection.get(include=["metadatas"]).get('metadatas')
    except Exception as e:
        # 如果数据库为空或出错，返回提示信息
        return None, None, f"无法加载知识库数据: {e}"

    if not metadatas:
        return None, None, "知识库为空，无数据可供可视化。"

    # 将元数据转换为Pandas DataFrame
    df = pd.DataFrame(metadatas)

    total_vectors = len(df)
    summary_text = f"### 知识库总览\n- **总向量数:** {total_vectors}\n- **覆盖家族/威胁总数:** {df['family'].nunique()}"

    # 1. 按家族/威胁统计向量数量 (条形图)
    family_counts = df['family'].value_counts().nlargest(20)  # 只显示最多的20个
    fig_bar = px.bar(
        family_counts,
        x=family_counts.index,
        y=family_counts.values,
        labels={'x': '恶意软件家族/威胁', 'y': '向量数量'},
        title="知识库中各家族/威胁的向量数量 (Top 20)"
    )
    fig_bar.update_layout(xaxis_tickangle=-45)

    # 2. 按情报类型统计向量数量 (饼图)
    type_counts = df['type'].value_counts()
    fig_pie = px.pie(
        type_counts,
        names=type_counts.index,
        values=type_counts.values,
        title="知识库中各类情报的占比"
    )

    return fig_bar, fig_pie, summary_text


# --- Gradio Interface Definition ---
if __name__ == "__main__":
    with gr.Blocks(theme=gr.themes.Soft(), title="Artemis Knowledge Base Dashboard") as dashboard:
        gr.Markdown("# Artemis 知识库可视化仪表盘")

        # 显示摘要信息
        summary_output = gr.Markdown()

        # 显示图表
        with gr.Row():
            plot_bar = gr.Plot()
            plot_pie = gr.Plot()

        # 页面加载时自动执行函数并更新组件
        dashboard.load(generate_dashboard, inputs=None, outputs=[plot_bar, plot_pie, summary_output])

    print("Dashboard 正在启动...")
    print("请在浏览器中打开链接 (通常是 http://127.0.0.1:7860)")
    dashboard.launch()