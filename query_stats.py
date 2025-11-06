# query_stats.py
import yaml
from pathlib import Path
from collections import Counter
import chromadb
import pandas as pd


def load_config():
    """加载YAML配置文件"""
    try:
        with open("config.yaml", "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("错误：config.yaml 文件未找到。请确保此脚本与配置文件在同一目录下。")
        exit()


def main():
    """主函数，连接数据库并统计数据"""
    config = load_config()

    db_path = str(Path(config['data_paths']['vector_db']))
    collection_name = config['collection_name']

    print(f"正在连接到知识库: {db_path}")

    try:
        # 1. 连接到持久化的ChromaDB数据库
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_collection(name=collection_name)

        # 2. 获取所有条目，但只包含元数据以提高效率
        # get() 方法返回一个字典，我们需要 'metadatas' 键对应的值
        results = collection.get(include=["metadatas"])
        metadatas = results.get('metadatas')

        if not metadatas:
            print("知识库为空或无法读取数据。")
            return

    except Exception as e:
        print(f"连接或查询数据库时出错: {e}")
        print("请确保您已经成功运行过 main.py 或 historical_import.py 来构建知识库。")
        return

    # 3. 使用Counter进行统计
    family_counter = Counter()
    type_counter = Counter()

    for meta in metadatas:
        # 统计家族
        family = meta.get('family', 'Unknown')
        if family:
            family_counter[family] += 1

        # 统计类型
        doc_type = meta.get('type', 'Unknown')
        if doc_type:
            type_counter[doc_type] += 1

    total_vectors = len(metadatas)

    # --- 4. 格式化并打印结果 ---

    print("\n" + "=" * 60)
    print(" KNOWLEDGE BASE COMPOSITION REPORT ".center(60, "="))
    print("=" * 60)
    print(f"总向量数 (Total Vectors): {total_vectors}\n")

    # 使用pandas创建更美观的表格
    # 统计家族报告数量
    if family_counter:
        print("--- 按恶意软件家族/威胁名统计 (By Malware Family/Threat) ---")
        family_df = pd.DataFrame(family_counter.most_common(), columns=['Family/Threat Name', 'Vector Count'])
        print(family_df.to_string(index=False))
        print("\n")

    # 统计情报类型数量
    if type_counter:
        print("--- 按情报类型统计 (By Intelligence Type) ---")
        type_df = pd.DataFrame(type_counter.most_common(), columns=['Document Type', 'Vector Count'])
        print(type_df.to_string(index=False))
        print("\n")

    print("=" * 60)


if __name__ == "__main__":
    # 为了使用pandas，您可能需要先安装它
    try:
        import pandas
    except ImportError:
        print("检测到'pandas'库未安装，正在尝试自动安装...")
        import subprocess
        import sys

        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
            print("'pandas' 安装成功，请重新运行此脚本。")
        except Exception as e:
            print(f"自动安装'pandas'失败: {e}")
            print("请手动运行 'pip install pandas' 后再试。")
        exit()

    main()