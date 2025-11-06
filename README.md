# Artemis: 智能恶意软件分析智能体 🛸

**Artemis** 是一个基于大型语言模型（LLM）和检索增强生成（RAG）技术的自主威胁情报分析平台。它旨在模拟高级安全分析师的思维过程，自动整合多源异构情报、调用外部工具，对恶意软件样本进行深入分析，并生成流式的、人类可读的分析报告。

本项目是为探索下一代“安全副驾驶”（Security Co-pilot）而构建的原型

## 的核心功能

* **🧠 智能体核心 (Agentic Core)**: 基于**ReAct (Reason + Act)** 框架，Artemis能够自主地“思考”和“行动”。它会根据当前情报状态，决策下一步是继续分析、调用工具还是生成最终报告。
* **🧩 动态工具链 (Tool Calling)**: Artemis的“手臂”。当内部知识不足时，它会自动调用外部工具来获取实时情报，目前已集成：
    * `virusshare_search`: 检查一个哈希是否存在于海量恶意样本库中。
    * `virustotal_live_lookup`: 实时从VirusTotal API获取一个哈希的详细分析报告。
    * `network_analyzer`: 对IP或域名执行`whois`查询，以分析其信誉和归属。
* **📚 多源威胁情报知识库 (RAG)**: Artemis的“大脑”。它集成了多种来源的威胁情报，并将其自动化地处理、向量化后存入ChromaDB：
    * **VirusTotal** API（JSON报告）
    * **Malware Bazaar**（签名与哈希）
    * **CISA** 权威报告（PDF）
    * **开源YARA规则**（`.yar`文件）
    * **VirusShare** 哈希集
* **📜 模型上下文协议 (MCP)**: Artemis的“神经系统”。这是一个在分析过程中不断流转和丰富的JSON对象，它记录了分析的每一步（`analysis_log`）、所有检索到的上下文（`retrieved_context`），并作为LLM进行决策的唯一依据。
* **🌐 交互式Web UI (Gradio)**: 提供了直观的前端界面，支持：
    * **双模式输入**: 可直接拖拽上传文件，或输入文本（哈希, IP, 域名）。
    * **流式报告**: 实时“直播”Artemis的每一步思考、行动和观察，过程完全透明。
* **🛡️ (可选) 安全隔离架构**: 支持将高风险的文件分析（如哈希计算）隔离在虚拟机（VM）中的`analysis_worker.py`执行，而AI推理则在主机上利用GPU全速运行，兼顾安全与性能。
* **📊 可视化仪表盘**: 包含`dashboard.py`（用于统计知识库构成）和`knowledge_graph.py`（用于展示情报实体间的关联）的可视化脚本。

## 📈 架构概览

```
  [ 用户 (Gradio UI) ]
         |
  [ Artemis Agent (app.py) ] <--- [ MCP (状态JSON) ]
         |
  [ LLM (Ollama) - (思考) ]
         |
  +------+------+
  |             |
[ 工具集 (行动) ] [ 知识库 (RAG) ]
  |             |
  - VT API      - ChromaDB
  - VS API      - (VT Reports)
  - Whois       - (CISA PDFs)
                - (YARA Rules)
```

## 🛠️ 技术栈

* **核心框架**: Python 3.10+
* **AI / LLM**: Ollama (Mistral 7B / Phi3), LangChain
* **向量数据库**: ChromaDB
* **数据处理**: Pandas, PyPDF
* **API & 工具**: requests, python-whois
* **Web UI**: Gradio

## 🚀 快速开始

### 1. 环境配置

1.  **克隆仓库**
    ```bash
    git clone [https://github.com/您的用户名/Artemis.git](https://github.com/您的用户名/Artemis.git)
    cd Artemis
    ```

2.  **创建Python虚拟环境**
    ```bash
    python -m venv venv
    source venv/bin/activate  # (Windows: venv\Scripts\activate)
    ```

3.  **安装依赖**
    ```bash
    pip install -r requirements.txt
    ```

4.  **安装并运行Ollama**
    * 访问 [https://ollama.com/](https://ollama.com/) 下载并安装。
    * 拉取您选择的模型（Mistral 7B是平衡性能和效果的推荐选项）：
        ```bash
        ollama run mistral:7b-instruct
        ```
    * 确保Ollama服务在后台持续运行。

5.  **配置API密钥**
    * 将 `.env.example` 文件复制为 `.env`。
    * 在 `.env` 文件中填入您从VirusTotal、VirusShare和Malware Bazaar获取的API密钥：
        ```env
        VT_API_KEY="YOUR_VIRUS_TOTAL_API_KEY"
        VIRUSSHARE_API_KEY="YOUR_VIRUSSHARE_API_KEY"
        BAZAAR_API_KEY="YOUR_MALWARE_BAZAAR_KEY"
        ```

### 2. 构建知识库

在您第一次运行Artemis之前，需要为其“大脑”填充知识。

1.  **下载情报数据**
    * 将您的CISA PDF报告放入 `data/external/cisa_reports/`。
    * 将您的YARA规则（`.yar`文件）放入 `data/external/yara_rules/`。
    * 将您的VirusShare哈希列表文件放入 `data/external/hash_lists/`。
    * （可选）在 `data/external/cisa_reports/metadata.json` 中为PDF添加元数据。

2.  **运行历史数据导入脚本**
    * 这将获取与您的YARA规则和PDF元数据相关的VT报告，并将其全部向量化。
    ```bash
    python historical_import.py
    ```
    * （可选）运行VirusShare哈希导入脚本来进一步扩充：
    ```bash
    python import_virusshare_hashes.py
    ```

### 3. 运行Artemis

一切准备就绪！启动主应用：

```bash
python app.py
```

在您的浏览器中打开 `http://127.0.0.1:7860` 即可开始分析。

### 4. 其他脚本

* **知识库仪表盘**: `python dashboard.py`
* **知识图谱生成**: `python knowledge_graph.py`
* **每日增量更新**: `python main.py`

## 🔮 未来展望

静态分析增强
集成yara规则扫描
实现PE文件结构分析
添加字符串和熵值分析
动态分析集成
集成开源沙箱
实现API调用序列分析
添加网络行为监控
桶过mcp链接kali以及其他工具

## 📄 许可证

本项目采用 [MIT License](LICENSE) 许可证。
