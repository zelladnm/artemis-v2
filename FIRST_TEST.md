# Artemis v3：第一次实机测试

让 AI 承担证据整理、行为解释和报告草拟，分析人员保留研判与处置决定。
这是首次实机试用的预览代码，基于原项目 PR #20；不是正式发布版。

## 先跑通，再接真实报告与模型

首次启动只需要 **Python 3.11 及以上的标准安装**，无需 GPU、Docker、沙箱、API Key、
Gradio、ChromaDB 或 pip 安装。建议 Windows 11 使用 Python 3.13 的标准 64 位安装。
Python 官方入口：https://www.python.org/downloads/windows/ 。安装后确保 `python --version`
能显示版本；不要使用仅供嵌入的最小 Python 包。

1. 下载本次测试分支或 CI 的 `artemis-v3-first-test` 包，**完整解压**到普通用户可读的目录。
   路径可以包含空格和中文。不要直接在 ZIP 的预览窗口里运行。
2. Windows 双击 `doctor.cmd` 查看自检；Linux 在终端运行 `sh doctor.sh`。
   `status` 应为 `passed`。自检会创建数据目录，并写入、删除一份临时探针；不会改动调查库。
3. 在此目录打开终端，运行 `python launch.py --smoke-test`。
   它只用合成数据和临时数据库，检查本机 HTTP、解析、归档重开与复核保存；不会调用模型或执行样本。
4. Windows 双击 `start.cmd`；Linux 运行 `sh start.sh`。
   浏览器应自动打开。若没有，请复制窗口里的 `Open: http://127.0.0.1:...` 地址。
5. 点击“加载离线演示”，检查进程、时间线和来源证据，规则原始分数应为 **1 / 10**。
6. 导入 `examples/report_synthetic.json`，勾选“合成演示数据”，点击开始调查。
   源码检出时可使用 `tests/fixtures/cape_summary_synthetic.json`。
   行为汇总应显示注册表读字段缺失、写入有 2 条、服务启动明确为空。
   同值记录保留各自出处，服务摘要不证明失败的 API 调用执行成功。
7. 点击“归档来源”，刷新页面后精确查询并重新打开，导出 JSON、Markdown 或 HTML。
   关闭控制台或 Ctrl+C 停止，再次启动后应仍能重开归档。每次启动请使用新打印的地址。

**窗口持续运行时服务才可用。** 默认选取空闲的回环端口，不修改防火墙、不监听局域网。
需要固定端口时运行 `python launch.py --port 8765`；占用时会报错，不会连接到别的服务。

## 数据放在哪里

默认调查库位于代码目录之外：

| 系统 | 默认目录 |
|---|---|
| Windows | `%LOCALAPPDATA%\ArtemisV3` |
| Linux | `$XDG_STATE_HOME/artemis-v3`，未配置时为 `~/.local/state/artemis-v3` |
| macOS（尚待实机验证） | `~/Library/Application Support/ArtemisV3` |

启动窗口会打印本机实际目录。`cases.sqlite` 保存明确归档的来源；`reviews.sqlite` 保存明确
保存的复核。启动或仅浏览不会把报告自动归档。数据库不随代码更新而删除。

可指定另一处有写权限的本地目录：

```sh
python launch.py --data-dir "D:/ArtemisData"
```

Windows 命令也接受 `/` 路径分隔符。不要把真实报告、数据库、配置或密钥放进公开仓库。
备份和恢复仍使用 [STORAGE.md](docs/v3/STORAGE.md) 的停止写入、双库备份与新路径恢复流程。

## 可选配置

无需配置即可启动 Lite。需要保存设置时，将 `settings.example.json` 复制为同目录的
`artemis.local.json`，再修改。该文件已加入 Git 忽略规则，不进入测试包。

- `data_dir: null` 使用上述系统默认目录；配置中的相对路径以配置文件目录为基准。
- `port: 0` 自动选空闲端口；`open_browser: false` 适合 SSH 或不自动弹出浏览器。
- `ollama_model: null` 不配置模型。设置后仍须在界面明确点击才发送受限证据。
- `model_digest` 可固定完整 64 位模型权重 SHA-256；仅在指定模型时使用。
- `--config PATH` 读取指定配置；CLI 参数覆盖配置，`--lite` 本次禁用模型。
- JSON 字段、类型、大小和重复键均会校验。不要加入 API Key 或复制 v2 的 `.env`。

```sh
python launch.py --no-browser
python launch.py --config "D:/ArtemisConfig/artemis.local.json"
python launch.py --lite
```

有多个 Python 时，可先运行 `py -3.13 launch.py --doctor`，或给 `ARTEMIS_PYTHON` 设置
已安装的解释器完整路径再运行启动脚本。脚本不运行 pip、不拉取模型，并禁用 Python
安装管理器的自动安装开关；缺少运行时需按官方方法自行安装。

## 第二阶段：你自己的 CAPE 报告

只导入已生成、已检查敏感内容的 **report.json（最大 10 MiB）**，准确取消合成标记。
先检查导入结果、覆盖告警、进程关系、API 的状态/返回值，以及汇总的原始位置。
缺失字段、空列表和成功执行不是同一含义。超限时先记录文件大小，不要截断 JSON 冒充完整报告。

可在本机生成内容不含原始命令、路径、IOC 的结构概况（数量也可能敏感，分享前检查）：

```sh
python -m artemis_v3.cape_audit --report "D:/Private/report.json" --cape-version "你实际部署的版本"
```

版本栏是你的声明，工具不会自动认证版本。详见 [CAPE_PROFILE.md](docs/v3/CAPE_PROFILE.md)。
PCAP、BSON、内存转储和未知样本执行不在这次 Lite 实测范围。

## 第三阶段：可选的本地模型

先完成无模型测试。若已有本地 Ollama 和已安装的 GGUF 模型，可运行：

```sh
python launch.py --ollama-model "你的已安装本地模型名"
```

按 [SEMANTIC.md](docs/v3/SEMANTIC.md) 在 **Ollama 服务自身环境**中关闭云功能并重启服务。
不要把模型占位符原样输入，也不要在 Artemis 中期待自动下载模型。
自检中的 `model_connection: not_checked` 表示未检查模型连接；真正的本地模型预检在
明确请求解释时执行，失败会显示在界面。评分调整仍需独立人工决定。

真实解释质量请用已脱敏报告逐条核验。固定权重与可重复评测见 [EVALUATION.md](docs/v3/EVALUATION.md)，
图形化核验见 [EVALUATION_REVIEW.md](docs/v3/EVALUATION_REVIEW.md)。模拟自测通过不能代替这些验收。

## 反馈哪些信息

先告诉我你停在第几步、预期与实际现象，以及 `python --version`。再按需要提供：

```sh
python launch.py --doctor
python launch.py --smoke-test
```

这两个 JSON 只含有限环境信息或合成自测结果，不含用户名、主机名、绝对路径、环境变量值、
报告内容、样本哈希、API Key 或原始模型输出。元数据仍请检查后再发。
如需保存自检输出，在 **CMD** 中运行 `python -X utf8 launch.py --doctor > environment-check.json`。
PowerShell 5.1 的重定向可能使用另一种文本编码，直接复制 JSON 也可以。

| 现象 | 先做什么 |
|---|---|
| 双击无反应或找不到 Python | 从终端运行 `python --version` 和 `python launch.py --doctor`，核对所用解释器 |
| 文件不完整或清单校验失败 | 完整重新解压同一测试包；清单用于发现损坏，不是数字签名 |
| 数据目录不可写 | 使用 `--data-dir` 选择普通用户可写目录；不要因此以管理员身份运行整个分析工具 |
| 页面打不开 | 保留控制台运行，用本次 `Open:` 地址；可加 `--no-browser` 手动打开 |
| 指定端口占用 | 换端口或省略 `--port`，默认使用空闲端口 |
| 自测无法绑定回环服务 | 检查本机策略并反馈自检结果；不要关闭安全软件或扩大监听地址 |
| 报告被拒绝 | 记录大小和 CAPE 版本，先运行结构概况工具；保留原始报告 |
| 模型失败 | 先以 `--lite` 验证证据与归档，再核对本地模型名称、服务和版本 |

不要直接提交真实敏感日志、数据库或报告到 GitHub。第一次实机反馈回来后，优先修复你实际遇到的
部署与兼容性问题，再决定后续功能。当前研究结论和历史论文实验不作为本版本的效果保证。
