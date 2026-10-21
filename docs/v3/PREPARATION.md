# 本地 CAPE 验收套件准备

`evaluation prepare` 把分析人员选定的报告与规则原始字节复制到一个新的评测目录，
自动填写路径、SHA-256 和来源标记，整理字段覆盖与上下文预检。每次准备一个当前
报告和可选历史报告，无需 Ollama、数据库、网络或新增 Python 依赖。

输入应是分析人员已整理的本地报告。**准备操作不会匿名化数据**；原始报告和上下文
预览都应保留在合适的本地目录。只读取明确指定的文件，不根据报告中的路径取文件。

## 准备草稿

从仓库根目录运行，替换本地路径；输出目录须不存在，父目录须已存在：

```sh
python -m artemis_v3.evaluation prepare --report /local/current-report.json --ruleset /local/ruleset.json --case-id cape_case_01 --name "Local CAPE acceptance" --output-dir /local/cape-case-01
```

需要同一样本的历史对照时增加 `--historical-report /local/prior-report.json`。两个报告
须声明同一个有效 `/target/file/sha256`，且报告字节不同。样本哈希仍是报告声明，
尚未核验样本字节或证明跨运行等价。默认将两份报告标为 `synthetic: false`；仅在确实
使用合成报告时增加 `--synthetic`。规则文件的 synthetic 标记独立保留。

现有目录、文件或符号链接均拒绝覆盖。无效来源或不匹配的历史来源在创建输出前
被拒绝。写入中断可能留下不完整草稿，应检查后另选新目录重新准备。

| 输出 | 用途 |
|---|---|
| `sources/report.json` | 当前报告原始字节，保留 BOM、换行和空白 |
| `sources/ruleset.json` | 显式选定规则的原始字节 |
| `sources/historical-report.json`（可选） | 历史报告原始字节 |
| `suite.json` | suite/2 草稿；评分预期为 null，参考说明为空 |
| `preparation.json` | 来源/实现文件指纹、分类数量、覆盖警告、观察到的规则结果、上下文预检和环境记录栏 |
| `model-context.json`（预检通过时） | 使用生产选择逻辑构建的完整上下文对象预览 |

规则结果仅供定位问题，**不是独立标准答案**。`suite.json` 中三个字段必须由分析人员
根据来源和受控规则独立填写：

```json
{
  "expected_base_score": 6,
  "expected_critical": false,
  "reference_notes": "核对当前调用的失败状态，禁止将历史成功陈述归到当前；记录可支持的观察与覆盖不足。"
}
```

这里的 6 仅是字段示例。预期分数是规则契约，不是恶意概率或独立恶意标签。参考说明
应事先确定，包含应核对的字段、禁止推出的结论及不足。未填写时 `check` 和 `run`
均拒绝该草稿；软件不会复制观察值来自动补齐预期。期望与实际规则计算不符时报告差异，
不会改写人工填写值。环境记录栏留待记录 CAPE/处理器版本与 Guest OS。

## 离线预检，再运行模型

```sh
python -m artemis_v3.evaluation check --suite /local/cape-case-01/suite.json
```

预检只读：核对所有来源指纹、规则预期和历史关联，再用与工作台/实际评测共享的
逻辑构建上下文。结果逐例记录当前/历史的覆盖警告、已选引用和遗漏数量，`model_called` 为 false。
空证据或放不下的关键证据会显示 `ready: false`；关键证据不会被悄悄删掉以通过预检。
覆盖警告不表示报告良性。预检通过只说明来源和上下文契约可用。

退出码：0 为预检通过；1 为至少一例无法构建上下文；2 为草稿未填写、来源/配置无效
或本地 I/O 错误。准备命令退出 0 只表示草稿写出，不表示可以直接评测。

之后按 [EVALUATION.md](EVALUATION.md) 使用事先安装、锁定摘要的本地模型执行 `run`，
再逐条填写人工支持核验表。实际评测重新读取复制的 sources 并重建上下文，不从
`model-context.json` 读入模型答案。原文件之后改变不影响复制品；复制品改变会触发
指纹不匹配。修改报告、规则或代码后应重新准备预览并审核预期。

`preparation.json` 的 `draft_suite_sha256` 记录初始草稿。填写人工字段后，套件指纹
自然改变；评测使用填写后的精确套件指纹。上下文预览记录的是预览文件自身的字节
指纹，与模型传输时的紧凑 JSON 指纹含义不同。保留原始来源、准备包、代码版本、
环境记录和最终 run/review 结果，供后续核对。

本功能已用合成输入与模拟提供者验证准备、预检及上下文一致性。真实 CAPE 格式
兼容性、真实模型效果、独立专家判定和节省时间仍待实测。
