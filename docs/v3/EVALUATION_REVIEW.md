# 在工作台核验固定评测输出

评测完成后，无需手工编辑每条 ratings JSON，即可在现有证据视图中核验原输出，
保存到复核库并导出对应本次运行的人工评分表。全程不重新调用模型，也不运行样本。

## 启动与核验

先运行 EVALUATION.md 的单/双来源套件，保留 suite、其引用的来源文件以及 run.json。
以下合成示例中，输出目录须不存在，父目录已存在：

```sh
python -m artemis_v3.evaluation run --suite tests/fixtures/semantic_eval/historical_suite.json --replay tests/fixtures/semantic_eval/historical_replay.json --output-dir ../artemis-history-eval
python -m artemis_v3.workbench --evaluation-suite tests/fixtures/semantic_eval/historical_suite.json --evaluation-run ../artemis-history-eval/run.json --review-db ../artemis-eval-reviews.sqlite
```

`--evaluation-suite` 与 `--evaluation-run` 必须同时提供，须配置 `--review-db`，
不得同时配置 `--ollama-model`。这是原调查工作台的可选离线入口，无新运行依赖。
单来源 suite/run/1 与带来源归属的 suite/run/2 均可打开；实际模型运行也可在模型离线时核验。

1. 在“固定评测 · 人工核验”选取用例和重复轮次，点击“打开评测输出”。
2. 在模型解释中展开当前/历史引用，结合人工参考说明核对文字。错误引用导致的失败
   尝试保留在列表中，仍可查看来源和失败原因，但没有可保存的解释。
3. 逐条填写支持程度与理由，填写核验人，点击“保存并选用于本轮评测”。未检查的条目
   保持未核验。已有核验时，从本次精确输出的核验历史明确载入对应修订，再继续修改。
4. 为其他尝试重复以上步骤。相同生成内容在不同轮次出现时，也须逐次明确保存或载入
   并选择；不会自动把一次判断复制到其他轮次。可以移除当前选择。
5. 填写汇总人并导出核验包。原核验人、汇总人分别保留，两者都是本地声明身份。

切换输出时，未保存草稿须明确放弃。核验判断按原 CLAIM_REVIEW.md 追加修订。
页面中的本次选择仅在当前页面有效，刷新后须重新打开并从历史载入、明确选择；数据库中的
核验不会丢失。导出只读取明确选择的已保存修订，即使该输出已有较新修订，也不会擅自换版。
未保存草稿不进入评测评分表。调查报告、规则基准分、评分调整决定均保持独立。

## 核验包

下载 `artemis-evaluation-review.zip`，包含：

| 文件 | 用途 |
|---|---|
| `ratings.json` | 原有 `artemis-eval-ratings/1` 或 `/2`，精确绑定 run.json 原始字节 |
| `summary.json` | 与原 CLI 共用校验与汇总；未核验不计作支持，无核验时支持比例为空 |
| `bindings.json` | 每个明确选择的用例/轮次、review ID、修订、生成指纹、原核验人及记录指纹；另列未选择尝试 |

解压到新目录后，可用原命令重新计算汇总（结果应与 summary.json 一致）：

```sh
python -m zipfile -e artemis-evaluation-review.zip ../artemis-eval-human-review
python -m artemis_v3.evaluation review --run ../artemis-history-eval/run.json --ratings ../artemis-eval-human-review/ratings.json
```

失败尝试仍保留在原 run 的技术失败分母；人工汇总只统计有解释的陈述，不会凭空给失败
输出添加“正确”评分。核验包不包含原始报告、完整 run 或复核库，应与这些来源一起保留。
包内可能含有模型陈述、核验理由和人名，不会自动匿名化或上传。

## 校验和边界

启动前校验套件、来源、完整尝试集合、规则预期、提示词与实现指纹，再用记录的文字
重建生产上下文与解释契约，核对来源归属、遗漏、模型元数据和评分门禁。工具实现或提示词
不一致时拒绝打开，使用对应的代码版本运行。旧版工具没有该入口时，仍可使用其原 JSON
核验流程；不把旧记录静默迁移为当前实现的测量结果。

服务端固定本次运行与来源快照，浏览器只选择用例/轮次 ID，不提供文件路径或替换的
来源。启动后的文件修改不改变该快照；重启后重新校验。端点沿用回环 Host、Origin 和
随机请求令牌保护。普通调查模式仍可使用，但无关输出的核验不能导入本次评测。

导出重新读取具体 review ID，检查输入、完整生成快照及当前证据，拒绝混用其他运行、
输出、来源、修订或重复选择。只有同一个生成快照可在明确选择时供不同重复轮次复用；
该关联在 bindings.json 中可见。导出不写库，不调用模型，不修改 run，不作恶意性结论。

这些检查证明数据之间的一致性，不能认证模型实际执行过或证实文字正确。未签名 run
和数据库校验和不抵抗有意重写所有内容及哈希的人。当前回归与浏览器验收使用合成报告、
回放或模拟模型；实际 CAPE 兼容性、真实模型质量、独立专家核验和省时效果仍待实际测量。
