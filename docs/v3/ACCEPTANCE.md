# Artemis v3 集成验收清单

更新：2026-10-21。目标：让 AI 减少证据整理、关联和报告撰写的重复劳动，
分析人员保留事实核验、评分调整和最终决策。

当前 Lite alpha 的范围是**读取已有报告，辅助本地分析**。完整 V3 另需隔离
Worker 和动态取证。工程验收不代表检测准确率、真实模型质量或生产发布批准。

## 当前集成范围

`feat/artemis-v3-integrated-acceptance` 在来源归属开发链上整合 VT 修复，保留
两侧提交来源及原分支/PR；没有合并 GitHub PR、修改 main 或发布。

| 能力 | 已实现的工程能力 | 仍需验证或开发 |
|---|---|---|
| CAPE 证据/时间线 | 字段指针、报告指纹、调用状态、分时钟域时间线 | 实际部署版本、完整行为语义 |
| 评分/复核 | 基准分保留、关键负向建议阻止、复核追加历史 | 生产规则、独立标签与效果评估 |
| 案件归档/回溯 | 保存原始字节、重开、精确哈希查询 | 部署备份；样本字节身份仍未核验 |
| 模型/历史对照 | 显式调用、受限上下文、来源引用、导出 | 真实模型权重、事实支持与归因质量 |
| 双报告评测 | 固定来源、失败计数、来源分组人工核验表 | 真实独立语料与专家核验 |
| VT 查询 | 响应身份/计数/时间、大小和重定向约束 | 真实服务兼容性、缓存与限流 |
| 工作台 | 导入、查看、对照、复核、归档、导出 | 目标系统的实际试用 |

## 工程验收命令

从仓库根目录运行，无额外 Python 运行依赖，不需要模型或沙箱：

```sh
python -m compileall -q artemis_v3
python -m unittest discover -s tests -p 'test_v3*.py' -v
python -m artemis_v3 demo.example --format json
python -m artemis_v3.workbench
```

最后一条启动回环工作台。在浏览器加载合成演示，检查引用与时间线并导出。
持久化须显式配置独立的复核/归档数据库，见 WORKBENCH.md。
Chromium CI 包含桌面/手机、历史选择、复核和导出流程，使用合成报告和模拟模型服务。

单来源与历史套件分别运行，**输出目录须不存在，父目录已存在**：

```sh
python -m artemis_v3.evaluation run --suite tests/fixtures/semantic_eval/suite.json --replay tests/fixtures/semantic_eval/replay.json --output-dir ../artemis-single-acceptance
python -m artemis_v3.evaluation review --run ../artemis-single-acceptance/run.json --ratings ../artemis-single-acceptance/review.json
python -m artemis_v3.evaluation run --suite tests/fixtures/semantic_eval/historical_suite.json --replay tests/fixtures/semantic_eval/historical_replay.json --output-dir ../artemis-history-acceptance
python -m artemis_v3.evaluation review --run ../artemis-history-acceptance/run.json --ratings ../artemis-history-acceptance/review.json
```

应分别记录 6 次与 5 次技术接受，基准分违规为 0；关键负向建议分别 2 次与 1 次，
均被阻止。人工支持比例应为空，核验覆盖率为 0。回放刻意包含错误的成功/归因陈述，
说明技术接受与事实支持必须分别评估。CI 保存两套 run/review JSON；被拒输出留在失败分母。

## Lite 实际试用前的剩余验收

| 优先级 | 任务 | 完成证据 |
|---|---|---|
| P0 | 实际脱敏 CAPE 格式契约 | CAPE/处理器版本；正常、失败、稀疏、大报告的字段/状态/时间核对 |
| P0 | 真实本地模型端到端运行 | 锁定权重摘要；单/双报告重复运行；耗时、失败、遗漏及版本记录 |
| P0 | 分析人员核验解释/校正 | 逐条核对观察、推测与降分理由；记录危险降权、误归因、核验覆盖 |
| P0 | 实际任务省时验证 | 同批报告的人工基线、辅助分析及纠错总耗时；保留最终结论与分歧 |
| P1 | 发布前集成审查 | Draft PR 依赖及 VT 修复审查；干净检出运行验收；合并与发布另行决定 |
| P1 | 部署与数据恢复 | 目标系统启停、数据库备份恢复、升级与失效来源处理实测 |

真实模型命令与审核表见 EVALUATION.md。先定义来源、预期及参考说明，再生成；
私有套件的两个来源均准确声明 `synthetic: false`，仅使用显式锁定的本地模型。
当前环境没有实际模型权重，不能把模拟服务通过写成真实模型验收。
报告不会自动匿名化；私有来源与结果保留本地，不提交到公共仓库。

## 完整 V3 后续范围

- 独立 Host/Worker、隔离任务状态、取证采集和失败恢复。
- BSON/PCAP/内存/截图证据读取及有证据支持的行为关联。
- 版本化规则、ATT&CK 映射、独立标签语料与误报/漏报/危险降权评测。
- 在可追溯精确来源基础上扩展检索与调查状态。

以上尚未交付。完成度只能作为范围估算，不能由 PR 或测试数量换算。
