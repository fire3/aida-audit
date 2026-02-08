# 10. 工程化约束（V1）

## 10.1 文档构建（Sphinx + Markdown）

本文档工程使用 Sphinx + MyST（Markdown 解析）：

- 源码目录：`devdocs/ida-cpg-sphinx/source/`
- HTML 输出目录（推荐）：`devdocs/ida-cpg-sphinx/_build/html/`

构建命令：

```bash
python -m sphinx -b html devdocs/ida-cpg-sphinx/source devdocs/ida-cpg-sphinx/_build/html
```

依赖（需要在环境中安装）：

- `sphinx`
- `myst-parser`

## 10.2 持久化（V1 可选）

V1 默认只保留导出包与扫描结果，不要求持久化整张 CPG。若需要持久化，采用 SQLite 两表：

- `nodes(id PRIMARY KEY, kind, binary_id, func_ea, ea, props_json)`
- `edges(src, dst, kind, props_json)`

约束：

- 持久化不得改变 ID 规则；重建必须得到相同的 `id`。

## 10.3 性能策略（V1）

- Extractor：
  - 函数级 try/catch，失败不影响整体导出；
  - 仅导出 V1 必需字段（reads/writes/call/cfg），避免导出完整 MicroCode 对象快照。
- Builder：
  - 流式读取 `functions.jsonl`，避免一次性加载全量 JSON；
  - intern 结构必须使用 dict/set，避免 O(n²) 查找。
- Scanners：
  - 先做候选过滤（按 callee_name、String/Const 参数筛选），再对候选做数据流分析。

## 10.4 回归样本（V1 必备）

V1 必须准备三类样本并能自动跑完：

- 合成样本：每个 CWE 一个最小程序（编译成多平台/多优化级版本）
- 开源样本：至少一个中等规模项目的 release 二进制
- 真实漏洞样本：至少 1 个公开 PoC 可复现的二进制

验收要求：

- 对合成样本：每条规则至少命中 1 条高置信 finding。
- 对开源样本：扫描全量完成，且输出可定位（不要求零误报）。

