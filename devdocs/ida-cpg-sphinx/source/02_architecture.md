# 2. 总体架构

## 2.1 两阶段流水线（强制）

系统严格拆分为两阶段：

1) **IDA 内抽取（Extractor）**
- 输入：完成 IDA 分析的 `idb/i64` 与目标函数集合。
- 输出：导出包目录（只包含结构化数据，不依赖 IDA 运行时）。

2) **IDA 外构建与分析（Builder/Analyzer）**
- 输入：Extractor 导出包目录。
- 输出：内存 CPG + `findings.jsonl`（可选附加 SARIF）。

分离的约束：

- 离线侧不得依赖任何 IDA API；所有离线所需信息必须在导出包中显式提供。
- 离线侧必须能复现同一导出包下的图 ID 与边集合（图可重建）。

## 2.2 目录与模块（原型布局）

V1 建议按如下模块边界实现（目录名可根据仓库约定调整，但职责不得混淆）：

- `extractor_ida/`
  - 遍历函数、生成 MicroCode、抽取 CFG/指令/操作数、导出 `functions.jsonl`
  - 提供“操作数规范化”实现（见第 4 章）
- `cpg/`
  - CPG Schema 常量（节点/边 kind 枚举、role 枚举）
  - 图构建器（MicroCode 导出包 → CPG）
  - 图查询 API（按 kind/属性过滤、邻接遍历、按地址索引）
- `analysis/`
  - reaching definitions（生成 `REACHING_DEF` 派生边或内存索引）
  - intra-procedural taint（函数内污点传播）
  - dominator（用于“检查是否支配 sink”判定）
- `scanners/`
  - 规则框架（matcher + analysis + report）
  - 规则集（CWE-121/122/134/78）

## 2.3 数据契约优先级

V1 的工程优先级是“先稳定数据契约，再提升分析精度”：

- 导出包字段与含义优先稳定，尽量少依赖 IDA 版本差异。
- 构建侧仅做确定性的结构组装与一致性校验；不在构建期做重型推断。
- 分析侧产生的派生关系（例如 `REACHING_DEF`、污点路径）必须可重跑且可解释。

