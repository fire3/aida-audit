# IDA MicroCode CPG 与 CWE 扫描器（V1 设计）

本文档用于指导第一版原型实现：在 IDA/Hex-Rays 中抽取 MicroCode，离线构建 CPG，并基于图与数据流实现一组可落地的 CWE 扫描器。后续迭代以“保持数据契约与图不变式稳定”为前提逐步增强分析精度。

```{toctree}
:maxdepth: 2
:caption: 目录

01_scope
02_architecture
03_extractor_ida
04_normalized_operand
05_cpg_schema
06_builder
07_analysis
08_scanners
09_api_models
10_engineering
```

