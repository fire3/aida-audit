# 基于 IDA Microcode 的污点传播分析方案

## 1. 目标与范围

本方案设计一套直接利用 IDA Microcode 的污点传播分析流程，覆盖单函数与跨函数传播，兼顾可解释性与可扩展性，面向二进制安全场景中的输入污染检测、危险调用审计与路径证据输出。

目标包括：

- 以 Microcode 为唯一语义来源，完成 DEF/USE 与调用传播
- 支持常见输入源、危险汇、净化函数与污点标签传播
- 输出可追溯证据：污点源、传播路径、落点指令与调用链

## 2. Microcode 选择与抽取策略

推荐使用 MMAT_LVARS：

- 变量被映射为稳定的 local/stack/global 形式
- 折叠表达式结构更接近语义，利于构建表达式级传播

抽取要点：

- 每条顶层指令作为语句节点
- 对指令内嵌的子树使用 for_all_ops 访问，采集 read/write 与 call
- call 的参数、返回值以及 target 统一标准化

## 3. 数据模型

### 3.1 节点与属性

- Instr：顶层 microcode 指令
- Operand：规范化 mop 结构
- CallSite：从指令中提取的调用事件

### 3.2 污点标签

- Label：字符串或枚举标记污染来源
- TaintSet：标签集合
- ValueTaint：Operand -> TaintSet 的映射
- MemTaint：地址区间/抽象内存对象 -> TaintSet

### 3.3 抽象内存对象

- StackSlot：通过栈偏移标识
- GlobalObj：通过全局地址标识
- HeapObj：通过调用返回值或简化的分配点标识
- UnknownMem：无法精确建模的内存汇总点

## 4. 传播语义

### 4.1 基本传播规则

- 赋值类：dst 继承 src 的 TaintSet
- 二元运算：dst 继承 src1 ∪ src2
- 比较/条件：不产生写，但读取污染参与路径约束
- 内存读：dst 继承 MemTaint[addr]
- 内存写：MemTaint[addr] 继承 src
- 取地址：产出地址值时标记 access_mode=addr，作为地址传播

### 4.2 调用传播

对 CallSite：

- 参数污点：按形参索引汇总为 CallContext
- 返回值：若无摘要，默认继承所有参数污点
- 已知函数摘要：根据规则覆盖默认传播
- 间接调用：基于目标表达式污点推断风险并保守传播

### 4.3 净化函数

净化函数通过摘要消除指定参数或返回值的污点：

- 例如：strncpy、memcpy 视长度与源参数进行部分传播
- 例如：sanitize、escape 等函数将输入污点转为低置信度标签

## 5. 指令级实现

### 5.1 读写与调用抽取

- 对顶层指令调用 for_all_ops visitor
- visitor 依据 is_target 标记写入，否则记为读取
- 遇到 mop_d 且为 call 指令时，记录 CallSite

### 5.2 指令传递函数

为每条 Instr 构造 Transfer：

- 输入：当前环境 Env（寄存器/变量/内存污点）
- 输出：更新后的 Env
- 依赖：读取集合与写入集合

### 5.3 表达式内传播

对单条指令内部的子表达式，仅需对 leaf mop 参与 taint 合并即可：

- 叶子：寄存器、local、stack、global、常量、字符串
- 内部节点：由指令 opcode 决定合并方式

## 6. 过程内分析算法

推荐前向数据流：

- CFG 以 microcode block 为节点
- Transfer 在指令序列中顺序应用
- 合并点采用 TaintSet 并集

收敛条件：

- Env 无变化时停止
- 可设置最大迭代次数与节点上限

## 7. 跨过程分析

### 7.1 摘要生成

对每个函数生成 Summary：

- 输入参数 -> 输出值污点映射
- 参数 -> 全局/内存副作用污点映射
- 关键调用链与外部函数使用记录

### 7.2 调用点应用

调用时：

- 使用被调函数 Summary 更新返回值与内存
- 无 Summary 则采用保守传播策略
- 外部库函数使用内置摘要表

## 8. 规则与策略

### 8.1 Source 与 Sink

- Source：read、recv、fgets、gets、scanf 等
- Sink：system、popen、strcpy、sprintf、memcpy 等
- 规则可配置，支持函数名正则与签名匹配

### 8.2 置信度与分级

- 直接来源：高置信度
- 间接传播：中置信度
- 通过净化或不确定地址传播：低置信度

## 9. 证据输出

输出包含：

- Source 位置、标签
- 传播链条：指令序列与调用链
- Sink 位置与参数索引
- 相关 microcode 文本与地址

## 10. 工程落地建议

- 抽取层与传播层解耦
- Visitor 仅负责收集 operands 与 calls
- 传播层统一处理语义与策略
- 保留原始 microcode 文本用于调试与报告

## 11. 迭代路线

- V1：过程内传播 + 规则化调用摘要
- V2：跨过程摘要与别名改进
- V3：路径敏感与条件污点约束
