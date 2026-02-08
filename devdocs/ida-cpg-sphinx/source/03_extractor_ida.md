# 3. IDA/Hex-Rays 抽取器（Extractor）设计

## 3.1 运行环境与前置条件

- 必须运行在 IDA Pro 的 Python 环境内，并且具备 Hex-Rays 许可（MicroCode 依赖反编译器）。
- 对 IDA/Hex-Rays API 差异必须通过兼容层隔离：导出格式不随 IDA 小版本变化。
- 对无法反编译的函数：V1 直接跳过，并在 `functions.jsonl` 中记录 `status="failed"` 与错误信息。

## 3.2 导出包目录结构（固定）

Extractor 输出一个目录（V1 不压缩，便于调试与增量）：

- `meta.json`
- `functions.jsonl`
- `imports.jsonl`（可选，存在则离线侧加载）
- `exports.jsonl`（可选）
- `strings.jsonl`（可选）

文件编码：

- JSON 必须为 UTF-8。
- 所有地址字段使用十六进制字符串（例如 `"0x401234"`），避免跨语言 64 位整数歧义。

## 3.3 `meta.json`（Program 元信息）

`meta.json` 必须包含：

```json
{
  "binary_id": "sha256:<hex>",
  "input_path": "<extractor 运行时看到的路径，仅用于追踪>",
  "arch": "x86_64|x86|arm64|arm|mips|...",
  "endian": "little|big",
  "bitness": 32,
  "imagebase": "0x140000000",
  "ida": {
    "version": "9.2",
    "hexrays": true
  },
  "extractor": {
    "version": "v1",
    "time_utc": "2026-02-08T00:00:00Z"
  }
}
```

约束：

- `binary_id` 必须稳定：对输入文件内容做 SHA-256 后编码成 `sha256:<hex>`。

## 3.4 MicroCode 生成策略
建议在每个函数上：
- `gen_microcode(func_ea)` 获取 mba
- 将 maturity 推进到 `MMAT_LOCOPT`（Local Optimization）
  - 选择理由：此级别已完成基本的控制流图（CFG）构建与死代码消除，但尚未进行高阶的“栈变量映射（LVARS）”与“调用参数折叠”。
  - 优势：保留了更接近汇编/RISC 的指令形态（明确的 flag 操作、寄存器传递参数），避免了 Hex-Rays 过度优化导致的逻辑合并（如 `setz` + `jnz` 被合并为 `jz`，或复杂的 `call` 嵌套），更适合精确的数据流分析与漏洞挖掘。
- 遍历 `mba` 的 block 与 insn
- 尽可能提取 `minsn.ea` 与 `mop` 的来源信息

关键点：
- **Maturity Level**：锁定在 `MMAT_LOCOPT`。不要使用 `MMAT_LVARS` 或更高，因为高层级会掩盖底层的 flag 依赖与寄存器传输细节。
- 间接调用：优先结合 IDA 的 xrefs、类型签名、vtable 识别结果、以及 microcode 中的 callee mop 形态做保守解析。

## 3.5 `functions.jsonl`（函数级导出契约）

`functions.jsonl` 每行一个函数记录。每条记录必须包含下列字段：

```json
{
  "func_ea": "0x401000",
  "name": "sub_401000",
  "type_str": "int __cdecl sub_401000(int a1)",
  "status": "ok|failed|skipped",
  "error": null,
  "microcode": {
    "maturity": "MMAT_LOCOPT",
    "blocks": [
      {
        "block_id": 0,
        "start_ea": "0x401000",
        "end_ea": "0x401020"
      }
    ],
    "cfg_edges": [
      {
        "src_block_id": 0,
        "dst_block_id": 1,
        "branch": "fallthrough|true|false|switch|exception|unknown"
      }
    ],
    "insns": [
      {
        "block_id": 0,
        "insn_idx": 0,
        "ea": "0x401004",
        "opcode": "m_call",
        "text": "call $memcpy",
        "reads": [
          {"role": "callee", "index": 0, "op": {"kind": "global", "name": "memcpy", "...": "..."}},
          {"role": "explicit", "index": 0, "op": {"kind": "reg", "name": "R0", "...": "..."}},
          {"role": "explicit", "index": 1, "op": {"kind": "reg", "name": "R1", "...": "..."}},
          {"role": "explicit", "index": 2, "op": {"kind": "reg", "name": "R2", "...": "..."}}
        ],
        "writes": [
          {"role": "explicit", "index": 0, "op": {"kind": "reg", "name": "R0", "...": "..."}}
        ],
        "call": {
          "kind": "direct|indirect|unknown",
          "callee_name": "memcpy",
          "callee_ea": null,
          "args": [
            {"kind": "reg", "name": "R0", "...": "..."},
            {"kind": "reg", "name": "R1", "...": "..."},
            {"kind": "reg", "name": "R2", "...": "..."}
          ],
          "ret": {"kind": "reg", "name": "R0", "...": "..."}
        }
      }
    ]
  },
  "decompilation": {
    "pseudocode": null,
    "ea_to_line": null
  }
}
```

约束：

- `reads` / `writes` 是 V1 的关键契约：Builder 仅基于它们生成 `USE/DEF`，不在离线侧做 opcode 语义推断。
- `text` 用于报告与调试，不参与等价判断。
- `call` 字段只在 call 语义指令上出现；其内容与 `reads/writes` 保持一致。

## 3.5 `imports.jsonl` / `exports.jsonl` / `strings.jsonl`

这三类文件为可选，但一旦存在必须满足以下最小字段：

- `imports.jsonl`：
  - `name`（符号名）
  - `ea`（若可得）
  - `module`（若可得）
- `exports.jsonl`：
  - `name`
  - `ea`
- `strings.jsonl`：
  - `ea`
  - `value`（UTF-8 字符串；无法解码则使用 `base64:<...>`）

## 3.6 失败与降级策略（V1）

- 若 `decompile(func_ea)` 失败：
  - 记录 `status="failed"`，`error` 写入异常摘要；
  - `microcode` 为 `null`。
- V1 不回退到反汇编级 CPG（避免数据契约膨胀）；回退作为 V2 选项引入。

