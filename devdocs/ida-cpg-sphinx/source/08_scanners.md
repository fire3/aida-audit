# 8. 扫描器（V1）

V1 扫描器以“候选匹配 → 证据验证 → 报告输出”为固定流程。任何告警必须包含可回到 IDA 的定位信息。

## 8.1 规则执行框架（固定接口）

每条规则包含三个阶段：

- `match(cpg) -> Iterator[Candidate]`
  - 只做快速过滤，输出候选 sink/source 组合
- `analyze(cpg, candidate) -> Optional[Finding]`
  - 执行数据流/控制流验证，构造证据链
- `render(finding) -> dict`
  - 输出 JSON finding（8.2）

## 8.2 `findings.jsonl` 输出格式（V1 固定）

每行一个 JSON 对象，字段固定：

```json
{
  "rule_id": "cwe-134.printf.format_tainted",
  "cwe": "CWE-134",
  "title": "Format string is attacker-controlled",
  "severity": "high|medium|low",
  "confidence": "high|medium|low",
  "binary_id": "sha256:<hex>",
  "func_ea": "0x401000",
  "sink": {
    "kind": "CallSite|Instr",
    "ea": "0x401234",
    "callee": "printf",
    "arg_index": 0
  },
  "sources": [
    {"kind": "CallSite|Instr", "ea": "0x401100", "name": "recv"}
  ],
  "evidence": {
    "path_ea": ["0x401100", "0x401120", "0x401234"],
    "node_ids": ["C:0x401000:0x401234", "I:0x401000:3:12"],
    "key_values": {
      "format_kind": "string|nonconst",
      "taint_carriers": ["V:0x401000:stack:fp:-32"]
    }
  },
  "message": "printf 的 format 参数可被外部输入影响"
}
```

约束：

- `func_ea/sink.ea/sources[].ea/path_ea[]` 必须能在 IDA 中定位。
- `node_ids` 使用第 5 章 ID 规则。

## 8.3 V1 内置规则集（必须实现）

### 8.3.1 CWE-121/122：危险拷贝

目标 sink：

- 无界：`strcpy/strcat/gets/sprintf`
- 有界但长度可控：`memcpy/memmove/strncpy/snprintf`

候选匹配（match）：

- 找到 `CallSite.callee_name` 命中上述名单的调用点。

验证（analyze）：

- 无界 API：直接报告 `confidence=high`。
- memcpy 类：
  - 若 size 参数为非 `Const`，并且可由 source 污点到达，则报告 `confidence=medium/high`（取决于证据完整度）。
  - 若能在支配关系上发现长度检查并覆盖 sink，则降级或抑制（依规则策略）。

### 8.3.2 CWE-134：格式化字符串

目标 sink：

- `printf/fprintf/sprintf/syslog`（按平台扩展）

验证（analyze）：

- format 参数（通常 arg0/arg1，按函数签名由模型决定）：
  - 若为 `String` 常量：不报
  - 若为非 `String`：报告
  - 若可从 source 污点到达：`confidence=high`

### 8.3.3 CWE-78：命令执行

目标 sink：

- POSIX：`system/popen/exec*`
- Windows：`WinExec/ShellExecute*/CreateProcess*`

验证（analyze）：

- 命令参数若为非 `String` 且可 taint 到达：报告 `high`
- 若只满足“非 String”但无 taint 证据：报告 `medium`

## 8.4 去重（V1 固定 key）

同一问题的去重 key：

`(rule_id, func_ea, sink.ea, sink.callee, sink.arg_index, binary_id)`

