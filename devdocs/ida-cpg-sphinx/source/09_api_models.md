# 9. API 模型（V1）

V1 的跨调用语义由“API 模型”提供。没有模型时，分析默认不跨调用传播（保守截断）。

## 9.1 模型用途（V1）

模型用于回答：

- 哪些参数是 source（产生污点）
- 哪些参数是 sink（消费污点并触发告警）
- taint 是否从参数传播到返回值
- taint 是否从参数传播到内存（例如复制、格式化输出）
- 是否存在 sanitizer（例如 `realpath` 后校验前缀）

## 9.2 模型数据格式（V1 固定）

V1 采用 JSON（或 YAML 等价结构），每个条目代表一个 API：

```json
{
  "name": "memcpy",
  "match": {
    "symbol_names": ["memcpy", "__memcpy", "memcpy_chk"]
  },
  "signature": {
    "args": ["dst", "src", "n"],
    "ret": "dst"
  },
  "effects": {
    "taint": {
      "from": [{"arg": 1}],
      "to": [{"mem_of_arg": 0}]
    }
  }
}
```

字段定义：

- `match.symbol_names`：与 `CallSite.callee_name` 进行精确或大小写无关匹配（实现需固定策略）
- `signature.args`：用于给 `arg_index` 命名（便于规则表达）
- `effects.taint`：
  - `from`：污点来源（参数或返回值）
  - `to`：污点去向（参数、返回值、某参数指向的内存）

## 9.3 V1 必带模型（最小集合）

### 9.3.1 输入类（Sources）

- `recv/read/ReadFile/fgets/getenv`
  - `effects.taint.to`：写入到 buffer 参数（`mem_of_arg`）
  - `effects.taint.to`：返回值长度（`ret`）可选

### 9.3.2 拷贝/格式化类

- `memcpy/memmove/strncpy/snprintf/sprintf`
  - `memcpy/memmove/strncpy`：`src` → `mem_of(dst)`
  - `snprintf/sprintf`：format 或变参 → `mem_of(dst)`

### 9.3.3 命令执行/进程创建类（Sinks）

- `system/popen/exec*`
- `WinExec/ShellExecute*/CreateProcess*`
  - 规则以“命令参数是否 tainted”作为触发条件

