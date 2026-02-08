# CWE-78 修复总结报告 - 2026-02-08

## 1. 修复概览

**修复对象**: CWE-78 (OS Command Injection) 检测引擎
**相关用例**: 
- `CWE78_OS_Command_Injection__char_connect_socket_execl_21-bad`
- `CWE78_OS_Command_Injection__char_connect_socket_execl_22-bad`
**修复结果**: 漏报已解决，检测率提升至 100% (针对上述用例)

## 2. 问题分析

在 `CWE78_OS_Command_Injection__char_connect_socket_execl_21/22-bad` 用例中，污点传播路径存在跨函数调用的情况。

**传播链条**:
1.  **Source**: `recv` 函数在辅助函数 `badSource` 中被调用。
2.  **Propagation**: `recv` 将数据写入缓冲区。
3.  **Return**: `badSource` 函数通过返回值（ARM64 架构下为 `x0` 寄存器）将缓冲区地址返回给调用者。
4.  **Sink**: 调用者接收返回值，并将其传递给 `execl` (arg 3)。

**根本原因**:
原有的 `TaintEngine` 缺乏**跨函数追踪能力 (Interprocedural Tracing)**。当引擎追踪到 `badSource` 的调用点时，无法自动进入函数内部去关联返回值与内部污点源的关系，导致追踪中断，产生漏报。

## 3. 解决方案

修改了 `backend/aida_cli/taint_engine.py`，实现了针对特定模式的跨函数追踪启发式算法。

### 3.1 核心变更

在 `TaintEngine` 中增加了 `_trace_interprocedural` 逻辑：

1.  **识别调用**: 当追踪遇到未知来源的函数调用返回值时。
2.  **进入函数**: 获取被调函数的控制流图 (CFG)。
3.  **定位返回值**: 根据架构惯例（ARM64）查找对应的返回值变量（如 `x0` 或 `fp:0`）。
4.  **递归追踪**: 从返回值变量开始，在被调函数内部反向追踪，检查是否连接到已知的 Source（如 `recv`）。

### 3.2 代码实现 (片段)

```python
# backend/aida_cli/taint_engine.py

def _trace_interprocedural(self, call_id, visited, depth):
    # ... 省略部分代码 ...
    # 查找被调函数节点
    func_node = self.func_map.get(name)
    if not func_node:
        return False
        
    # 定位返回值变量 (启发式: x0 / fp:0)
    return_var = self._find_return_var(func_node)
    
    # 递归追踪被调函数内部
    return self._trace(return_var, visited, depth + 1)
```

## 4. 验证结果

使用回归测试脚本 `scripts/regression_test_cwe78.py` 进行验证。

**命令**:
```bash
python scripts/regression_test_cwe78.py --filter "char_connect_socket_execl_2"
```

**输出**:
```
[1/2] Processing CWE78_OS_Command_Injection__char_connect_socket_execl_21-bad... Detected
[2/2] Processing CWE78_OS_Command_Injection__char_connect_socket_execl_22-bad... Detected
------------------------------------------------------------
Total Files: 2
Processed:   2
Detected:    2
Missed:      0
Detection Rate: 100.00%
```

## 5. 总结

本次修复通过引入轻量级的跨函数追踪机制，增强了 `TaintEngine` 处理函数封装型污点源的能力。该修复不仅解决了当前的漏报，也为未来处理类似的跨函数数据流问题奠定了基础。
