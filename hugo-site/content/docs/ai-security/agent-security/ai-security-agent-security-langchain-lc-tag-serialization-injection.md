---
id: ai-security-agent-security-langchain-lc-tag-serialization-injection
title: LangChain Core 的 lc 信任标记注入（CVE-2025-68664 LangGrinch）：密钥窃取、任意类实例化与 RCE
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: langchain-core-lc-tag-serialization-injection
tags:
- ai
- agent
- langchain
- langchain-core
- deserialization
- serialization-injection
- trust-tag
- secret-exfiltration
- rce
cve:
- CVE-2025-68664
severity: high
confidence: high
status: verified
affected_versions: langchain-core < 0.3.81；langchain 1.0.0–1.2.4（原文靶场 0.3.74）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:38:37+08:00'
  notes: 已对照原文核对；dumps 不转义 lc、secret 解析、AIMessage 实例化、修复版 __lc_escaped__ 转义，均与正文与截图 6/7 一致；卡内已注明 constructor+Jinja2 RCE 为原文描述的组合路径而非单独执行的 PoC；affected_versions 按原文标记设置。
url: /docs/ai-security/agent-security/ai-security-agent-security-langchain-lc-tag-serialization-injection/
draft: false
kb_aliases:
- CVE-2025-68664
- LangGrinch
- lc 标记注入
- LangChain 序列化注入
- lc constructor
- lc secret 密钥窃取
- dumps 不转义 lc
---

## 一句话结论

`langchain-core < 0.3.81`（及 `langchain 1.0.0–1.2.4`）在 `dumps()`/`dumpd()` 序列化普通字典时不转义其中的保留键 `lc`；攻击者让带 `{"lc":1,"type":"secret","id":["KEY"]}` 或 `{"lc":2,"type":"constructor",...}` 的字典经提示注入进入状态并被持久化，后续任意一次 `loads()` 都会把它当作受信任的框架对象：解析环境变量/密钥映射中的秘密、实例化 `langchain*` 命名空间内任意类，结合 Jinja2 模板可进一步 RCE。

## 原理

- **`lc` 是信任标记而非普通数据**：LangChain 序列化格式用 `lc` 保留键表示“这是框架原生对象”。`{"lc":1,"type":"secret","id":["KEY_NAME"]}` 让反序列化器从 `secrets_map` 或环境变量解析真实值；`{"lc":1/2,"type":"constructor","id":["module","Class"],"kwargs":{...}}` 让反序列化器动态导入模块并调用构造器。
- **合法序列化器的约定**：`dumpd()` 只在序列化真正的框架对象时写入 `lc`。攻击者提供的普通字典本不应携带它，加载端也不应把它当信任标记。
- **缺陷**：0.3.74 的 `dumps()`/`dumpd()` 序列化自由字典时原样保留内嵌 `lc` 键，没有转义、也没有区分“框架生成”与“用户数据”。攻击者内容只要经过一次持久化，再被 `loads()` 读回，就获得了与框架对象相同的信任等级（P(x)=TRUSTED），从而执行 import/构造器语义。
- **三种后果**：① 密钥窃取——旧默认 `secrets_from_env=True`，反序列化会把环境变量中的 API Key、数据库密码等填入攻击者指定的 `id`；② 任意类实例化——目标类在 `langchain_core`/`langchain`/`langchain_community` 命名空间内时，可实例化命名空间内任意类；③ RCE——结合 Jinja2 模板引擎，在模板渲染路径执行代码。
- **入口与 LLM 的关系**：与 CVE-2025-64439 相同，提示注入让 LLM 输出带 `lc` 键的结构化 JSON（或经 RAG 文档、工具返回进入状态），应用用 `dumps()` 持久化，之后任何 `loads()` 触发。无需工具调用，也无需攻击者直接接触序列化字节流。
- **修复方式**：≥0.3.81 / ≥1.2.5 将用户数据中的 `lc` 转义为 `__lc_escaped__`（截图已验证），使反序列化后仍是普通 dict；同时构造器白名单与 `secrets_from_env` 默认关闭。

## 触发条件

- `langchain-core < 0.3.81`（0.3.x 线）或 `langchain 1.0.0–1.2.4`（原文靶场 `langchain-core 0.3.74`）。
- 应用把攻击者可影响的字典用 `dumps()`/`dumpd()` 序列化并持久化（会话、缓存、消息历史、检查点），之后调用 `loads()` 读取。
- 加载时未显式传入严格的 `allowed_objects` 白名单。
- 密钥窃取需 `secrets_from_env=True`（旧默认）或加载方传入含敏感值的 `secrets_map`；RCE 需 Jinja2 模板路径可达。
- 攻击者能让带 `lc` 键的结构进入上述数据流（提示注入、RAG 投毒、工具输出、用户可控 JSON 字段）。

## 利用步骤

1. 在输入中构造带保留键的字典，例如 `{"payload": {"lc": 1, "type": "secret", "id": ["MY_API_KEY"]}}`。
2. 让该结构进入模型输出/状态（提示注入让 LLM 原样输出 JSON，或投毒 RAG 文档）。
3. 应用调用 `dumps()`/`dumpd()` 持久化；漏洞版原样保留 `lc` 键。
4. 应用或框架后续调用 `loads()`；Reviver 把 `payload` 当受信任对象：`secret` 解析出密钥值，`constructor` 动态导入并实例化。
5. 读取反序列化结果中的秘密，或利用实例化/Jinja2 路径执行代码。
6. 对照修复版：`lc` 被转义为 `__lc_escaped__`，`loads()` 得到普通 dict，秘密不解析。

## PoC

```python
from langchain_core.load import dumps, loads

attacker = {
    "user_input": "totally normal text",
    "payload": {"lc": 1, "type": "secret", "id": ["MY_API_KEY"]},
}
blob = dumps(attacker)                      # 0.3.74：lc 键原样保留
obj = loads(blob, secrets_map={"MY_API_KEY": "sk-LEAKED-12345"})
print(obj["payload"])                       # -> sk-LEAKED-12345
```

```text
# 原文截图输出（0.3.74）：
# [1] secret extracted on loads(): True
# [2] loads() produced object of class: AIMessage
# [!] SERIALIZATION INJECTION CONFIRMED
#
# 修复版（1.6.6）：
# dumps() 输出 {"payload":{"__lc_escaped__":{...}}}
# [1] secret extracted on loads(): False
# [2] loads() produced object of class: dict
```

```text
# 构造器形态（示意，未在原文中单独执行）：
{"lc": 2, "type": "constructor", "id": ["langchain_core", "<Class>"], "kwargs": {...}}
# 结合 Jinja2 模板渲染路径可进一步执行代码
```

## 变体与关联

- 变体：`type=secret` 指向环境变量中的云厂商密钥、数据库口令、模型 API Key；批量读取后外带。
- 变体：`type=constructor` 实例化命名空间内的类，构造器副作用或后续方法调用可造成文件写入/网络请求。
- 变体：与 Jinja2/模板注入组合，把对象实例化升级为模板表达式执行。
- 关联：[[ai-security-agent-security-langgraph-checkpoint-json-fallback-rce]]（同属智能体框架序列化注入，CVE-2025-64439，靠 JSON 回退触发）、[[web-python-deserialization]]（pickle、yaml 等“数据获得代码语义”的同类问题）、[[ai-security-prompt-injection]]（把恶意结构送进状态的上游入口）。
- 边界：升级到 `langchain-core >= 0.3.81` 或 `langchain >= 1.2.5`；加载端显式限制 `allowed_objects`；`secrets_from_env=False`；应用不持久化/不回读攻击者可控字典；目标命名空间无可利用构造器时影响降低。

## 检测与防御

- 检测：依赖版本 `langchain-core < 0.3.81` 或 `langchain 1.0.0–1.2.4`；持久化数据中出现未转义的 `"lc":`、`"type":"secret"`、`"type":"constructor"`；`loads()` 结果中出现预期外的 `AIMessage` 等框架对象；反序列化后立即出现环境变量读取/网络外连；状态中用户可控字典含 `lc/type/id/kwargs`。
- 修复：升级 `langchain-core >= 0.3.81`（0.3.x）或 `>= 1.2.5`，`langchain >= 1.2.5`，`langgraph-api >= 0.5`；成套升级依赖。
- 加固：`loads(blob, allowed_objects="messages")` 或显式类白名单；`secrets_from_env=False`；进入状态前递归剥离 `lc/type/id/kwargs/graphs` 保留键；对持久化字节做 HMAC 签名并验签；数据与框架对象分命名空间存储。
