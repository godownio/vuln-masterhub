---
id: web-generic-sqli-like-wildcard-metacharacter-data-exposure
title: LIKE 通配符未转义：real_escape_string 后搜索条件被 _%_ 扩大导致全表泄露
type: scenario
domain: web
path: web/generic/sqli
technique: like-wildcard-metacharacter-injection
tags:
- sqli
- like
- wildcard
- php
- mysqli
- data-exposure
- code-audit
cve:
- CVE-2026-34973
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: phpMyFAQ < 4.1.1（4.1.1 修复）
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:13:24+08:00'
  notes: 已对照原文与3张截图核对：real_escape_string不转义%/_，搜索词_%_生成LIKE '%_%_%'，正常Public返回1条、_%_返回3条并泄露SECRET/CONFIDENTIAL（图02/03）。未验证点：原文复现是把searchCustomPages逻辑提取到自建/search.php夹具，未在原生phpMyFAQ搜索路由上实测；卡内PoC沿用该夹具路径，读者需按目标实际路由替换。版本<4.1.1原文明确。CVE按原文记录。
url: /docs/web/generic/sqli/web-generic-sqli-like-wildcard-metacharacter-data-exposure/
draft: false
kb_aliases:
- LIKE 通配符注入
- LIKE wildcard injection
- real_escape_string LIKE 缺口
- _%_ payload
- 搜索条件通配符越权
- CVE-2026-34973
---

## 一句话结论

当搜索接口用 `mysqli::real_escape_string()` 转义输入后直接拼进 `LIKE '%...%'`，`%` 和 `_` 不会被转义；攻击者提交 `_%_`（3 个字符）即可把搜索条件变成“匹配任意非空字符串”，在未登录状态下取出表中全部记录，而不是只返回与关键词匹配的行。

## 原理

- `real_escape_string()` 的职责是转义 SQL 字符串界定符：NUL、`\n`、`\r`、`\`、`'`、`"`、`\x1a`。它不转义 `%` 和 `_`，因为这两个是 `LIKE` 的模式匹配元字符，不是字符串界定符。
- 漏洞代码把转义后的词直接拼进 `(page_title LIKE '%$word%' OR content LIKE '%$word%')`，没有 `ESCAPE` 子句。输入 `_%_` 生成 `LIKE '%_%_%'`：
  - 外层两个 `%` 是代码固定的前后缀；
  - 输入中的 `_` 匹配恰好 1 个字符，保证只命中非空行；
  - 输入中的 `%` 匹配任意长度序列。
- 因此 `%_%_%` 的语义是“至少包含一个字符的任意字符串”，等价于 `LENGTH(col) >= 1`，表中所有非空行都满足。
- 这不是传统的“引号闭合型”SQL 注入：单引号已被正确转义，SQL 结构没有被改变；问题在于 `LIKE` 的语义层被用户输入控制。仅使用预编译参数而不转义 `%`/`_` 也不能解决该问题，必须把通配符降级为字面字符（如 `str_replace` + `ESCAPE '|'`）。
- 该场景常见的前置过滤器是“搜索词长度至少 3 字符”；`_%_` 恰好 3 个字符，能顺利通过，属于过滤器与 payload 的边界交叠。

## 触发条件

- phpMyFAQ < 4.1.1，且公开搜索功能可调用 `searchCustomPages()`（无需登录）。
- 用户输入经 `real_escape_string()` 后直接拼入 `LIKE`，没有转义 `%`/`_` 或 `ESCAPE` 子句。
- 搜索词长度过滤器允许至少 3 个字符（`_%_` 刚好满足）。
- 数据库中存放了攻击者本不应看到的内容（内部文档、凭据、客户列表等）。
- 数据库为 MySQL/MariaDB 等使用 `%`/`_` 作为 LIKE 通配符的系统。

## 利用步骤

1. 访问公开搜索页，确认搜索参数（如 `q`）和最小长度限制。
2. 先提交正常关键词建立基线，记录结果数量。
3. 提交 `_%_`；若参数需要 URL 编码，`%` 写作 `%25`，即 `q=_%25_`。
4. 观察结果数量是否变为全表行数，并检查返回内容是否包含未公开记录。
5. 可调整 payload（如 `_%_%_`、`%_%`）适配不同长度过滤或匹配非空/特定长度行。

## PoC

```http
GET /search.php?q=_%25_ HTTP/1.1
Host: target
```

生成的 SQL：

```sql
SELECT page_title, content FROM faq_faqcustompages
WHERE (page_title LIKE '%_%_%' OR content LIKE '%_%_%')
```

```bash
# 基线
curl "http://target/search.php?q=Public"
# 通配符注入：返回全部非空记录
curl "http://target/search.php?q=_%25_"
```

```python
import requests
r = requests.get("http://target/search.php", params={"q": "_%_"})
print(r.status_code, len(r.text))
# 对比正常关键词与 _%_ 的返回条数/内容
```

## 变体与关联

- 变体：`_` 连续出现可匹配固定长度；`%` 单独使用可匹配任意长度，但常因长度过滤器被拦截，需用 `_%_` 等 3 字符组合绕过。
- 变体：其他数据库的 LIKE 元字符不同（SQL Server 还有 `[`、`]`、`^`；Oracle 使用 `%`、`_`），转义实现需按目标数据库处理。
- 变体：若 `LIKE` 输入进入的是 `ORDER BY`、`HAVING` 等其他上下文，可能从语义越权升级为结构性注入。
- 关联：[[web-generic-sqli-like-clause-append-search]] 描述的是引号闭合型 LIKE 拼接注入；本卡是转义正确但通配符语义未处理的另一类缺口。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]] 中的 LIKE 拼接点同样需要注意通配符。
- 边界：如果代码把 `%`/`_` 转义为字面字符并加 `ESCAPE`，或对搜索词做强白名单，则该 payload 失效。

## 检测与防御

- **检测（代码）**：搜索 `LIKE '%...%'` 且没有 `ESCAPE`；检查 `real_escape_string`/`escape` 后是否另有 `str_replace(['%','_'])`；SAST 把 LIKE 上下文单独建模，而不是只检查引号拼接。
- **检测（请求）**：搜索参数中出现 `%`、`_` 组成的短 payload，尤其是 `_%_`、`%_%`、`_%_%_`；同一 IP 用短通配符请求返回异常大的结果集。
- **检测（响应）**：正常关键词与通配符请求的结果数量差异巨大；未登录用户拿到内部文档/凭据字段。
- **修复**：升级 phpMyFAQ >= 4.1.1；热修复为 `str_replace(['|','%','_'], ['||','|%','|_'], $word)` 并在 SQL 加 `ESCAPE '|'`。
- **通用防御**：LIKE 查询使用参数绑定的同时，先转义 `%`、`_` 和转义符本身；对搜索结果做授权过滤和条数上限，不能依赖搜索条件本身承担访问控制。
- **加固**：数据库账号最小权限；关闭详细错误回显；对公开搜索接口做速率限制与异常结果量监控。
