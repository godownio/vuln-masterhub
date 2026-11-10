---
id: web-generic-sqli-sqlmap-heuristic-probe
title: SQL 注入启发式探测：随机引号串报错/类型转换报错/算术求值差异一次请求初筛可注入参数（sqlmap heuristic check）
type: scenario
domain: web
path: web/generic/sqli
technique: heuristic-sqli-probe-error-casting-arithmetic
aliases:
- sqlmap 启发式检测
- heuristicCheckSqlInjection
- possible integer casting detected
- 算术求值探测 SQL 注入
- 随机引号串探测注入
- 类型转换报错判定注入
tags:
- web
- sqli
- sqlmap
- heuristic
- detection
- error-based
- type-casting
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463
  verified_at: '2026-11-10T14:33:38+08:00'
  notes: 已对照原文核实：HEURISTIC_CHECK_ALPHABET 随机串、wasLastResponseDBMSError/CASTED/算术求值判据、--smart/--skip-heuristics 与 XSS/FI 顺带探测均与原文一致；工具技法卡无需 affected_versions；原文为源码走读无实弹 PoC，卡内已标注。dup-scan 报告(2026-11-08)早于建卡(2026-11-10)，不涉及本卡。
---

## 一句话结论

sqlmap 在发正式注入 payload 前会先做一次低成本的启发式探测：向参数值塞入一段必含单个单引号和单个双引号、并混有括号与逗号的随机串，依据响应是否出现数据库报错、类型转换异常，或数字原值被替换为 `(原值+随机数)-随机数` 后回显是否等价，决定该参数是否值得进入完整注入测试；这一探测还会顺带提示反射型 XSS 与文件包含。

## 原理

- **探测串设计**：随机串长度 10，字符取自 `" ' ) ( , .`，循环生成直到单引号、双引号各恰好出现 1 个，再拼上用户指定的 prefix/suffix 放入参数值。引号用于闭合字符串上下文，括号/逗号用于闭合函数调用或制造语法错误，目标是让参数无论落在字符串还是数值上下文都尽量触发一次数据库语法错误。
- **报错判据**：发出探测请求后，用 DBMS 错误特征判断响应页是否为数据库报错页（`wasLastResponseDBMSError`）。命中则启发式结论为 POSITIVE，并可从报错文案解析出数据库类型。
- **类型转换判据**：若响应没有 DBMS 报错，但页面出现类型转换异常特征串（`FORMAT_EXCEPTION_STRINGS`，如 `Type mismatch`、`Conversion failed`、`java.lang.NumberFormatException`、`ValueError: invalid literal`、`invalid input syntax for integer` 等），且原始页面没有这些串，则标记为 CASTED——说明参数确实到达了后端的数字转换（如 `intval`、`Integer.parseInt`、`int.TryParse`），但不代表可注入。
- **算术求值判据**：当参数原值是纯数字、页面动态（`kb.dynamicParameter`）且未命中上面两条时，再发 `(原值+randInt)-randInt` 形式（数学上等于原值，如 `5189-5188` 对应原值 1），依据回显是否与原始请求等价来判断表达式是否被后端求值；不命中时再退化为 `原值.随机数+随机串` 形式进一步确认。这是不依赖引号、特征更低的数值型注入探测思路。
- **中止条件**：页面 heavily dynamic（每次请求内容差异过大）时停止启发式，避免误判；`--skip-heuristics` 直接跳过该阶段。
- **参数跳过策略**：判定为 CASTED 时，`--smart` 会对启发式结果非 POSITIVE 的参数直接跳过；用户对 "do you want to skip those kind of cases" 回答跳过后，`kb.ignoreCasted` 也会跳过 CASTED 参数。这正是 sqlmap 提示 "possible integer casting detected" 后不再测试该参数的原因，也是漏报真实注入点的常见来源。
- **顺带探测**：同一函数随后发送 `randStr1 + 固定占位串 + randStr2` 组成的标记值——若该标记值（大小写不敏感）原样出现在响应中，提示可能存在反射型 XSS（输入被回显且未做 HTML 编码）；若响应匹配文件包含报错正则且包含 `randStr1`，提示可能存在文件包含。两者都只是提示，不是确认。

## 触发条件

- 目标参数会进入 SQL 查询（任意 DBMS、任意后端语言）；
- 应用会把数据库错误或类型转换错误回显到页面，或至少返回可区分的内容（报错判据失效时只能依赖算术/回显差异）；
- 手工复现或自建探测时需要能控制 prefix/suffix 以闭合引号、括号上下文。

## 利用步骤

1. 在可疑参数值处插入随机串（同时含一个 `'`、一个 `"`，以及 `)(,.` 字符），保持其余请求不变。
2. 对比原始响应：出现数据库错误关键字说明高度可疑；出现类型转换异常说明参数进入了数字转换，继续做算术探测；无差异则换参数或换上下文。
3. 对数字型参数发送 `x+rand-rand`（数学上仍等于 x）：若响应与原始请求等价，说明表达式被求值，存在数值型注入的可能。
4. 将确认可疑的参数交给 sqlmap 或手工 payload 继续深入（报错、联合、布尔、时间盲注等）。
5. 若 sqlmap 在 "heuristic (basic) test ... might be injectable" 之后跳过了参数，检查是否被 CASTED 判定与 `--smart` 影响，可用 `--skip-heuristics` 强制进入完整测试。

## PoC

无 PoC（原文为 sqlmap 源码走读，未对真实目标执行）。手工探测的最小请求示意：

```http
GET /search?q=1'"),( HTTP/1.1
Host: target

# 观察响应是否出现 DBMS 报错 / 类型转换异常

GET /search?q=5189-5188 HTTP/1.1
Host: target

# 期望响应等价于 q=1 的原始请求，说明表达式被后端求值
```

## 变体与关联

- 报错型探测依赖详细错误回显；生产环境统一错误页时失效，应改用算术、布尔或时间差异判断。
- CASTED 是"参数被当数字转换"的信号而非注入确认，但说明参数进入了强类型 sink（如 cast 后仍拼接进查询），值得继续审计代码。
- 同一随机标记可复用于反射型 XSS（原样回显）与文件包含（报错含标记）的初筛，相当于一次请求覆盖 SQLi/XSS/FI 三类 sink 的粗筛。
- 与 `--smart` 的关联：启发式跳过是 sqlmap 扫描结果漏报的常见原因之一，遇到可疑参数可关闭启发式或强制测试。

## 检测与防御

- 关闭或统一数据库错误页与调试信息，类型转换失败也返回统一错误，消除报错 oracle；
- WAF/日志侧可识别 sqlmap 启发式特征：参数值中出现长度约 10、混合 `'")(,.` 的随机串，或 `数字+数字-数字` 形式的算术参数；
- 数字参数强制类型转换并拒绝非数字输入，从根上消除字符串上下文注入；
- 根本上仍应使用参数化查询/预编译。
