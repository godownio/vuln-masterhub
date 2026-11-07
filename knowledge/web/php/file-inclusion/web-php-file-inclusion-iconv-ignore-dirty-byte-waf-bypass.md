---
id: web-php-file-inclusion-iconv-ignore-dirty-byte-waf-bypass
title: iconv UTF-7//IGNORE 脏字节夹在关键词中绕过 WAF 后读取任意文件
type: scenario
domain: web
path: web/php/file-inclusion
technique: iconv-ignore-dirty-byte-waf-bypass
aliases:
- iconv //IGNORE 绕过
- UTF-7 脏字节绕过
- fl%c2ag
- 编码转换 WAF 绕过
- 过滤后归一化
tags:
- php
- file-read
- waf-bypass
- iconv
- utf-7
- encoding
- normalization
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:29:42+08:00'
  notes: 已对照原文与图01/02核对：preview.php 中 rawPath=basePath.f 先过 preg_match('/flag|\/flag|\.\.|php:|data:|expect:/i') 再做 iconv(user->encoding,'UTF-8//IGNORE')，最后 file_get_contents；图02 证实 fl%c2ag 被转换为 /flag 并读出 flag。cookie 反序列化 User 对象与 UTF-7 编码控制属实。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

当应用先用 WAF/正则检查路径、再做 `iconv($encoding, "UTF-8//IGNORE", $path)` 归一化时，在敏感关键词中插入该编码下的非法字节（如 UTF-7 里的 `%C2`），WAF 看到的是 `fl\xc2ag`，iconv 的 `//IGNORE` 会丢弃脏字节得到 `flag`，检查与使用之间的这道差异即可绕过并读取目标文件。

## 原理

- 检查发生在编码转换之前：WAF 对原始字符串做 `preg_match('/flag/i')`，而真正 `file_get_contents` 使用的是转换后的路径。
- UTF-7 中 `0x80` 以上的字节不是合法字符；`iconv('UTF-7', 'UTF-8//IGNORE', ...)` 遇到非法序列时按 `IGNORE` 策略丢弃，而不是报错或保留。
- 把 `0xC2` 插到 `flag` 中间（URL 编码 `fl%c2ag`），原始字符串不再匹配 `flag`；转换后 `0xC2` 被丢弃，路径恢复为 `/flag`。
- 之所以成立：这是典型的“过滤后归一化/规范化不一致”（parser differential）——检查器与被检查对象看到的是两个不同的字符串。
- 同一思路还可用于路径穿越（`..` 中插脏字节）、协议头（`php:`）等关键词。

## 触发条件

- 用户可控参数进入 `iconv($attackerControlledEncoding, "UTF-8//IGNORE", $path)`，或应用在其他环节做带 `//IGNORE` 的编码转换；
- 安全检查（WAF、`preg_match`、黑名单）在编码转换之前执行；
- 转换目标路径随后被 `file_get_contents`/`include`/`fopen` 使用；
- 攻击者能控制或已知源编码（本例为 UTF-7；`$user->encoding` 通过 cookie 反序列化可控）。

## 利用步骤

1. 确认路径由可控前缀与文件名拼接，检查是否在编码转换之前做关键词过滤。
2. 遍历源编码下会被 `//IGNORE` 丢弃的字节（UTF-7 可用 `0xC2`；其他编码需实测），构造 `fl<脏字节>ag`。
3. 将脏字节 URL 编码（`fl%c2ag`）传入；WAF 放行，iconv 归一化为 `flag`。
4. 结合可控 `basePath`/路径前缀读取目标绝对路径；若服务端还校验目录，需同时让前缀落在允许目录或利用穿越。

## PoC

```http
GET /preview.php?f=fl%c2ag HTTP/1.1
Host: target:8080
Cookie: user=O%3A4%3A%22User%22%3A3%3A%7Bs%3A4%3A%22name%22%3Bs%3A5%3A%22guest%22%3Bs%3A8%3A%22encoding%22%3Bs%3A5%3A%22UTF-7%22%3Bs%3A8%3A%22basePath%22%3Bs%3A1%3A%22%2F%22%3B%7D
```

服务端逻辑等价于：

```php
$rawPath = $user->basePath . $f;                      // /fl\xc2ag
if (preg_match('/flag/i', $rawPath)) { exit; }        // 不匹配，放行
$converted = @iconv($user->encoding, 'UTF-8//IGNORE', $rawPath); // /flag
echo file_get_contents($converted);
```

枚举脏字节的脚本：

```php
for ($i = 0; $i <= 255; $i++) {
  $c = chr($i);
  $r = @iconv('UTF-7', 'UTF-8//IGNORE', $c);
  if ($r === false || $r === '') echo bin2hex($c), "\n";  // 可被 IGNORE 的字节
}
```

## 变体与关联

- 变体：其他编码的非法序列（UTF-8 超长编码、GBK 截断、UTF-16 孤立代理项）；在 `..`/`php:`/`data:` 中插脏字节；双重编码后再归一化；控制 `encoding` 字段切换到更宽松的编码。
- 关联：[[web-php-file-inclusion-filter-chain-fileless-rce]]（同样利用 `php://filter` 的编码语义绕过检查）；通用路径读取见 `web/generic/file-inclusion`。
- 实现注意：文章示例的脏字节遍历脚本存在未定义变量等笔误，实际应以 `chr($i)` 为单位测试；不同 PHP/iconv 版本对 `//IGNORE` 的行为可能不同，需在目标环境验证。
- 影响边界：要求过滤在归一化之前；若应用先归一化再校验、或校验与使用同一份字符串，则不成立。

## 检测与防御

- 检测：请求参数中出现编码后不可见字节（`%C2`、`%80-%FF` 混入 ASCII 关键词）；同一参数在 URL 解码后含非 UTF-8 字节；访问日志中 `flag` 被非常规字节拆分；WAF 告警与源站访问路径不一致。
- 防御：先做编码归一化，再基于归一化后的字符串做路径校验与白名单；路径解析与使用同一份规范化结果（如 `realpath` 后再检查前缀）；固定允许的源编码，不信任客户端传入的 `encoding`；禁用 `//IGNORE` 的宽松转换，转换失败直接拒绝；对文件名只允许 `[A-Za-z0-9._-]`。
