---
id: crypto-hash-md5-identical-prefix-collision-pair-strict-compare
title: MD5 identical-prefix 碰撞对：两个不同字符串哈希相同，绕过 md5($a) === md5($b) 强比较
type: scenario
domain: crypto
path: crypto/hash
technique: md5-identical-prefix-collision-pair-strict-compare
aliases:
- TEXTCOLLBY 碰撞对
- md5 强比较绕过
- 相同 MD5 不同字符串
- MD5 collision pair
- PHP md5 === 绕过
- md5 碰撞对
tags:
- crypto
- hash
- md5
- collision
- identical-prefix
- fastcoll
- php
- strict-comparison
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-07T23:26:31+08:00'
  notes: 已对照原文核对：题目第三个 if 要求  !==  且 md5() === md5()，原文给出 TEXTCOLLBYfGiJUETHQ4hAcK... 与 ...hEcK... 两串（仅一字节不同、MD5 相同），img/13-14 源码与 img/16 最终 payload 均一致。卡内仅提炼该强比较碰撞原语，数组/0e/HashPump 三关按既有卡跳过合理。CTF 题解无组件版本，未设 versions。
---

## 一句话结论

`md5($a) === md5($b)` 的严格比较可被 identical-prefix MD5 碰撞对绕过：两个内容不同、但 MD5 完全相同的字符串同时满足 `$a !== $b` 与 `md5($a) === md5($b)`，既不依赖数组/null 类型混淆，也不依赖 `0e` 弱比较。

## 原理

- MD5 采用 Merkle-Damgård 迭代结构；identical-prefix collision 工具（如 fastcoll）可为选定前缀构造两条不同消息 `m0`、`m1`，使 `MD5(m0) == MD5(m1)`。
- 公开的碰撞对 `TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak` 与 `TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak` 仅一个字节不同，但 32 位 MD5 完全相同；二者都是合法字符串。
- 由于 `===` 比较的是字符串字面值，`md5($a) === md5($b)` 对碰撞对为 true，同时 `$a !== $b` 也为 true，正好满足“输入不同但哈希相同”的强比较条件。
- 与数组绕过（`md5(array)` 返回 null，`null === null`）不同，这里两个输入都是字符串，服务端即使先做 `is_string`/长度/字符集校验也可能通过。
- 与 `0e` 魔术哈希不同，强比较 `===` 下两个 `0e...` 字符串不相等；碰撞对是强比较场景的通用绕过。
- 碰撞对可用 fastcoll 对任意选定前缀现场生成；使用公开碰撞对时要注意传输层必须保持字节一致（URL 编码、表单编码、不要做 trim/转义/编码转换）。

## 触发条件

- 代码用 `md5($a) === md5($b)`（或比较两个 MD5 哈希是否相等）判断两个用户可控字符串“不同输入相同哈希”。
- 两个输入按字符串处理（不是数组），长度/字符集允许约 80 字节的任意字符串。
- 传输层不做会改变字节的规范化/截断；或攻击者能自行生成适配前缀的碰撞对。

## 利用步骤

1. 确认比较使用 `===`，且 `a`、`b` 都来自请求参数并作为字符串参与 `md5()`。
2. 构造 `a=<碰撞串1>&b=<碰撞串2>`，确保两者不同且 MD5 相同。
3. 若目标限制长度/前缀，使用 fastcoll 在相同前缀上生成新的 identical-prefix 碰撞对。
4. 提交并观察是否通过比较进入后续逻辑；注意不要触发会改变字节的 WAF 解码/转义。

## PoC

```text
a=TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
b=TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak
# 两串仅 "Q4hAcK" / "Q4hEcK" 一处不同
```

```php
<?php
$a = $_POST['a'];
$b = $_POST['b'];
var_dump($a !== $b);          // true
var_dump(md5($a) === md5($b)); // true
```

```text
# 生成新的碰撞对（identical-prefix）：
#   fastcoll -p <prefix> 生成两个共享 prefix、MD5 相同的文件/字节串
# 传输时按目标编码方式整体编码，保持二进制字节不被改写。
```

## 变体与关联

- 变体：fastcoll 生成新碰撞对；对碰撞结果再嵌套一次 identical-prefix 碰撞可构造三碰撞，见 [[crypto-hash-md5-three-way-collision-nested-fastcoll]]。
- 变体：SHA-1 也有公开碰撞对（SHAttered），但 PHP 业务中 MD5 更常见；SHA-256 目前无实用碰撞。
- 关联：[[web-generic-auth-php-md5-array-strict-comparison-bypass]]（数组/null 绕过 `===`）、[[web-generic-auth-php-md5-magic-hash-pair-double-verify]]（`0e` 魔术哈希绕过 `==`）、[[crypto-hash-md5-length-extension-password-forge-admin]]（secret-prefix 长度扩展伪造 MAC）。
- 边界：代码若先做 `is_string` 校验，碰撞对仍可用；若对输入做 trim、大小写转换、转义或长度截断，预计算碰撞对可能失效；若使用 HMAC/bcrypt/Argon2 则本手法不适用。

## 检测与防御

- 检测：两个长度约 80 字节、仅少量字节不同的字符串参数同时通过 MD5 强比较；流量中出现 `TEXTCOLLBY` 等已知碰撞前缀；同一参数在两次请求中仅单字节变化但业务判断结果相同。
- 防御：不要用 MD5 做安全相等性判断；密码存储使用 `password_hash`（bcrypt/Argon2），完整性校验使用 HMAC-SHA-256 并配合 `hash_equals`；比较用户可控哈希时拒绝超长/二进制输入并做规范化。
- 加固：在代码扫描中标记 `md5(...) === md5(...)`、`md5($x) == $y` 等模式；对认证/业务判断使用服务端密钥的 HMAC 而非裸哈希。
