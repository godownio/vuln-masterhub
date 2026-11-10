---
id: binary-pwn-php-zend-assign-dim-side-effect-uaf-arbitrary-rw
title: PHP VM 数组赋值副作用 UAF：error_handler 在 undefined notice 中 resize/reassign 数组，借 fakeZval 与 fake zend_string 构造任意读写
type: scenario
domain: binary
path: binary/pwn
technique: php-zend-assign-dim-side-effect-uaf-fakezval-arbitrary-rw
aliases:
- PHP ZEND_ASSIGN_DIM UAF
- PHP VM 数组 resize UAF
- zend_array butterfly UAF
- fakeZval
- fake zend_string
- addressOf 原语
- php://memory 任意读写
tags:
- pwn
- php
- zend-vm
- uaf
- fake-zval
- zend-string
- arbitrary-read-write
- heap
- interpreter
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: PHP 7.x/8.x（原文：PHP 7 或 8 均可触发 segfault；分析发布时未修复）
verification:
  verified_by: verifier-V475
  verified_at: '2026-11-10T17:27:06+08:00'
  notes: 已对照原文全部 9 图核对：ZEND_ASSIGN_DIM_OP 先算 elem_addr 后检查右值的副作用、slow_index_convert 对 undefined index 的 refcount 检查、butterfly index cells 2*capacity 与首元素 0x40 偏移、str_repeat 尺寸公式 16*4+8*0x20-0x20=0x120、true/1 为 glibc 持久字符串 vs int 100、fake zend_string gc_info=hash=0 免 COW、0x00007fff00303031 巨长 len、addressOf fake array、php_stream_memory_data 任意读写均与原文一致；PoC 为原文最小触发。原文明确 PHP 7/8 触发，affected_versions 已按原文标注。作者未公开完整 RCE exp（文章明言没有修复前不提供），卡内已如实注明，属已证明的 UAF→任意读写固原语而非仅理论链；未实测复现。
---

## 一句话结论

PHP 7/8 的 `ZEND_ASSIGN_DIM(_OP)` 在检查右值（可能是未定义变量）之前就计算好了目标元素地址；`set_error_handler` 在随后的 undefined notice 里 resize（`$array[] = 1`）或重新赋值（`$array = 2`）数组，会让该地址指向已搬移/释放的 butterfly，VM 返回后仍向 stale 地址写入，形成 UAF/内存破坏。配合在 error_handler 里用同尺寸 `zend_string` 抢占被释放的 butterfly 并伪造 zval/zend_string，可逐步构造 fakeZval、堆地址泄露、addressOf 与 `php://memory` 任意读写原语（该分析发布时官方尚未修复、无 CVE）。

## 原理

- **漏洞点（元素地址在副作用前计算）**：`ZEND_ASSIGN_DIM_OP` 的近似流程是"取 array 基址 → 按 index 算出元素地址 elem_addr → 读 elem → 检查右值 var（未定义变量会发 notice）→ 计算 res → 写回 elem_addr"。第 4 步会执行用户注册的 error_handler，handler 里对同一数组做 `$array[] = 1` 触发扩容 realloc，或 `$array = 2` 直接销毁旧数组；返回后 elem_addr 已失效，VM 仍按它写入，造成 write-after-free/越界写。官方对 undefined **index** 的转换用临时 refcount 检测数组是否被销毁，但对"要写入的值"没有同类保护。
- **为什么难以简单修复**：只检查 `arData` 是否变化会遇到 ABA（旧内存被释放、被同构结构占用又释放）；把 `check_var` 提前也不行——`$array['a']['b'] = $var` 会先用 `FETCH_DIM_W` 取到指向 `$array['a']` 的 V2 指针，后续赋值同样可能经历 handler 副作用而失效。彻底修复需要 delayed error handling 或 multi-index 形式的 ASSIGN_DIM，把错误延迟到赋值完成之后统一处理。
- **butterfly 布局**：packed/mixed array 的元素区前面是 `2 × capacity` 个 4 字节 index cells，`arData` 指向后面的 Bucket 数组；容量 8 时 index table 为 0x40 字节，Bucket 每个 0x20 字节。因此第 1 个元素的 val 相对 butterfly 起始的 offset 是 0x40。
- **fakeZval 原语**：在 handler 里触发 resize 后，被 realloc 放弃的旧 butterfly 会立即被 `str_repeat` 生成的字符串抢占；把字符串长度选成让目标 offset 0x40 落在字符串内容区（zend_string header 0x18 字节，内容从 +0x18 开始），再在内容里布置一个非 refcounted 的 fake zval（type/value 均可控），VM 的 null 写入就会落在这个 fake zval 上而不破坏其他结构。
- **泄露堆地址**：对 fake zval 执行 `.= null` 这类弱类型连接，整数/布尔会被转成字符串并把结果 string zval 写回 fake zval；用 `int 100` 得到 `string "100"` 的地址（布尔 `true` 对应 interned 的 `"1"`，位于 glibc 持久字符串区，不适合作为 PHP 堆地址），读取用户字符串即可拿到该地址。
- **fake zend_string 免 COW**：以泄露的 `"100"` 地址为基准，把 fake zval 的 value 指向 `str100_addr + 0x8` 并标成 string 类型；这个假 string 的 len 字段会读到后续堆字节，形成巨大长度（示例 `0x00007fff00303031`），足以覆盖整个 memory chunk；同时它的 gc_info 取原字符串的 hash 值（示例为 0），PHP 因此认为它不是 refcounted，写 `$heap` 时不会触发 copy-on-write，可直接漫游/修改这块内存。
- **addressOf 原语**：在可控内存布置 fake array（元素 0..7、refcount=1），用 fakeZval 包住它，触发 UAF 释放后立即申请同尺寸数组 `$hax` 抢回同一块内存；`$hax[0] = $val` 后从 `$heap` 读 fake array butterfly 的第一个元素，就得到 `$val` 的值（非 refcounted）或其指针（refcounted）。
- **任意读写**：`php://memory` 的底层结构 `php_stream_memory_data { char *data; size_t fpos; size_t fsize; size_t smax; int mode; }` 在堆上；用 fake string 布置同尺寸字符串并 UAF 释放，让 `fopen("php://memory")` 抢回，再改 `data` 指针与 `fpos`/`fsize`，即可把流读写重定向到任意内存。
- **版本与状态**：该分析在 PHP 7/8（测试至 8.3.x）上均可触发 segfault，发布时官方未修复；修复方向（delayed error handling）仍在讨论中。依赖具体版本的 Zend MM 布局与 chunk 尺寸，换版本需要重新校准。

## 触发条件

- 能执行 PHP 代码并调用 `set_error_handler`（研究环境、CTF、受限 PHP 执行环境；不是通过 HTTP 参数直接触发的 Web 漏洞）。
- error_handler 内能对参与赋值运算的同一数组做扩容（`$array[] = 1`）或重新赋值（`$array = 2`）。
- 目标 PHP 版本存在该 VM 缺陷，且尚未合入 delayed error handling 类修复。
- 能做字符串堆风水（`str_repeat` 等）并了解/可测 Zend MM 的 chunk 尺寸与 zend_string header 布局。

## 利用步骤

1. 构造全局数组 `range(0,7)` 与 set_error_handler；handler 内 `$array[] = 1` 强制扩容；执行 `$array[0] += $undef_var` 触发 undefined notice → resize → stale 写，先确认 segfault。
2. 在 handler 内 resize 后立即 `str_repeat` 分配合适长度（示例 `16*4 + 8*0x20 - 0x20 = 0x120`）的字符串抢占旧 butterfly，并在字符串内容中相对 butterfly offset 0x40 处布置非 refcounted 的 fake zval。
3. 对 fake zval 做 `.= null` 弱类型连接，读出转换后字符串的地址，得到 PHP 堆地址。
4. 用 fake zval 构造 fake zend_string（gc_info=0、巨大 len），通过 `$heap` 读写该 chunk，实现堆漫游。
5. 构造 fake array 实现 addressOf，读取任意变量/对象的地址或立即值。
6. 在堆上布置 `php_stream_memory_data`，UAF 后用 `fopen('php://memory')` 抢回，修改 data/fpos/fsize 得到稳定任意读写。
7. 后续按常规 PHP 漏洞利用模板（改函数指针/解析器结构等）完成 RCE；该分析未公开完整 exp。

## PoC

最小触发（会导致 PHP 进程 segfault，仅为原理验证）：

```php
<?php
$array = range(0, 7);
set_error_handler(function ($err, $msg) {
    global $array;
    $array[] = 1;        // 数组已满 -> resize/realloc，之前算好的 elem_addr 失效
});
function crash() {
    global $array;
    $array[0] += $var;   // $var 未定义 -> notice -> 进入 error_handler
}
crash();
```

fakeZval 抢占的尺寸示意（不含完整利用）：

```php
// error_handler 内：旧 butterfly 被 realloc 释放后，用同尺寸 zend_string 抢占
$user_str_len = 16 * 4 + 8 * 0x20 - 0x20; // 0x120，内容区覆盖目标 offset 0x40
$user_str = str_repeat('b', $user_str_len);
// 在 $user_str 内容相对 butterfly offset 0x40 处布置 fake zval
```

说明：未公开完整 exp；不要在生产环境执行。

## 变体与关联

- 变体：`$array['a']['b'] = $var` 走 `FETCH_DIM_W` + `ASSIGN_DIM`，V2 指针同样会因副作用失效；object property 的 assignment/fetch 也存在同类问题。
- 变体：把 resize 换成 `$array = 2` 直接销毁数组；函数作用域内 `unset($array)` 只清本地变量，不影响全局，不能触发。
- 变体：修复方向是 delayed error handling（错误延迟到赋值完成后再抛）或把 ASSIGN_DIM 改成 multi-index、先算完所有 index/右值；合入后该链失效。
- [[web-php-rce-uaf-memory-corruption-disable-functions-bypass]]：PHP 8 UAF 内存破坏绕过 disable_functions 的另一条 PHP 引擎利用。
- [[web-php-rce-glibc-iconv-direct-call-roundcube-session-overwrite-cve-2024-2961]]：PHP 进程内堆塑形与 zend_string 篡改的相邻思路。
- [[binary-pwn-php-extension-array-length-oob-strlen-got-system]]：PHP 扩展越界读写 → GOT 劫持，可与本卡的 fakeZval/任意读写原语对照。
- 边界：依赖 Zend MM 的具体 chunk 尺寸与页面归属（free 小内存时按 page/bin 投放），布局不对会落到错误 free_list；不同 PHP 版本/JIT 需重新校准偏移与字符串 header。

## 检测与防御

- 检测：PHP 进程在 `ZEND_ASSIGN_DIM(_OP)` 处理器附近 segfault；错误处理器内出现对参与赋值数组的 resize/reassign；堆上出现 gc_info=0 且 len 异常巨大的伪造 zend_string、异常的 `php_stream_memory_data` 覆盖。
- 防御：升级到包含 delayed error handling/相关修复的 PHP 版本；无法升级时避免在 error_handler 中修改参与赋值运算的数组；对可执行 PHP 代码的环境做进程隔离与资源限制（容器/seccomp 不是内存安全边界，disable_functions 也不能阻止内存破坏）。
