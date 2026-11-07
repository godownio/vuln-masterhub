---
id: binary-pwn-stack-unordered-map-bucket-copy-stack-overflow
title: unordered_map 单桶 bucket_size 无界复制栈溢出：键模数控制同桶并强制 13→29 扩容
type: scenario
domain: binary
path: binary/pwn/stack
technique: unordered-map-bucket-copy-stack-overflow
aliases:
- unordered_map 栈溢出
- 哈希桶复制溢出
- bucket_size 未校验
- 同桶键构造
- 13 到 29 扩容
- C++ 容器栈溢出
- std::copy 桶迭代器
tags:
- pwn
- stack-overflow
- cpp
- stl
- unordered-map
- hashtable
- ret2libc
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:57:35+08:00'
  notes: 已对照原文与7张图核对：bucket_size+std::copy 整桶复制到栈缓冲、键 key=1+i*29 在 29 模同桶、13→29 rehash、21*0x10 覆盖返回地址及 ret2libc 链均与原文 exp 一致；硬编码地址仅属原题，卡内已声明不可复用。PoC 未在本机执行
---

## 一句话结论

当 C++ 程序用 `unordered_map::bucket_size(n)` 作为长度，把某个哈希桶里的全部元素 `std::copy` 到固定大小的栈缓冲区时，攻击者可以通过控制键值让“扩容后”的同一桶塞入大量元素：默认桶数 13、`max_load_factor=1.0`，先用跨桶键把元素总数推过 13 触发 rehash 到质数 29，再让所有键都满足 `key % 29 == c`，使最多 29 个 `pair` 连续写入栈缓冲区，覆盖保存的 rbp/返回地址，配合 ret2libc/ROP 获得 shell。

## 原理

- **libstdc++ unordered_map 的桶机制**：对象前部是桶数组指针与桶数（默认质数 13），每个桶是一条单链表（头插，LIFO）；`bucket(key) = hash(key) % bucket_count`。对整数键，`std::hash<unsigned int>` 在 libstdc++ 中通常是恒等映射，因此桶号可预测为 `key % bucket_count`。
- **扩容策略**：`_Prime_rehash_policy` 默认 `max_load_factor = 1.0`；当元素总数超过 `bucket_count` 时触发 rehash，桶数扩到下一个质数（13 → 29 → 59 …），所有元素按新模数重新分桶。原文把它描述为“同一桶元素超过模数触发扩容”，实际触发条件是全局负载因子；但在本利用中两种描述都指向同一动作：先把总数推过阈值，逼出 29 桶。
- **同桶构造**：rehash 到 29 后，桶号是 `key % 29`。攻击者选择 `key = c + i*29`（`i = 0..`），这些键在 29 模下全部同余于 `c`，于是全部落入同一个桶；而在 13 模下它们分散到不同桶，不会提前把某个旧桶堆满（也不会让 rehash 前的复制先溢出）。
- **无界复制**：漏洞代码先 `bucket_size(blood)` 得到桶内元素数，再 `std::copy(begin(blood), end(blood), buf)` 把整桶复制到栈上 `std::pair` 数组。它没有检查 `bucket_size` 是否超过 `buf` 容量，也没有检查 `blood` 对应的桶是否只含少量元素。`pair<unsigned int, unsigned long>` 在 x86-64 下是 16 字节（key 4 字节 + 对齐 4 字节 + value 8 字节），元素数一多就线性覆盖栈。
- **为什么可控**：攻击者完全控制插入的键（哈希桶）和值（溢出内容）。只要桶数可预测、整数哈希可预测，攻击者就能把任意数量的元素集中到一个桶，并把每个 `pair.value` 布置成溢出 qword。
- **覆盖返回地址**：示例中栈缓冲区到返回地址约 21 个 pair（约 0x150 字节），而新桶数 29 允许单桶最多 29 个元素（29×16 = 464 字节），足以覆盖保存的 rbp 与返回地址。由于桶链表是头插、rehash 会改变节点顺序，具体哪个插入序号落到返回地址需按目标 libstdc++ 的 rehash/插入顺序实测；示例通过把栈地址与代码地址放在特定插入序号完成栈迁移/ROP。
- **后续利用**：示例先用 `Author:` 输入在固定地址放入 ROP 链（`puts@got`、`puts@plt`、`fgets` 等），再用桶溢出覆盖返回地址跳入链，泄露 libc 后二次输入 `system("/bin/sh")` 或 execve ROP。

## 触发条件

- 程序使用 libstdc++ 的 `std::unordered_map`，并把 `bucket_size(n)`/桶迭代器范围复制到固定大小的栈数组（`std::pair*` 目标），未校验元素数。
- 攻击者可控制插入的键与值，且键类型为整数（或哈希可预测）；桶数/扩容策略为默认值（13 起、`max_load_factor=1.0`）。
- 程序允许插入足够多的元素以触发 rehash（至少超过当前桶数），并能再次调用复制桶的分支。
- 目标栈缓冲区到返回地址的距离可由元素数覆盖；若开启栈 canary，需要先泄露/绕过（示例未使用 canary 或通过其它路径泄露）。
- 目标无 PIE 或已泄露代码基址、无 Full RELRO 或可泄露 GOT；示例使用 `puts` 泄露 libc 后 ret2libc。

## 利用步骤

1. **确定初始桶数与扩容阈值**：默认 `bucket_count=13`；插入第 14 个元素时触发 rehash 到 29。可通过程序行为或本地同版本 libstdc++ 验证。
2. **选择目标桶与键序列**：选定 `c`（如 1），构造 `key_i = c + i*29`。在 13 模下这些键分散（`29 mod 13 = 3`，序列 `c, c+3, c+6, ...` 覆盖多个桶），避免 rehash 前单桶过大；在 29 模下全部等于 `c`。
3. **先插入 13 个元素**：用上述键填满旧桶数（不触发 rehash），让总数达到 13。
4. **插入第 14 个元素触发 rehash**：第 14 次插入使负载因子超过 1.0，哈希表重建为 29 个桶；此前 13 个键与新键全部按 `%29` 落入同一个桶。
5. **继续插入到目标数量**：单桶最多可放 `29` 个元素（受下一次扩容阈值限制）；示例插入到 22 个，足够覆盖 21 个 pair 的栈距离。每个元素的 `value` 按溢出布局布置（填充值、栈地址、代码地址等）。
6. **调用复制分支**：程序执行 `bucket(key)` → `bucket_size(bucket)` → `std::copy(begin(bucket), end(bucket), stack_buf)`；桶内 22 个 pair 依次写入栈，覆盖保存的 rbp/返回地址。
7. **控制执行流**：示例在固定地址（`Author:` 输入缓冲区）预置 ROP 链，溢出后返回地址被改到链上；先 `puts(puts@got)` 泄露 libc，再回到 `fgets` 读入第二阶段 ROP，最终 `system("/bin/sh")` 或 execve。
8. **验证**：本地用同版本 libstdc++ 的 gdb 观察 `bucket_count`、桶链表顺序与复制起始位置，确认第几个插入序号覆盖返回地址；必要时调整 `c`、插入数量或填充值。

## PoC

```c
/* 目标接口：add(blood, evidence) 向 unordered_map<unsigned,unsigned long> 插入
 * part2(blood) 执行 bucket_size + std::copy 到栈缓冲区（无边界检查） */

/* 键选择：key = 1 + i*29，29 模下全同余 1，13 模下分散 */
for (int i = 0; i < 0xb; i++)        /* 11 个，总数未过 13 */
    add(1 + i * 29, i);

add(1 + 0xb * 29, rsp_value);        /* 第 12 个 */
add(1 + 0xc * 29, code_addr);        /* 第 13 个 */

/* 第 14 个插入触发 13 -> 29 rehash；之后所有键都在 bucket 1 */
for (int i = 0xd; i < 0x16; i++)     /* 再 9 个，共 22 个 */
    add(1 + i * 29, i);

/* 触发无界复制：bucket_size(1) == 22，22*16 = 352 字节写入栈 */
part2(1);
```

```python
# 键生成等价写法
keys = [1 + i * 29 for i in range(22)]      # 全部 %29 == 1
for i, k in enumerate(keys):
    add(k, i)                                # 第 14 个插入时 rehash 到 29
part2(1)                                     # std::copy 整桶到栈
# 示例后续：puts@got 泄露 libc -> fgets 二次读入 -> system("/bin/sh")
```

原文完整 exp 使用 `ret=0x40201a`、`rsp=0x4025be`、`addr=0x40A540` 等硬编码地址布置 ROP/栈迁移，并把 `rsp`/`addr` 放在特定插入序号；这些值依赖题目二进制与 libstdc++ 版本，不能直接复用。本卡不执行 PoC。

## 变体与关联

- **字符串键**：需要预测 `std::hash<std::string>` 并构造同余键，难度更高；若程序使用自定义哈希/加盐哈希，攻击者难以控制桶分布。
- **自定义 `max_load_factor`/`reserve`**：`reserve(n)` 会预分配更多桶，改变扩容阈值与单桶上限；攻击者需按实际 `bucket_count` 重新计算键序列。
- **32 位程序**：`pair<unsigned,unsigned long>` 可能为 8 字节（4+4），覆盖距离与元素数不同；`size_t`/指针宽度也变化。
- **其它容器**：`std::map` 的迭代器范围复制、`vector` 的 `size()` 复制、`deque` 的块遍历也可能出现“长度来自容器、目标为固定栈缓冲区”的同类错误。
- **缓解场景**：栈 canary 会先于返回地址被覆盖，需要泄露 canary 或改用不覆盖 canary 的局部指针/函数指针；Full RELRO + PIE 会提高 ROP 门槛。
- **关联**：[[code-analysis-reverse-linux-cpp-stl-container-layout-disassembly]]（unordered_map 布局、bucket/bucket_size/局部迭代器识别）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（两阶段 ret2libc 写法）、[[binary-pwn-stack-pivot-leave-ret-bss]]（栈迁移）。
- **边界**：利用依赖默认 libstdc++ 哈希/扩容策略与可控整数键；若目标使用随机化哈希、提前 `reserve` 或严格边界检查，需要另找路径。

## 检测与防御

- **代码修复**：绝不能用 `bucket_size(n)` 直接作为固定栈数组的复制长度；改用 `std::vector<std::pair<...>>` 动态扩容，或先比较 `bucket_size(n)` 与目标容量并拒绝/截断。
- **输入校验**：限制单次可插入元素数与单桶元素数；对不可信键使用随机化哈希（如带进程随机种子的 `std::hash` 封装），降低桶分布可预测性。
- **编译加固**：开启栈保护（`-fstack-protector-strong`）、PIE、Full RELRO、`FORTIFY_SOURCE`、C++ 标准库断言（`_GLIBCXX_ASSERTIONS`）；ASAN 可在测试环境直接捕获栈越界。
- **检测**：监控程序中 `unordered_map` 元素数量异常增长、单桶元素数远超平均值、`bucket_size` 与固定缓冲区容量不匹配的调用；崩溃/ASAN 报告中的栈溢出；CTF/审计中重点搜索 `std::copy(begin(n), end(n), fixed_buf)` 模式。
- **运行环境**：对处理不可信输入的 C++ 服务限制单请求可插入元素数、使用独立进程/沙箱隔离，降低溢出后的利用面。
