---
id: binary-pwn-heap-strcmp-bytewise-libc-pointer-leak
title: strcmp 逐字节爆破 libc 指针：利用 NUL 截断与指针低字节左移泄露 main_arena
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-strcmp-bytewise-libc-pointer-brute-force
tags:
- pwn
- heap
- libc-leak
- strcmp
- bytewise-brute-force
- main-arena
- oracle
- glibc-2.23
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:43:39+08:00'
  notes: 已对照原文及8张图核对：strcmp遇NUL停止、data指针低字节0x55指向main_arena+0x58指针最高非零字节、逐字节从0x55递减到0x51爆破7f/ff/f7/bc/4b、补0xa0后按小端拼0x7ffff7bc4ba0并减0x3c4ba0得libc基址，与原文EXP及图07/08一致。未验证点：爆破依赖目标libc 2.23-0ubuntu11.3布局，EXP未本机复跑；CTF题无组件受影响版本；frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-strcmp-bytewise-libc-pointer-leak/
draft: false
kb_aliases:
- strcmp 泄露 libc
- 逐字节爆破 libc 地址
- main_arena+88 泄露
- 密码比较 oracle
- 指针低字节改写
- 登录比较侧信道
---

## 一句话结论

当程序用 `strcmp(input, user->data)` 做登录校验、且攻击者已能改写 `user->data` 指针时，可以把该指针指向 unsorted bin 中的 `main_arena+88` 指针附近；利用 `strcmp` 遇到 `\x00` 停止的特性，从指针的最高非零字节开始逐字节试探（每匹配一个字节就把指针低字节减 1，向左推进），最终拼出完整 libc 指针并算出 libc 基址。

## 原理

- **`strcmp` 的停止条件**：`strcmp(s1, s2)` 逐字节比较，遇到任一方为 `\x00` 就停止；只有此前所有字节相等才返回 0（登录成功）。输入缓冲区由 `memset(pass, 0, 256)` 初始化后 `read` 指定长度，因此输入在有效字节后自然是 `\x00`；`user->data` 指向的内存若在某个位置有 `\x00`，比较也会在该处停止。
- **libc 指针的字节形态**：典型 x86_64 libc 地址形如 `0x00007ffff7bc4ba0`，小端存储为 `a0 4b bc f7 ff 7f 00 00`。最高两个字节为 `0x00 0x00`，直接从头比较会在第一个 `0x00` 处停止，无法逐字节验证非零高位；但可以从最高非零字节（示例 `0x7f`，地址 `...1055`）开始，向左逐字节推进。
- **指针低字节改写**：漏洞允许改写旧 `user` 结构体 `data` 指针的最低字节。若该指针原本指向堆上某个地址（示例低字节 `0x10`），把它改成 `0x55` 就指向同一页内偏移 `0x55` 的位置——示例该位置正好是一个 libc 指针（`main_arena+88`）的第 5 个字节（最高非零字节）。
- **逐字节 oracle**：
  1. 把 `data` 低字节设为 `0x55`，调用 `login`，输入 `c`（后接 NUL）。内存从 `...1055` 开始是 `7f 00 ...`；只有 `c == 0x7f` 时，输入 `7f 00` 与内存 `7f 00` 才相等，登录成功。匹配后记录 `0x7f`。
  2. 把 `data` 低字节减 1 变为 `0x54`（指向 `0xff`），输入 `c + 已泄露的 0x7f`。内存为 `ff 7f 00...`；只有 `c == 0xff` 时相等，登录成功。记录后 `leak = ff 7f`。
  3. 重复：`0x53 → f7`、`0x52 → bc`、`0x51 → 4b`，每轮把新字节“补到已有结果最前方”，指针继续向左。
  4. 最后一个字节 `0xa0` 已知（或通过已知偏移/上一轮外推），拼成 `a0 4b bc f7 ff 7f`，`u64` 小端解析得 `0x7ffff7bc4ba0`。
- **计算基址**：该指针是 unsorted bin 的 `fd`/`bk`，等于 `main_arena + 0x58/0x60` 一类固定位置；示例 `0x7ffff7bc4ba0 - 0x3c4ba0 = 0x7ffff7800000` 即 libc 基址（低 12 位为 0，可作为校验）。
- **前提**：需要一块已释放进 unsorted bin 的 chunk 提供 libc 指针，且该指针位于 `user->data` 可指向的、低字节可控的堆地址上；指针低字节递减不会越界到不可读页。若 ASLR 下堆页与 libc 页布局变化，需要相应调整低字节或先泄露堆地址。
- **为什么是 oracle 而非直接读**：程序不提供 read/show 任意地址接口，只返回“登录成功/失败”；`strcmp` 的提前终止和返回值给了攻击者一比特（匹配/不匹配）信息，256 次以内即可确定一个字节。

## 触发条件

- 目标程序存在 `strcmp(user_input, attacker_controlled_pointer)` 的登录/比较逻辑，且失败/成功可被攻击者区分。
- 攻击者能改写该指针（例如通过 UAF 结构体复用实现对 `data` 指针的低字节/完整控制）。
- 目标 libc 为低版本（示例 2.23），存在 unsorted bin 中的 libc 指针（`main_arena+88`），且该指针的低字节位置可通过改写指针到达。
- 输入长度可控且缓冲区会补零（`memset` + `read`），使 `strcmp` 在输入末尾自然终止。
- 网络/交互稳定，可承受每字节最多 256 次比较（示例 5 字节约 1280 次，实际远少）。

## 利用步骤

1. 先制造一个进入 unsorted bin 的 chunk（如 `add(3, 0x80, ...); free(3)`），再用同尺寸分配把它取出并在起始处写 1 字节（示例 `add(4, 0x80, b'\xa0')`），保留其中的 libc 指针字节。
2. 通过 UAF 重叠把旧 `user->data` 指针的最低字节改成指向该 libc 指针的最高非零字节（示例 `0x55`）。
3. 对每个候选字节 `c`（0x00–0xff），构造 `payload = bytes([c]) + leaked`，调用 `login`，观察返回是否包含 `Login success!`。
4. 命中后把 `c` 前置到 `leaked`，把 `data` 低字节减 1，继续下一字节；重复直到覆盖指针的全部有效字节。
5. 补上已知的低字节（示例 `0xa0`），`u64(leaked.ljust(8, b'\x00'))` 得到 libc 指针，减去 `main_arena+88` 的 libc 偏移（示例 0x3c4ba0）得到基址。
6. 校验基址低 12 位为 0；解析 `system`、`__free_hook` 等符号，转入任意写/劫持阶段。

## PoC

原文 EXP 的核心循环（glibc 2.23-0ubuntu11.3，未在本机执行）：

```python
libc_leak = b''
for i in range(5):
    num = 0x55 - i
    edit(1, p8(num))              # 改写 users[0]->data 低字节，向左推进
    for c in range(0x100):
        payload = bytes([c]) + libc_leak
        res = login(0, len(payload), payload)
        if b'Login success!' in res:
            print(f'[+] 第 {i+1} 个爆破字节: {hex(c)}')
            libc_leak = bytes([c]) + libc_leak
            break
    else:
        print('[-] 爆破失败'); break

libc_leak = b'\xa0' + libc_leak
libc_addr = u64(libc_leak.ljust(8, b'\x00')) - 0x3c4ba0
print(f'[+] libc: {hex(libc_addr)}')
```

gdb 观察（原文）：`strcmp` 的 `s2 = 0x555555a01055` 指向 `0x7ffff7bc4ba0` 的第 5 字节；内存从该地址起为 `7f 00 ...`，因此正确输入 `0x7f` 时比较立即成功。逐轮把指针从 `0x55` 降到 `0x51`，依次泄露 `0x7f, 0xff, 0xf7, 0xbc, 0x4b`，再补 `0xa0`。

## 变体与关联

- **直接读接口**：若程序有 show/print 任意地址，直接读 8 字节即可，无需 oracle；本技巧适用于只有比较结果的场景。
- **其他比较函数**：`strncmp`（长度受限）、`memcmp`（无 NUL 终止，不能直接套用）、`strcasecmp`（大小写不敏感，候选集缩小）行为不同，需要调整。
- **其他 libc 指针来源**：unsorted bin `fd/bk`、large bin、`_IO_2_1_stdout_` 结构、`environ`（栈指针）、GOT 中的 libc 函数地址。
- **高版本 glibc**：2.34+ 移除 `__free_hook`/`__malloc_hook`，需转向 FSOP、`exit_funcs`、`_IO_wfile_jumps` 等；但 `strcmp` oracle 本身与版本无关。
- **关联**：指针改写来源见 [[binary-pwn-heap-uaf-struct-reuse-data-pointer]]；unsorted bin 直接读泄露见 [[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]。
- **防御**：登录比较应使用定长 `memcmp` 或常量时间比较，避免把内存比较结果作为可观测 oracle；不要向用户暴露 `strcmp` 的提前终止差异；对输入长度与失败次数做限制。

## 检测与防御

- **代码层**：避免 `strcmp` 直接比较用户输入与敏感指针/内存；使用 `memcmp` + 长度校验、常量时间比较；限制登录尝试次数与速率。
- **运行时检测**：同一会话内大量登录失败后突然成功、输入长度递增且逐字节变化，符合逐字节爆破特征；堆指针被低字节逐步修改的 UAF 行为。
- **防御**：修复 UAF 与任意指针改写是根本；启用 ASLR、堆保护与 glibc 缓解；对 CTF 服务记录异常比较次数并限流。
- **取证**：若捕获 EXP，可见 `login` 循环 0x00–0xff 试探与低字节递减；堆内存中 `user->data` 指向 libc/堆交界，是典型特征。
