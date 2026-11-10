---
id: ctf-reverse-ios-arm64-unicorn-init-string-base64-table-rc4-decrypt
title: iOS ARM64 无调试环境逆 Crypto 题：用 Unicorn 模拟 init 段机器码，从内存里直接取魔改 Base64 表与 RC4 解密结果
type: scenario
domain: ctf
path: ctf/reverse
technique: ios-arm64-unicorn-emulate-init-rc4-recover
tags:
- ctf
- reverse
- ios
- arm64
- unicorn
- emulation
- rc4
- base64-table
- mach-o
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:45+08:00'
  notes: 已对照原文核对：init 段改 base64 表、key 与密文异或还原、RC4 轮数 0xFA，Unicorn 脚本的 mem_map 四段地址、SP 与栈上伪 x0/x8（x8 低字节 0xFA）、X19/X20/X21 指向 input/key/cipher、key f6ccc8d5c9c0eec0dcedc0d7c0 与长度 0x0d、33 字节密文、0x1000058B8 处改写 W9=0x21 并跳过长度分支、0x100005938 处读 W8 拼 flag 直到 flag{45_4_105_r3v3r51n6_b361nn3r}，均与正文一致；已把取换表片段里 mem_read(0x0, 0x40) 更正为 mem_read(reg_read(X8), 0x40)（正文说明表写在 X8 指向地址，0x0 是 RC4 S 盒）；本次核对未读取图片，IDA 中 init 定位与 uEmu 界面（img/01-03）未核实；未安装 unicorn/未执行脚本。
url: /docs/ctf/reverse/ctf-reverse-ios-arm64-unicorn-init-string-base64-table-rc4-decrypt/
draft: false
kb_aliases:
- Unicorn 模拟执行解 iOS 题
- uEmu 取 base64 换表
- 魔改 RC4 轮数 0xFA
- arm64 机器码模拟执行
- 古剑山 India Pale Ale
---

## 一句话结论

iOS 逆向题把关键算法藏在 `init` 段的函数里——它们动态改写 Base64 换表、异或还原 RC4 的 key 与密文、并把 RC4 轮数改成一个非标准值（本例 `0xFA`）；在没有 iOS 调试环境的情况下，把这些函数的机器码整段喂给 Unicorn（ARM64），按 IDA 里的地址布置栈、寄存器与数据，再在指定地址下 `UC_HOOK_CODE` 读取寄存器/内存，就能直接拿到换表后的 Base64 字母表与最终明文，无需真机或越狱设备。

## 原理

- **init 段的作用**：Mach-O 里 `__mod_init_func`（Objective-C/Swift 的全局构造）在 `main` 之前执行，题目的换表、key/密文异或还原都放在这里；静态看 `init` 里的常量是「异或后的脏数据」，只有执行过才是真值。
- **为什么用模拟执行而不是直接解**：换表代码可能由多条 STP/LDP 把 64 字节表分两段写入（`STP Q0,Q1,[X8]` / `STP Q0,Q1,[X8,#0x20]`），直接读静态常量会漏掉后 32 字节的拼接顺序；用 Unicorn 跑一遍这几条指令，`X8` 指向的内存就是最终表，`uc.mem_read(X8, 64)` 即可。
- **为什么 RC4 可模拟**：RC4 是对称流密码，`加密(明文, key) == 解密(密文, key)`，所以不必把算法逆出来——把「密文 + key + 长度」放进内存，直接调用程序自己的 RC4 函数（本例轮数改成 `0xFA`）执行一遍，输出就是明文。
- **关键约束（长度分支）**：该函数用 `std::string` 构造密文，`strlen` 后若长度 ≥ `0x17` 会走 SSO 之外的分支，`operator new` 重新分配并把指针存进结构体前 8 字节；因此密文的真实地址不再是你写入的 `0x100020000`，而是新分配的堆地址，模拟时必须按程序走或在 hook 里绕开该分支。
- **必须 nop 掉外部调用**：函数尾部会 `BL std::string::push_back`，Unicorn 里没有 libc++ 实现，不 nop 会直接跳飞；改为在 `EOR W8, W9, W8`（异或出明文字节）处 hook 读 `W8` 逐字节拼 flag。
- **寄存器/栈初始化是成败关键**：`SP`、`X19/X20/X21`（分别指向输入、key、密文）、以及栈上伪 `x0/x8` 槽位都要按反编译结论摆好，否则一进入就访问非法地址。

## 触发条件

- 拿到 iOS 应用的 ipa，解包后对二进制做静态分析（IDA/Ghidra），确认关键逻辑在 `init` 段函数里且不依赖系统框架调用（或可被 nop）。
- 本机无 iOS 调试环境（无越狱机/无 lldb 连接），只能静态 + 模拟。
- 所需算法（换表、RC4、异或）只用到寄存器运算与内存读写，没有必须依赖 ObjC runtime/CoreFoundation 的调用点。
- 安装了 `unicorn`（Python 绑定）与 `keystone`（可选，用于改机器码）。

## 利用步骤

1. 解包 ipa，IDA 打开主二进制，定位 `init` 段函数（`__mod_init_func` 里的函数指针），找出三处改写：Base64 换表、RC4 key 异或还原、密文异或还原。
2. **取换表**：用 uEmu（或直接写 Unicorn 脚本）从换表函数入口模拟到 `STP Q0,Q1,[X8,#0x20]` 之后，`uc.mem_read(X8, 0x40)` 读出 64 字节字母表。
3. **取 RC4 参数**：同样方式跑 key/密文还原函数，读内存得到 13 字节 key 与 33 字节密文（本例 key `f6cc...c0`，密文 33 字节）。
4. 选定要模拟的 RC4 函数，从 IDA 复制其机器码（只取到 `ret` 之前），注意把 `BL std::string::push_back` 这类外部调用替换成 `NOP`（`0xD503201F`）。
5. 映射内存：`uc.mem_map(0x100005000, 0x9000)` 放代码、`uc.mem_map(0x10000E000, 0x10000)` 放栈、`uc.mem_map(0x10001E000, 0x20000)` 放输入/key/密文。
6. 设置寄存器：`SP=0x10000E000`，`X19=input`、`X20=key`、`X21=cipher`，并在栈上补伪 `x0/x8`（有些优化后的函数会从栈槽恢复这两个值）。
7. 处理长度分支：长度 ≥ `0x17` 时会 `operator new` 并改写指针，可在 `LDRB W9,[X20,#0x17]` 处 hook 把真实长度写进 `W9` 并 `PC += size` 跳过，避免走堆分配。
8. 在 `EOR W8,W9,W8` 处 hook 读 `W8` 累加字符，`emu_start(0x10000582C, 0x100005954)` 跑完后打印即得 flag。

## PoC

```python
from unicorn import *
from unicorn.arm64_const import *

text = bytes.fromhex("<从 IDA 拷贝的机器码，外部 BL 已 NOP 为 D503201F>")
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
uc.mem_map(0x0,        0x1000)
uc.mem_map(0x100005000, 0x9000)     # code
uc.mem_map(0x10000E000, 0x10000)    # stack
uc.mem_map(0x10001E000, 0x20000)    # input / key / cipher

INPUT, KEY, CIPHER = 0x10001E000, 0x10001F000, 0x100020000
uc.mem_write(0x10000582C, text)
uc.mem_write(INPUT,  b'flag{123456789012345678901234567890}')
uc.mem_write(KEY,    bytes.fromhex('f6ccc8d5c9c0eec0dcedc0d7c0'))
uc.mem_write(KEY+0x17, b'\x0d')                    # key_length
uc.mem_write(CIPHER, bytes.fromhex('f10a192a76f635cf0d87480d4749d8a42701821d331d0d66973b6658c3f5e2c6f6'))

uc.reg_write(UC_ARM64_REG_SP,  0x10000E000)
uc.mem_write(0x10000E008, b'\x00' * 8)             # 伪 x0
uc.mem_write(0x10000E010, b'\xfa' + b'\x00' * 7)   # 伪 x8：RC4 轮数 0xFA
uc.reg_write(UC_ARM64_REG_X19, INPUT)
uc.reg_write(UC_ARM64_REG_X20, KEY)
uc.reg_write(UC_ARM64_REG_X21, CIPHER)

flag = ''
def code_hook(mu, addr, size, userdata):
    global flag
    if addr == 0x1000058B8:                 # LDRB W9,[X20,#0x17]：绕过长度分支
        mu.reg_write(UC_ARM64_REG_W9, 0x21)
        mu.reg_write(UC_ARM64_REG_PC, addr + size)
    if addr == 0x100005938:                 # EOR W8,W9,W8：异或后的明文字节
        flag += chr(mu.reg_read(UC_ARM64_REG_W8))

uc.hook_add(UC_HOOK_CODE, code_hook)
uc.emu_start(0x10000582C, 0x100005954)
print(flag)     # flag{45_4_105_r3v3r51n6_b361nn3r}
```

```text
取 Base64 换表（跑换表函数到第二条 STP 之后）：
uc.mem_write(0x10000582C, base64_text); uc.emu_start(0x10000582C, 0x1000058B0)
print(uc.mem_read(uc.reg_read(UC_ARM64_REG_X8), 0x40))   # 表写在 X8 指向的地址，读 64 字节字母表
```

## 变体与关联

- **有调试环境**：直接 lldb 在 `init` 函数下断、`memory read` 即可，不必模拟；模拟的价值在于无设备/无越狱、需要批量解多道题时。
- **其它算法**：TEAs/XXTEA、魔改 RC4 轮数、S 盒初始化改动、自制 base64 字母表都是同一套路——找「输入 → 寄存器/内存 → 输出」的函数，构造最小内存布局后整段模拟。
- **外部调用处理**：除 nop 外，也可在 `UC_HOOK_CODE` 里对 `BL` 目标地址直接改 `PC` 跳过，或在 hook 中伪造返回值（例如 `push_back` 改成自己往缓冲写）。
- **替代工具**：`unidbg`（Java，含 JNI/虚拟文件系统）、`qiling`、IDA 的 `flare-emu`；原理相同，差别在系统调用与库的模拟完善度。
- 关联：[[ctf-reverse-ios-macho-unicorn-mach-ipc-rc4]]（同为 iOS Mach-O + Unicorn，那条模拟的是 Mach IPC 与校验逻辑）、[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（ARM64 JNI 的 Unicorn 离线 oracle）。

## 检测与防御

- 本题为 CTF 逆向，无攻击面；对教学/防守的意义是：**自定义 init 段改写算法 + 非标准轮数** 只能提高静态分析成本，一旦函数可被模拟执行就等于明文。
- 加固方向（若用于保护真实算法）：关键常量不放在可被 `mem_read` 的固定地址、算法中混入必须依赖真实运行时（系统调用/硬件）的分支、或把核心逻辑下沉到 native 之外（如服务端校验）。
- 分析侧经验：先确定函数边界与调用约定，再决定「nop 外部调用 + hook 取值」还是「完整模拟 + 伪造返回」；`SP/寄存器/内存` 三者对齐是首要步骤，否则先修地址再谈算法。
