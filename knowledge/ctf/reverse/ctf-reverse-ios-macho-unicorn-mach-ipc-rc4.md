---
id: ctf-reverse-ios-macho-unicorn-mach-ipc-rc4
title: iOS ARM64 Mach-O 游戏逆向：Unicorn 装载 + 用直接 actor handler 替换 Mach IPC，复现 RC4 解密
type: scenario
domain: ctf
path: ctf/reverse
technique: ios-macho-unicorn-mach-ipc-rc4
aliases:
- PacMan
- MachActorVM
- IPA 逆向
- iOS Mach-O
- Mach message actor
- Unicorn ARM64 仿真
- RC4 状态校验
tags:
- ctf
- reverse
- ios
- mach-o
- arm64
- unicorn
- objective-c
- mach-ipc
- rc4
- emulation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:47:50+08:00'
  notes: 已对照原文核对：pacman.ipa/MachActorVM、25×13 迷宫、分数 10000、0x100005c7c 的 288 轮校验、0x100006a1c RC4 40 字节、0x100006384 请求函数与 0x5f18/0x6100/0x6290 handler、Unicorn 装载与 mach_msg option=2 直接跳转、返回 X0==1 及 flag 输出均与原文逐行一致。未验证点：PoC 未在本机复跑；原文无图片；frontmatter 无 sources/source_url。
---

## 一句话结论

`pacman.ipa` 解压后只有一个 ARM64 Mach-O `MachActorVM`；Objective-C 方法显示这是一个迷宫游戏，分数达到 10000 后 `updateWithFrame:` 调用 `0x100005c7c` 做 288 轮状态校验并 RC4 解密 40 字节。该函数通过 Mach message 与四个 actor 交互，但 actor 处理器与 RC4 都在同一二进制内；用 Unicorn 装载 Mach-O，把 `mach_msg` 接收请求直接跳转到对应 actor handler，并伪造端口/栈保护等宿主依赖，即可完整跑出 flag。

## 原理

- **IPA 与 Mach-O**：IPA 本质是 ZIP，解压得到 `Payload/MachActorVM.app/MachActorVM` 与 `Info.plist`；可执行文件是未加密的 ARM64 Mach-O。`__objc_methlist` 中 `ViewController` 方法给出游戏主线：`restartGame`、`directionUp/Down/Left/Right`、`stepGame:`、`updateWithFrame:`。
- **游戏逻辑**：迷宫位于 `__TEXT,__cstring`，25 列、13 行；`stepGame:` 把方向传给 `0x100007a68`，维护位置、分数、豆子数、步数；分数达到 10000 时全局完成标志置位。
- **校验与 RC4**：`updateWithFrame:` 在完成标志置位后调用 `0x100005c7c`，进行 288 轮状态校验，最后在 `0x100006a1c` 解密 40 字节数据；该函数结构是标准 RC4：先用八字节状态构造长度 256 的置换表，再对 `__TEXT,__cstring + 0x3a0` 的密文执行 PRGA。
- **Mach IPC 依赖**：`0x100005c7c` 通过 Mach message 与四个 actor 交互；请求函数 `0x100006384` 按记录首字段选择 actor；三个核心处理器位于 `0x100005f18`、`0x100006100`、`0x100006290`。这些处理器和 RC4 都在附件自身代码段中，不依赖 iOS UI。
- **仿真策略**：在 Unicorn 中装载 Mach-O，映射 image/stack/return 区域；把 `mach_task_self`、栈 canary、端口数组等宿主依赖写成合法占位值；在 `mach_msg` 调用点（`0x100007eec`）判断是接收请求（option=2）还是发送，接收时把请求缓冲/回复缓冲指针放进 X0/X1，并直接跳到对应 actor handler；其他导入系统调用返回 0。这样保留题目状态链与 RC4 计算，只替换宿主系统无法提供的 Mach IPC 外壳。
- **调用入口**：从 `0x100005c7c` 开始执行到返回桩，X0 返回 1 表示 288 轮校验全部通过；末尾 RC4 解密结果写入 plain 缓冲，截断 NUL 即 flag。

## 触发条件

- 目标是 iOS IPA/Mach-O，核心校验逻辑与 RC4/状态机在二进制内，不依赖 UIKit/系统服务。
- 函数通过 Mach message 与同一二进制内的 actor 处理器交互，请求/回复缓冲布局可静态恢复。
- 可用 Unicorn 或类似 CPU 仿真器装载 ARM64 Mach-O，并能 hook 指定地址、改写寄存器/内存。
- 需要 patch 的宿主依赖（栈 canary、mach_task_self、mach_port_allocate）数量有限。

## 利用步骤

1. 解压 IPA，确认 Mach-O 架构与 Objective-C 方法表，定位游戏逻辑、完成标志与 `updateWithFrame:` 调用。
2. 反编译 `0x100005c7c`，识别 288 轮校验、RC4 初始化/PRGA、密文地址与长度；定位 `0x100006384` 与三个 actor handler。
3. 用 Unicorn 映射 image/stack/return；把栈 canary、`mach_task_self`、端口数组等写成合法占位值。
4. Hook `mach_msg`：option=2 时按 worker 编号选择 handler，设置 X0/X1 为请求/回复缓冲并跳转；发送/其他导入调用返回 0。
5. 从 `0x100005c7c` 执行到返回桩，检查 X0==1；读取 plain 缓冲，截断 NUL 得到 flag。
6. 必要时对 `0x100006660` 环境门等分支打补丁，使状态机走正常完成路径。

## PoC

```python
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM
from unicorn.arm64_const import (
    UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X21, UC_ARM64_REG_X23,
)

IMAGE, STACK, RETURN = 0x100000000, 0x200000000, 0x400000000
binary = Path("Payload/MachActorVM.app/MachActorVM").read_bytes()

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
uc.mem_map(IMAGE, 0x20000)
uc.mem_write(IMAGE, binary)
uc.mem_map(STACK, 0x20000)
uc.mem_map(RETURN, 0x1000)

# 伪造栈 canary / mach_task_self / 端口数组
uc.mem_write(IMAGE + 0xc098, struct.pack("<Q", IMAGE + 0x1ff00))
uc.mem_write(IMAGE + 0xc0e8, struct.pack("<Q", IMAGE + 0x1ff08))
uc.mem_write(IMAGE + 0x1ff00, struct.pack("<Q", 1))
uc.mem_write(IMAGE + 0x1ff08, struct.pack("<I", 1))
uc.mem_write(IMAGE + 0x10c58, struct.pack("<4I", 1, 1, 1, 1))

def ret(value=0):
    uc.reg_write(UC_ARM64_REG_X0, value)
    uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

def hook(uc, address, size, _):
    if address == IMAGE + 0x6668:
        ret(1)
    elif address == IMAGE + 0x65dc:
        uc.reg_write(UC_ARM64_REG_X0, 0)
    elif address == IMAGE + 0x6608:
        uc.mem_write(uc.reg_read(UC_ARM64_REG_X21) + 0x14, struct.pack("<I", 0x4D564901))
    elif address == IMAGE + 0x7ef8:
        uc.mem_write(uc.reg_read(UC_ARM64_REG_X2), struct.pack("<I", 1))
        ret(0)
    elif address == IMAGE + 0x7eec:
        if uc.reg_read(UC_ARM64_REG_X1) == 2:
            sp = uc.reg_read(UC_ARM64_REG_SP)
            worker = uc.reg_read(UC_ARM64_REG_X23) & 3
            handler = (0x5F18, 0x6100, 0x6290, 0x6290)[worker]
            uc.reg_write(UC_ARM64_REG_X0, sp + 8)
            uc.reg_write(UC_ARM64_REG_X1, sp + 0x70)
            uc.reg_write(UC_ARM64_REG_PC, IMAGE + handler)
        else:
            ret(0)
    elif IMAGE + 0x7e8c <= address < IMAGE + 0x8000:
        ret(0)

uc.hook_add(UC_HOOK_CODE, hook)

frame, plain, scratch = STACK + 0x100, STACK + 0x300, STACK + 0x500
for reg, value in ((UC_ARM64_REG_X0, frame), (UC_ARM64_REG_X1, plain),
                   (UC_ARM64_REG_X2, scratch), (UC_ARM64_REG_SP, STACK + 0x1f000),
                   (UC_ARM64_REG_LR, RETURN)):
    uc.reg_write(reg, value)

uc.emu_start(IMAGE + 0x5c7c, RETURN)
assert uc.reg_read(UC_ARM64_REG_X0) == 1
print(bytes(uc.mem_read(plain, 128)).split(b"\0")[0].decode())
```

## 变体与关联

- 其他跨平台 iOS 逆向：Theos/frida/LLDB 动态调试、Mach-O 解析、ObjC runtime 恢复；若函数依赖 UIKit，可补桩或改走静态算法。
- Mach IPC 替换可换成把 `mach_msg` 请求映射到本地函数、用 hook 框架模拟 reply；核心是保持请求/回复缓冲布局与状态机。
- RC4 可换成 AES/ChaCha/自定义流密码；先用常量/置换表识别算法，再决定是否仿真。
- 关联：iOS/Mach-O 逆向、Unicorn 仿真、Mach IPC、RC4 识别卡。

## 检测与防御

- 对 App 保护：核心校验不要只放在客户端，使用服务端验证/证书绑定/反调试；敏感常量加密并分散。
- 对分析方：先识别跨平台依赖，能用纯算法复现就不要完整仿真；需要仿真时只替换宿主服务，保留目标状态机。
- 检测：iOS 应用被 Unicorn/QEMU 装载、异常 `mach_msg` 调用序列、进程映射非系统镜像；App 启动时检测调试器/仿真环境。
