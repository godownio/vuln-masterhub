---
id: code-analysis-reverse-windows-corrupted-pe-driver-xor-ioctl-backtrack
title: 损坏 PE 驱动恢复：MZ 头修复 + 每 4 字节首字节 XOR 0x44 + IOCTL 多层 XOR 逆推
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: corrupted-pe-driver-xor-ioctl-backtrack
aliases:
- PE 修复
- MZ 头损坏
- 4 字节周期 XOR 0x44
- 驱动 IOCTL 逆向
- 链式异或逆推
- Driver.sys
tags:
- reverse
- windows
- pe
- driver
- ioctl
- xor
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T02:12:53+08:00'
  notes: 已通读原文 drive 段并核对：MZ 4D5A→09 5A、每4字节首字节 XOR 0x44（This 的 69→2D）、恢复后 \??\DeviceDrive/\Device\MYDEVICE/flag is you input、缺失符号 Drive 的 md5 f2c6151d6c0d99f3666129b97e2100f5、IOCTL 0x222000、第一层 buf[i-1]^=((buf[i-1]%0x12)+buf[i]+5)^0x34、第二层两轮链式异或、32字节目标常量、中间态与 flag{wnNCZJbBOqL3QA1C1cypiKYII4} 及正向验证均一致。已修正卡内逆推示意中的运算符优先级（改为 (cand ^ (...)) & 0xff）；逆第二层代码仍为示意未完整实现。未在本机复跑驱动/脚本；无组件版本。
---

## 一句话结论

当驱动样本的 `MZ` 头被改成 `09 5A`、且整个文件每 4 字节的第 1 个字节都被 XOR 了 `0x44` 时，先按周期恢复 PE，再逆向 `IRP_MJ_DEVICE_CONTROL` 的处理函数：用链式异或的逆变换从目标常量倒推中间态，再按第一层 `buf[i-1] ^= f(buf[i-1],buf[i])` 的“依赖右邻字节”结构从末尾向前回溯，即可恢复 32 字节输入（flag 就是输入本身）。

## 原理

- **PE 头损坏**：正常 PE 以 `4D 5A`（`MZ`）开头；样本变成 `09 5A`，说明第 1 字节被 XOR 0x44（`4D^44=09`）。继续观察可打印字符串：`This` 的 `69` 变成 `2D`，而 `2D^44=69`；按“每 4 字节第 1 字节 XOR 0x44”恢复整个文件，`Driver.sys` 重新成为可解析 PE。
- **驱动入口**：`DriverEntry` 创建 `\Device\MYDEVICE` 与符号链接 `\??\DeviceDrive`（缺失符号为 `Drive`），注册 `IRP_MJ_DEVICE_CONTROL` 分发函数；用户态 `link.exe` 发送 IOCTL `0x222000`。
- **第一层变换**：
  ```c
  for (i = 1; i < 32; i++)
      buf[i-1] ^= ((buf[i-1] % 0x12) + buf[i] + 5) ^ 0x34;
  ```
  每个 `buf[i-1]` 使用尚未修改的 `buf[i]`；因此逆推应从 `i=31` 开始，最后字节 `buf[31]` 未被第一层修改。
- **第二层校验**：两轮链式异或：
  ```c
  prev = 0x34;
  for (i = 0; i < len; i++) { tmp[i] = input[i] ^ prev; prev = input[i]; }
  for (i = 0; i < len; i++) { old = tmp[i]; tmp[i] ^= prev; prev = old; }
  ```
  第二轮把 `tmp` 与 `.data` 的 32 字节常量比较；成功分支返回字符串 `flag is you input`，提示 flag 就是用户输入本身。
- **逆推**：链式异或可逆，先从目标常量倒推第一层后的 32 字节中间态；再按第一层从末尾向前枚举 `original[i-1]`，要求变换后等于中间态。候选可能多个，用可打印字符 + `flag{...}` 格式 + 正向验证筛选。
- **为什么成立**：两层变换都是确定性的可逆运算（异或/加法/取模），目标常量已知；第一层依赖右邻字节，从后往前回溯可避免“修改后影响后续”的问题。

## 触发条件

- 拿到损坏的 PE 驱动与配套用户态程序；文件头/内容呈现周期性 XOR 损坏。
- 能恢复 PE 并加载到 IDA/Ghidra 分析；驱动创建设备/符号链接并注册 IOCTL 分发。
- 目标校验是 32 字节固定长度、两层可逆变换、目标常量在 `.data`。
- 成功分支提示“flag is you input”或类似信息，说明输入即 flag。

## 利用步骤

1. 用十六进制查看 `Driver.sys`：确认 `MZ` 变 `09 5A`；比较字符串 `This` vs `Th-s`，推断每 4 字节第 1 字节 XOR 0x44。
2. 写脚本按 `for i in range(0,len,4): data[i] ^= 0x44` 恢复文件；用 PE 解析器/IDA 验证节区/导入表正常。
3. 在 IDA 中跟 `DriverEntry` → `IRP_MJ_DEVICE_CONTROL` handler；确认 IOCTL `0x222000` 与 32 字节输入。
4. 记录第一层变换与第二层两轮链式异或，提取 `.data` 目标常量（32 字节）。
5. 逆第二层：按链式关系从目标常量倒推中间态（注意 `prev` 的更新顺序）。
6. 逆第一层：`buf[31]` 未变，从 `i=31` 向前枚举 `buf[i-1]`；用中间态校验；候选按可打印/flag 格式筛选。
7. 正向验证：输入候选 → 第一层 → 第二层 → 与目标常量比较；本题得到 `flag{wnNCZJbBOqL3QA1C1cypiKYII4}`。

## PoC

```python
# 1) 恢复 PE：每 4 字节第 1 字节 XOR 0x44
data = bytearray(open("Driver.sys", "rb").read())
for i in range(0, len(data), 4):
    data[i] ^= 0x44
open("Driver.fixed.sys", "wb").write(data)

# 2) 逆第二层链式异或（示意）
def inv_second(target, init=0x34):
    # 正向: tmp[i]=input[i]^prev; prev=input[i]
    #       old=tmp[i]; tmp[i]^=prev; prev=old
    # 逆推需按正向顺序维护 prev/old，具体实现按反编译核对
    ...

# 3) 逆第一层：buf[31] 未变；从 i=31 向前枚举 buf[i-1]
TARGET = bytes.fromhex(
    "660a09e0e2e3cb0914150c38011f0542"
    "716e567a0020e4bfe6cd28302c75a03a"
)
# 中间态（逆第二层后）示例：
MID = bytes.fromhex(
    "2f3e26dec43d0f341b21171916061344"
    "622a34503470d0cf36021e323247927d"
)
# 对每个 i 从 31 到 1：
#   want = MID[i-1]
#   for cand in range(256):
#       out = (cand ^ (((cand % 0x12) + buf[i] + 5) ^ 0x34)) & 0xff
#       if out == want: buf[i-1] = cand
# 注意 buf[i] 必须是已恢复的原始值；最后正向验证。
```

## 变体与关联

- **变体（损坏模式）**：周期性 XOR、单字节头损坏、节区偏移错乱、IAT 加密；先做文件头/字符串比对推断周期。
- **变体（变换层）**：链式异或、加法/取模、查表、RC4；逆推顺序由数据依赖决定（右邻/前一项）。
- **变体（驱动通信）**：IOCTL 码、DeviceIoControl 输入/输出缓冲、符号链接名；用户态程序可辅助确认协议。
- **关联卡片**：[[binary-pwn-kernel-ioctl-global-length-oob-read-flag]]（内核 IOCTL 越界读）、[[code-analysis-reverse-windows-pe-text-code-cave-call-rel32-patch]]（PE 代码洞）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（常量识别与解密）。
- **边界**：损坏模式可能不是全局周期；驱动可能加壳/虚拟化；多层变换若有不可逆操作（哈希/压缩）需换思路。

## 检测与防御

- **文件完整性**：驱动/PE 用签名校验、哈希白名单；发现 `MZ` 异常/周期性 XOR 视为可疑。
- **驱动安全**：不要用简单 XOR/固定常量做授权校验；密钥/flag 不应硬编码在驱动 `.data`；IOCTL 输入长度/权限严格校验。
- **检测**：YARA/PE 扫描 `09 5A`、每 4 字节首字节异常、节区/导入表损坏；监控未签名驱动加载。
