---
id: code-analysis-reverse-firmware-8051-eeprom-protocol-mac
title: 8051 + EEPROM 固件逆向：逐指令模拟还原 AUTH/MAC 状态机，暴力 nonce 后解密 EEPROM 记录
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: 8051-eeprom-protocol-mac-reverse
tags:
- ics
- firmware
- 8051
- at89c52
- eeprom
- protocol-reverse
- mac
- emulation
- serial
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:42+08:00'
  notes: 对照 IoT242：3211B 固件、TBL/EEPROM 布局、帧格式、MAC/密钥编排/GF(2^8)、第72次 nonce 一致
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-8051-eeprom-protocol-mac/
draft: false
kb_aliases:
- 零信任数仓
- vault51.hex
- AT89C52 固件逆向
- 24C02 EEPROM
- AUTHST 滚动状态
- HART 帧 A5 5A 01
- MAC 暴力 nonce
- emu8051
---

## 一句话结论

AT89C52 + 24C02 的串口维护协议里，AUTH 状态机、MAC 与两段式密钥编排都依赖静态阅读难以确证的细节；用自写 8051 反汇编/逐指令模拟器锁定循环次数、MAC 参数顺序与 fallthrough 后，对会话中第 72 次尝试暴力 16 位 nonce 得到唯一 MAC，再按 GF(2^8) 链式解密 EEPROM 记录即可取出 flag。

## 原理

- 固件 `vault51.hex` 转二进制约 3211 字节；常量表 `TBL=d3 51 a7 09 6c e2 44 b8` 位于 0x0C83；EEPROM 0x40 起 16 字节主密钥 K，0x50 起 32 字节加密记录，0x70 起 8 字节记录 tag。
- 串口帧格式：`A5 5A 01 | cmd | step | len | payload | CRC16`，CRC16 参数为多项式 0x1021、初值 0xFFFF、MSB-first、结果大端。状态机由 `RAM[0x0B]` 的 step 驱动：
  - 0x80 开机挑战（payload 为 TBL）；
  - 0x01–0x04 AUTH 协商；
  - 0x05 带 8 字节 MAC 的命令；
  - 0xF0/0xFF 设备侧 ACK/NACK；
  - 0x90 输出块。
- 加密体系四个部件：
  1. 启动密钥 `dkey[i]=TBL[i&7]^K[i]^0x6D^i`；
  2. AUTHST 16 字节滚动状态，每收一字节做一次 rot8 与加常数前馈；
  3. MAC（0x06B2）以 `nonce_lo/nonce_hi` 与当时 AUTHST 为输入，做 rot16 与 8 轮 K/AUTH 混合，注意 `h` 取 `nonce_lo`、`l` 取 `nonce_hi`，写反则 MAC 全错；
  4. 密钥编排（0x0227）分两段，第一段 16 轮生成 T1/T2，第二段 48 轮乘 16 列以 `blk(i)=T1[i]^T2[i]` 混合；第一段末尾没有 RET，直接落进第二段，只实现第一段 T1 会完全错误。
- 记录解密（0x07F5）在 GF(2^8)（多项式 0x1B）上做链式 seed 推进；每个字节用当前 seed 查表/运算后更新 seed。
- 三个易错点都属于“静态阅读无法确证、必须逐指令模拟”的类别：
  - 0BAD/09CB 的循环用 `SJMP` 先跳到 `DJNZ` 再回跳，实际执行次数是计数值减一；
  - MAC 的 h/l 分配与直觉相反；
  - 0x0227 第一段无返回、直接 fallthrough 到第二段。
- 关键顺序：MAC 用 cmd05 载荷喂入**之前**的 AUTHST；密钥编排用喂入**之后**的 AUTHST。顺序写反则 MAC/密钥都对不上。
- 会话侧按 0x80 开机帧切分尝试；对每次尝试用其自身 cmd01–05 重建 AUTHST，对 cmd05 载荷暴力枚举 16 位 nonce 重算 MAC——只有第 72 次尝试存在唯一解（`nonce_lo=0xb3`、`nonce_hi=0x5a`，MAC=`49 a7 96 bc 3f 93 3a f7` 完全匹配），其余尝试（含重传）的 ACK 载荷是诱饵值。用第 72 次编排后的密钥解 EEPROM 记录，`emu8051` 交叉验证 `out=666c61677b`（即 `flag{`）。

## 触发条件

- 拿到 8051 固件（Intel HEX）、EEPROM 转储与串口会话抓包。
- 协议帧可解析，存在 AUTH/MAC/密钥编排等自定义密码逻辑。
- 有反汇编/模拟器可逐指令跟踪（也可用现成 8051 模拟器）。
- EEPROM 中的密文记录可由会话中恢复的密钥解密。

## 利用步骤

1. 把 Intel HEX 转二进制，定位常量表、EEPROM 布局与串口中断/状态机代码。
2. 写/用 8051 反汇编器，重点跟踪 CRC16、AUTHST 更新、MAC、密钥编排、记录解密函数。
3. 用逐指令模拟器验证循环实际次数、寄存器分配与 fallthrough，修正静态阅读的误判。
4. 解析 session.bin：按 `A5 5A 01` 与 CRC16 切帧，按 `RAM[0x0B]` step 重建每次尝试的 AUTHST。
5. 对每次 cmd05 暴力 16 位 nonce 重算 MAC，筛选唯一匹配；确认 nonce/MAC 后按正确顺序计算密钥编排。
6. 用编排密钥按 GF(2^8) 链式解密 EEPROM 0x50 起的 32 字节记录，校验 tag/输出格式，提取 flag。

## PoC

```python
# 1) 帧解析：A5 5A 01 | cmd | step | len | payload | CRC16(0x1021, init 0xFFFF, MSB-first, BE)
def parse_frames(data):
    i, out = 0, []
    while i + 6 <= len(data):
        if data[i:i+3] != b"\xA5\x5A\x01":
            i += 1; continue
        cmd, step, ln = data[i+3], data[i+4], data[i+5]
        payload = data[i+6:i+6+ln]
        crc = int.from_bytes(data[i+6+ln:i+8+ln], "big")
        out.append((cmd, step, payload, crc))
        i += 8 + ln
    return out

# 2) 启动密钥
dkey = bytes(TBL[i & 7] ^ K[i] ^ 0x6D ^ i for i in range(16))

# 3) 对 cmd05 暴力 nonce，重算 MAC；唯一匹配即正确尝试
for nonce in range(0x10000):
    lo, hi = nonce & 0xFF, nonce >> 8
    if mac(authst_before_cmd05, lo, hi, dkey) == target_mac:
        print(hex(lo), hex(hi))
        break

# 4) 按正确顺序（MAC 用喂入前 AUTHST，密钥编排用喂入后 AUTHST）计算密钥
key = key_schedule(authst_after_cmd05, dkey)
record = eeprom[0x50:0x70]
plain = gf256_chain_decrypt(record, key, poly=0x1B)
```

```text
# 第 72 次尝试唯一解：
nonce_lo=0xb3 nonce_hi=0x5a
MAC=49 a7 96 bc 3f 93 3a f7
out=666c61677b  -> "flag{"
```

## 变体与关联

- 变体：其他 8 位 MCU（PIC、AVR、STM8）同样可用反汇编+模拟器；协议可换成 Modbus/DLMS/HART 私有封装。
- 变体：MAC 可换成 CBC-MAC/CMAC/自定义 Feistel；nonce 空间更大时需用侧信道/差分而非暴力。
- 关联：[[iot-protocol-hartip-command9-quadrant-covert-channel]]（工控协议字段分析）、[[code-analysis-reverse-firmware-huawei-squashfs-mips-emulation]]（固件模拟）。
- 边界：固件加密/读保护会阻止转储；模拟器需覆盖所有外设/中断；nonce 空间大时暴力不可行；诱饵 ACK 需要靠唯一性/CRC 排除。

## 检测与防御

- 检测：固件中自定义 MAC/密钥编排、EEPROM 明文密钥、串口协议无认证/可重放；会话中出现大量 nonce 尝试与重传。
- 修复：使用标准密码算法与安全元件；EEPROM 密钥加密/绑定设备；协议加随机挑战、防重放与速率限制；关闭调试/维护接口。
- 加固：固件读保护与签名；维护口物理隔离；对串口会话做异常检测；定期轮换主密钥。
