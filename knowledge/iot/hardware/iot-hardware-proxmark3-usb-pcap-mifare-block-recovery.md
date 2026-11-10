---
id: iot-hardware-proxmark3-usb-pcap-mifare-block-recovery
title: Proxmark3 USB 流量解析：按 PM3a/PM3b 帧格式提取 mf_readblock，按 blockno 还原 M1 卡 64 块数据取 flag
type: scenario
domain: iot
path: iot/hardware
technique: proxmark3-usb-pcap-mifare-block-recovery
aliases:
- Unfare
- Proxmark3 流量分析
- MIFARE Classic 数据恢复
- mf_readblock 0x620
- PM3a PM3b 帧格式
- M1 卡 64 块
tags:
- iot
- hardware
- rfid
- nfc
- mifare
- proxmark3
- usb-pcap
- protocol-decode
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:22:43+08:00'
  notes: 已对照原文核对：tshark -e usb.capdata导出、PM3a/PM3b帧magic/len/cmd解析、cmd 0x620对应mf_readblock_t{blockno,keytype,key[6]}、res[10:-2]写回out[blockno]、64块按块号重排取首字节拼接均与正文脚本及img01/02一致；最终crew{s3al_mak3_flag_l0ng_t0_c0v3r_th3s3_bl0cks!}与原文一致。未复跑原文pcapng。
---

## 一句话结论

拿到 Proxmark3 与主机之间的 USB pcapng 后，按 Proxmark3 new frame format 解析 `PM3a` 请求帧与 `PM3b` 响应帧，识别 `mf_readblock`（cmd `0x620`）请求中的 `blockno`、`keytype`、`key`，用对应响应帧的数据写回 `out[blockno]`；M1 卡共 16 扇区 × 4 块 = 64 块，读取顺序是随机的，按绝对块号重排后取每块首字节拼接即可恢复 flag。

## 原理

- **Proxmark3 帧格式**（new frame format）：
  - 命令：`[magic PM3a] [length+ng] [bool ng:1] [cmd] [data] [crc]`
  - 响应：`[magic PM3b] [length+ng] [bool ng:1] [status] [cmd] [data] [crc]`
  - 解析：`magic=frame[:4]`；`len = u16(frame[4:6]) & 0x7fff`；`cmd = u16(frame[6:8])`；`data = frame[8:]`（尾部含 CRC）。
- **mf_readblock**：`cmd=0x620`，请求 data 对应 `PACKED mf_readblock_t { uint8_t blockno; uint8_t keytype; uint8_t key[6]; }`，尾部 2 字节是 CRC，所以取 `cmd_data[0]` 为 blockno、`cmd_data[1]` 为 keytype、`cmd_data[2:-2]` 为 6 字节 key。
- **响应数据**：响应帧去掉 10 字节头部与 2 字节 CRC（`res[10:-2]`）即 16 字节块数据；脚本把 `out[blockno] = res[10:-2]`，因此不依赖读取顺序。
- **M1 存储结构**：16 个扇区，每扇区 4 块（块 0/1/2 为数据块，块 3 为控制块含密钥 A/存取控制/密钥 B）；绝对块号 0~63。块 0 为厂商代码，只读。
- **为什么按首字节能出 flag**：题目把 flag 的每个字符放在各块的首字节；随机顺序读取时如果直接按到达顺序拼接会乱序，必须用请求里的 `blockno` 还原绝对顺序，再过滤空块/零字节。
- **pcap 提取**：USB 流量用 `tshark -r traffic.pcapng -T fields -e usb.capdata` 导出每帧 hex，再按换行两两配对请求/响应。

## 触发条件

- 拿到 Proxmark3 与主机通信的 pcapng（USB 层，capdata 可见 PM3a/PM3b 帧）。
- 目标卡为 MIFARE Classic（M1），抓包期间读卡成功（响应含 16 字节块数据）。
- 已知/抓包中使用的扇区密钥可读（响应非错误状态）。
- 有 tshark 与 Python（struct）环境。

## 利用步骤

1. `tshark -r traffic.pcapng -T fields -e usb.capdata` 导出 capdata，得到成对的请求/响应 hex。
2. 逐对解析：请求取 magic、len、cmd、data；响应取 `res[10:-2]` 数据。
3. 对 `cmd == 0x620` 的请求，读 `blockno = data[0]`，把响应 16 字节写入 `out[blockno]`。
4. 忽略 0x107（version）、0x109（ping）、0x112（capabilities）等非读块命令。
5. 把 `out` 的 64 块拼成 `card.bin`；取每块首字节、去掉 `\x00`，按块号顺序拼接为字符串。
6. 检查是否得到 `flag{...}`/`crew{...}`；若字符缺失，确认块号解析与 CRC 偏移是否正确。

## PoC

```python
from struct import unpack

# 每行一个 usb.capdata 帧（请求/响应成对）
lines = open('capdata.txt').read().splitlines()
out = [b'\x00' * 16] * 64
for req_hex, res_hex in zip(lines[::2], lines[1::2]):
    req, res = bytes.fromhex(req_hex), bytes.fromhex(res_hex)
    cmd = unpack('H', req[6:8])[0]
    if cmd == 0x620:                      # mf_readblock
        blockno = req[8]                  # cmd_data[0]
        out[blockno] = res[10:-2]         # 16 字节块数据
        print('RDBL block', blockno)

print(b''.join(b[0:1] for b in out).replace(b'\x00', b''))
```

## 变体与关联

- 其它 Proxmark 命令（`mf_readblk` 加密读、`hf mf` 系列）可按同一帧格式解析，关键是找对 cmd 与 data 结构。
- 若响应头偏移不同（不同固件/是否带 ng 位），先用 version 响应校准 `res[10:-2]` 的起点。
- 非 M1 卡（DESFire/CPU 卡）数据布局不同，需按对应协议解析。
- 关联：Saleae 逻辑分析硬件协议卡；M1 卡加密/AES 认证类 CTF 题可结合密钥恢复。

## 检测与防御

- 该场景是取证/CTF 技巧；对真实资产，USB 流量与读卡器日志可能泄露卡片数据，敏感场景应使用加密卡（DESFire EV2/EV3、CPU 卡）并保护主机 USB 抓包。
- 对 M1 卡不要存放明文敏感数据；扇区密钥应定期轮换，避免默认密钥。
- 监控异常读卡/大量 mf_readblock 请求与 Proxmark3 设备接入。
