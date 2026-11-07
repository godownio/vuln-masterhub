---
id: iot-industrial-mms-filewrite-firmware-upload-forensics
title: MMS fileWrite 恶意固件上传取证：TPKT/COTP/MMS TLV 重组与 XOR/ZIP/LZMA 分层解码
type: scenario
domain: iot
path: iot/industrial
technique: mms-filewrite-firmware-upload-reassembly
aliases:
- MMS 文件传输
- IEC 61850 MMS
- fileOpen fileWrite fileClose
- MMS TLV 重组
- 保护继电器固件后门
- LZMA-alone PE
tags:
- ics
- mms
- iec61850
- scada
- forensics
- pcap
- firmware
- backdoor
- tlv
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:51:49+08:00'
  notes: 已对照原文核对；TPKT/COTP/MMS fileWrite 偏移重组、XOR 0x5A、ZIP、LZMA-alone、PE 与 license 裁决一致；PoC 为示意，具体 TLV 宽度需按抓包核对
---

## 一句话结论

在 IEC 61850/MMS 网络中，攻击者可以用 MMS 的 `fileOpen`/`fileWrite`/`fileClose` 把恶意固件或后门分块上传到保护继电器等设备；防守方从流量中按 TPKT→COTP→MMS 逐层解析，按 `fileWrite` 的偏移 TLV 重组上传文件，再对载荷做单字节 XOR、ZIP、LZMA-alone、PE 分层解码，即可还原攻击者上传的后门与指标。

## 原理

- MMS（Manufacturing Message Specification）是 IEC 61850 站控层使用的协议，通常承载在 TCP 102 端口，下层是 TPKT（ISO-on-TCP）与 COTP。
- 报文分层：TPKT 头 `03 00 <len16>` 给出总长度；COTP 数据帧常见 `02 f0 80`；其上为 MMS PDU（confirmed request/response）。
- MMS 文件服务：`fileOpen` 打开目标文件，`fileWrite` 分块写入，`fileClose` 关闭。`fileWrite` 请求体是 TLV 序列：`80 01 01`（文件句柄）、`81 <offset 小端>`（写入偏移）、`82 <len> <data>`（数据块）。攻击者常按 256 字节分块，末尾不足一块再发一次。
- 重组：解析每个 `fileWrite` 的偏移与数据，按偏移建表后按序拼接，得到完整上传件；只按包序拼接会在乱序/重传时出错。
- 载荷常再套多层：整体单字节 XOR（用 ZIP 头 `PK\x03\x04` 做 known-plaintext 可恢复 key，如 0x5A）→ ZIP → 内部文件为 LZMA-alone（头 `5d 00 00 00 04 ff`）→ 解出 MZ PE（如 x86-64 MinGW 后门）。
- PE 字符串常保留明文线索：反弹 shell 命令、自检/启动日志、工业协议数据点路径（如 `REL521_SUBALPHA`）、`ENCRYPTED_LICENSE=` 等；同一程序内两处单字节 XOR 可互相验证 key。
- 该攻击链的最终危害是设备固件被替换/植入后门：MMS 本身缺少强认证与完整性校验时，攻击者只要能在网络中与设备建立 MMS 会话，就能上传文件。

## 触发条件

- 目标网络使用 MMS/IEC 61850，设备开放 TCP 102 且允许 MMS 文件服务。
- 攻击者能建立 MMS 关联（无认证、弱认证或已窃取凭据），并对目标路径有写权限。
- 上传文件大小/分块符合设备限制；设备接受 `fileOpen`/`fileWrite`/`fileClose`。
- 防守方抓到包含文件传输的 PCAP；上传件经过 XOR/压缩/PE 等至少一层编码。
- MMS 流量未被加密（IEC 62351 未启用）或攻击者可解密。

## 利用步骤

1. 过滤流量：从 PCAP 中筛 TCP 102，按 TPKT 长度切分报文，解析 COTP 后得到 MMS PDU。
2. 定位文件服务：找到 `fileOpen`（目标文件名，如 `REL521_FW_v2.1.bin.gz`）、多条 `fileWrite`、`fileClose` 的请求/响应配对。
3. 提取 TLV：在每个 `fileWrite` 请求体中定位 `80 01 01 81`，读取句柄、偏移（小端）、长度与数据；按偏移建字典，按序拼接。
4. 识别编码：检查拼接结果首字节/熵/魔数；用常见压缩头做 crib。若与 `PK\x03\x04` 逐位异或得到固定 key，则整体 XOR 解码。
5. 解 ZIP：`unzip` 或 Python `zipfile` 提取内部文件；若内部文件头为 `5d 00 00 00 04 ff`，按 LZMA-alone 解码。
6. 分析 PE：确认 MZ/PE 头、架构、编译器；提取字符串（反弹 shell、自检日志、数据点路径、license 密文）；定位启动期完整性校验循环与真正的 license blob（排除诱饵）。
7. 还原攻击链：记录上传时间线、源/目的 IP、文件名、大小、分块数、解码后的 PE 哈希与 C2/命令；与设备固件基线比对。
8. 处置：隔离设备、恢复可信固件、轮换 MMS 凭据、启用 IEC 62351 安全、封禁攻击源。

## PoC

```python
def read_be(buf, pos):
    ln = buf[pos]; return buf[pos+1], ln, pos+2

def extract_written_file(frames):
    chunks = {}
    for fr in frames:
        i = fr.find(b"\x80\x01\x01\x81")
        if i < 0:
            continue
        p = i + 5 + fr[i + 4]          # 跳过句柄 TLV
        tag, ln, p = read_be(fr, p)
        if tag == 0x82:
            off = int.from_bytes(fr[i+5:i+9], "little")
            chunks[off] = fr[p:p+ln]
    return b"".join(chunks[k] for k in sorted(chunks))

blob = extract_written_file(file_write_frames)
# 单字节 XOR（key 由 ZIP 头 crib 恢复）
key = blob[0] ^ 0x50  # 'P'
zip_data = bytes(b ^ key for b in blob)
# 之后按 ZIP/LZMA-alone/PE 继续分析
```

PoC 为解析逻辑示意，未对真实 PCAP 执行；实际 TLV 偏移/长度字段需按 MMS 编码与抓包核对。

## 变体与关联

- 变体：`fileRead` 反向读取设备文件（配置、密钥、固件）外带；`fileRename`/`fileDelete` 破坏取证。
- 变体：载荷只用单字节 XOR 或 Base64，不压缩；或使用多层 ZIP/LZMA/PE 组合。
- 变体：同一 MMS 会话中混有正常读测点（MMXU、SUBALPHA）与异常文件传输，需按服务类型过滤，不能把背景流量当攻击。
- 关联卡片：[[iot-protocol-rtps-dds-writer-spoofing]]（工控协议无认证伪造）、[[iot-protocol-someip-sd-stopoffer-spoof-tp-command]]（SOME/IP 伪造）、[[defense-forensics-cve-2026-34621-pdf-js-layered-deobfuscation]]（分层载荷去混淆思路）。
- 注意：本例来自 CTF 流量分析，攻击链与解码结果在该 PCAP 中闭合；真实变电站的 MMS 实现、分块大小、文件路径与认证方式可能不同。

## 检测与防御

- 检测：监控 MMS `fileOpen`/`fileWrite`/`fileClose`，对写入固件路径、非运维时段、异常源 IP、超大文件/大量分块告警；建立正常运维文件传输基线。
- 检测：对上传件做魔数/熵/字符串扫描；发现 `PK`、LZMA-alone、MZ/PE、反弹 shell 字符串、`ENCRYPTED_LICENSE` 等组合时升级告警。
- 防御：启用 IEC 62351 的认证与加密，限制 MMS 写文件权限；网络分段与 ACL，仅允许运维跳板访问 TCP 102；固件签名与完整性校验。
- 防御：设备侧关闭不必要的文件服务；对固件升级走带外签名验证与双人审批；保留固件基线哈希。
- 响应：隔离受感染设备，恢复可信固件，检查同网段其他继电器/PLC，轮换 MMS/运维凭据，封禁攻击源并保留 PCAP 证据。
