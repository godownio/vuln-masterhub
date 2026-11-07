---
id: ctf-forensics-plc-firmware-container-nwlp-crc-slot-adjudication
title: PLC 固件容器与 OT 流量取证：段熵筛真段、CRC-16 剔除伪造密钥帧、槽位状态三重裁决
type: scenario
domain: ctf
path: ctf/forensics
technique: plc-firmware-container-nwlp-crc-slot-adjudication
aliases:
- PLC 固件容器
- OT 流量分析
- NWLP 协议
- CRC-16/CCITT-FALSE 验帧
- 槽位状态裁决
- 工控取证
tags:
- forensics
- plc
- firmware
- ot
- pcap
- nwlp
- crc16
- xor-stream
- permutation
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:46:27+08:00'
  notes: 已对照原文核对；段熵判噪声、12 字节名字区、CRC-16/CCITT-FALSE 参数、pkt#1782 CRC 失败与三重裁决均一致
---

## 一句话结论

面对“固件镜像 + OT 抓包”的取证题，先用分段熵把大段噪声排除、只分析小配置段，再从 `.config` 槽位描述符拿到 tag/mode/perm，用 NWLP 帧的 CRC-16/CCITT-FALSE 校验剔除伪造密钥帧，最后按槽位 mode、`.log` 封存记录与 CRC 三重证据裁决出当前有效的那份封存数据。

## 原理

- **容器结构**：PLC 镜像外套自定义容器，头部含 `magic/version/hdr_size/image_size/nsec/name/model`，段表每项含 `name[16]/offset/size/type/crc32`。11 个有效段 CRC32 全部通过，说明镜像未损坏，只是内容被替换，不必往文件损坏方向查。
- **熵筛真段**：`.text` 段熵 7.998、256 种字节全出现，是可执行代码特征的反面——实为噪声填充；题面暗示的大量代码段、点表、校验表是障眼法。真信息在几百字节的小段：`.config`、`.secrets`、`.log`、`.keys`。先算熵再决定投入方向，可省掉反编译两百多 KB 噪声的死路。
- **槽位描述符**：`.config` 每项 32 字节，名字区实际只有 12 字节（按 16 字节对齐读会把 tag 解析成垃圾）：`name[12] + tag[4] + mode + pad + chunk + pad[2] + chunk_size + pad[2] + perm[8]`。
- **密钥只在流量里**：`.keys` 段只有 `KEYT` 加三个 tag 各 8 字节的种子，不是真密钥；真密钥必须从 udp/40001 的 NWLP `type=0x7f` 帧中取，负载为 4 字节 tag + 8 字节 key + 填充。
- **CRC 是协议层自证**：NWLP 头部含 `crc16`，算法为 CRC-16/CCITT-FALSE（poly 0x1021、init 0xFFFF、不反射、无末尾异或），对头部之后长度为 `len` 的部分计算。源地址可以伪造，但帧内 CRC 不能；伪造帧算不对 CRC 会当场露馅。
- **封存结构**：`seal` 为 `magic[4] + chunk(u16) + chunk_size(u16) + plain_len(u32) + ct[]`；解密先逐 8 字节块与密钥异或，再按 `.config` 的 `perm[8]` 重排，最后按 `plain_len` 截断。
- **多解陷阱**：三个槽位都能解出格式合法的 flag，需要 `.config` 的 mode（.secrets=1、.bak=2、.old=3）、`.log` 的“activated/legacy/revoked”记录以及密钥帧 CRC 三重交叉，才能确定当前有效槽位。

## 触发条件

- 拿到 PLC 固件镜像与对应 OT 抓包，镜像使用自定义容器/段表。
- 抓包中存在厂商自定义协议（本题 NWLP，udp/40001），密钥帧带 tag 与校验字段。
- 固件配置段包含槽位描述符与封存数据，且存在多个历史/作废槽位。
- 镜像段 CRC32 完整，但内容可能被替换；需要区分“文件损坏”与“内容篡改”。

## 利用步骤

1. 解包并解析容器：读 magic、段数、段表；逐个校验段 CRC32，确认镜像完整性。
2. 计算每段熵与字节分布：把高熵大段（如 `.text` 7.998）判为噪声，优先分析小段 `.config`、`.secrets`、`.log`、`.keys`。
3. 解析 `.config` 槽位描述符：按 32 字节步长、名字区 12 字节读取，记录每个槽位的 tag、mode、chunk、perm。
4. 解析 `.keys`：识别 `KEYT` 与各 tag 的 8 字节种子，确认它们不是最终密钥。
5. 过滤 udp/40001 的 NWLP 帧：按头部解析 `magic/version/type/seq/len/crc16`，只保留 `type=0x7f` 的密钥帧。
6. 逐帧计算 CRC-16/CCITT-FALSE，对照头部 `crc16`：CRC 失败但 tag 完全正确的帧是伪造诱饵；CRC 通过且 tag 匹配的才是真密钥。
7. 用真密钥解封对应槽位：按 8 字节块异或，再按 `perm` 重排，按 `plain_len` 截断；断言输出为可读 base64/文本。
8. 三重裁决：`.config` 的 mode 表示槽位状态，`.log` 记录 activated/legacy/revoked，CRC 验证密钥来源；三者一致才取该槽位内容。

## PoC

NWLP CRC-16/CCITT-FALSE：

```python
def crc16_ccitt_false(buf):
    crc = 0xFFFF
    for byte in buf:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc
```

封存解密：

```python
blocks = [bytes(a ^ b for a, b in zip(ct[i*8:(i+1)*8], key)) for i in range(n)]
plain  = b"".join(blocks[i] for i in perm)[:plain_len]
```

原文实测：pkt#1782 携带完全正确的 `NWD1` tag，但 CRC 为 0x2b14、应为 0xd4eb，用其密钥解 `.secrets` 得到纯乱码；pkt#1783/1788/1794 的 CRC 均通过，分别对应 NWD1/NWD7/NWD3。三个槽位解出的 flag 都格式合法，最终按 mode=1 的 `.secrets` 与 `.log` 的 activated 记录裁决。

## 变体与关联

- **协议变体**：CRC-16/XMODEM（init 0x0000）等参数不同的变体容易误判；应先用已知合法帧回算校验参数，再判断帧是否伪造。
- **容器变体**：段表名字区宽度、对齐、`hdr_size` 与实际偏移不一致时，需要按原始字节逐字段核对，不能按直觉对齐。
- **加密变体**：XOR + 置换的顺序容易写反；应尝试“先异或后置换”“先置换后异或”等方向，用可读结构（base64、magic）做对账。
- **关联**：与固件逆向、OT 协议分析、隐写/封装取证同类；核心方法论是“先用熵缩小范围，再用协议自校验排除伪造，最后用业务状态裁决”。

## 检测与防御

- 固件侧：对镜像做签名而非仅 CRC32；段表与内容哈希绑定，防止内容替换后仍通过 CRC。
- 协议侧：密钥帧使用消息认证码（HMAC）而非 CRC，CRC 只能检错不能防伪造；对源地址与密钥帧做双向认证。
- 取证侧：先算熵再决定分析对象；对每个候选密钥帧做帧内校验；对多份可解内容建立“状态字段 + 日志 + 校验”三重裁决，不凭源地址或时间顺序猜测。
- 检测特征：高熵“代码段”、小配置段中的槽位表、udp 固定端口上的自定义 magic、带 tag 的密钥帧、`.log` 中的 activated/legacy/revoked 记录。
