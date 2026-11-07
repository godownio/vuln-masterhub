---
id: ctf-forensics-icmp-double-layer-pbkdf2-shuffle-exfil
title: ICMP 隐蔽外带双层加密：EX1L 元数据 + PBKDF2 派生 + ChaCha20/AES-GCM + ScrambleSeed 乱序
type: scenario
domain: ctf
path: ctf/forensics
technique: icmp-double-layer-pbkdf2-shuffle-exfil
tags:
- ctf
- forensics
- icmp
- covert-channel
- exfiltration
- chacha20
- aes-gcm
- pbkdf2
- pcap
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:14:29+08:00'
  notes: 复核修正：原文 exfiltrator 伪代码的元数据拼接顺序（EX1L+timestamp+scramble_seed+crypto_seed+md5）与取证脚本实际读取偏移（metadata[4:20]=crypto_seed、[20:24]=scramble_seed）不一致，卡片已改为以取证脚本/pcap 为准并注明该差异。其余（PBKDF2 双层派生、ChaCha20/AES-GCM、ScrambleSeed shuffle、ICMP ID/Seq 公式）与 91111 原文及图 15-17 一致。PoC 未在本机复跑。
url: /docs/ctf/forensics/ctf-forensics-icmp-double-layer-pbkdf2-shuffle-exfil/
draft: false
kb_aliases:
- ICMP 隐蔽隧道
- EX1L 元数据
- ChaCha20-Poly1305 + AES-GCM 双层
- ScrambleSeed 乱序
- ICMP 数据外带
- Windows Ping 伪装
---

## 一句话结论

样本把文件切成 224 字节块，先加 4 字节长度头并用 ChaCha20-Poly1305 加密，再用 AES-GCM 加密第二层，把结果塞进 ICMP Echo Request 的 16 字节伪 Ping 填充之后；发送顺序用 `ScrambleSeed` 打乱，ICMP ID/序列号用线性同余公式伪随机生成，元数据块以 `EX1L` 开头携带种子。取证时按公式还原块索引、用 `random.Random(scramble_seed)` 重放 shuffle、PBKDF2 派生两层密钥，依次解 AES-GCM 与 ChaCha20，拼接即得外带文件。

## 原理

- **隐蔽信道**：工具用 `scapy` 构造 `IP(dst)/ICMP(type=8, id, seq)/(padding + chunk_data)`，每个包前 16 字节固定 `abcdefghijklmnop`，模拟 Windows ping 的默认 payload；ICMP 不经过 TCP/UDP 端口，常规端口/协议审计容易忽略。
- **伪随机 ID/Seq**：`val = (index * 2654435769 + 305419896) & 0xFFFFFFFF`，`id = val >> 16`，`seq = val & 0xFFFF`。索引从 1 开始；取证时对每个 index 重算 `(id,seq)` 即可定位属于该索引的包，而不依赖包到达顺序。
- **元数据块**：以 `EX1L` 开头携带种子；原文取证脚本按 `metadata[4:20]` 取 16 字节 `crypto_seed`、`metadata[20:24]` 取大端 `scramble_seed`。注意文中 exfiltrator 伪代码拼接 `EX1L + >I timestamp + >I scramble_seed + 16 字节 crypto_seed + 16 字节 md5`，其顺序与取证脚本偏移不一致（伪代码的发送元数据部分本身被注释/简化）；实际布局以 pcap 为准。`crypto_seed` 每次运行随机生成，是派生密钥的 master seed；`scramble_seed` 基于时间，用于打乱发送顺序。
- **密钥派生**：
  - `key1 = PBKDF2(crypto_seed + b'Bloodharbor!2024', b'Silent_Update!!!' + b'\x01', dkLen=32, count=10000)`
  - `key2 = PBKDF2(crypto_seed + b'Bloodharbor!2024' + key1, b'Silent_Update!!!' + b'\x02', dkLen=32, count=10000)`
  两层使用不同 salt 后缀，且第二层混入 key1，增加离线分析成本。
- **双层 AEAD**：
  - Layer 1（ChaCha20-Poly1305）：`payload = >I len(data) + data`，输出 `nonce(12) + ciphertext + tag(16)`。
  - Layer 2（AES-GCM）：对 Layer 1 完整输出加密，输出 `nonce(16) + ciphertext + tag(16)`（PyCryptodome 默认 16 字节 nonce）。
- **乱序**：发送前 `rng = random.Random(scramble_seed); indices = list(range(total)); rng.shuffle(indices)`；第 `new_pos` 个发送的包携带原始块 `indices[new_pos]`，但 ICMP 索引按 `new_pos+1` 计算。取证时用同一 seed 重放 shuffle 即可把“发送顺序”映射回“原始块顺序”。
- **为什么能还原**：只要抓到元数据块和所有数据块，种子、算法、盐都是硬编码或随元数据提供；AEAD 的 tag 还能验证解出的明文/裁剪长度是否正确。

## 触发条件

- 流量包中存在大量 ICMP Echo Request（type 8），payload 前 16 字节固定、后续数据长度接近 224 字节或更短。
- 某个 payload 以 `EX1L` 开头，包含 timestamp、scramble_seed、crypto_seed、md5。
- 攻击样本/工具可获取或可推断硬编码盐、PBKDF2 参数与加密算法。
- 抓到全部数据包（乱序/丢包会导致块缺失，AEAD 或长度头校验会失败）。

## 利用步骤

1. 用 Wireshark/tshark 过滤 `icmp.type == 8`，观察 payload 是否带固定 16 字节前缀和 `EX1L` 元数据。
2. 提取元数据：`crypto_seed = metadata[4:20]`、`scramble_seed = metadata[20:24]`（大端）；记录文件 md5。
3. 对 `idx=1,2,...` 重算 `(id,seq)`，从包集合中取出对应密文；去掉 16 字节伪 Ping 填充。
4. 用 `random.Random(scramble_seed)` 重放 `shuffle`，把发送顺序还原为原始块顺序，拼接成完整密文流。
5. 派生 key1/key2；先解 AES-GCM（nonce 16 + tag 16），必要时尝试裁掉尾部 0–224 字节以适配最后一块长度；得到 Layer 1 密文。
6. 再解 ChaCha20-Poly1305（nonce 12 + tag 16），读取 4 字节长度头，截取原始数据；校验 MD5。
7. 保存为 zip/文件，继续解析（本例解压得到 100 张人员信息图片，OCR 定位目标手机号对应的地址）。
8. 若解密失败，检查 nonce/tag 长度、大小端、索引起点、shuffle 方向与裁剪长度。

## PoC

```python
import struct, random
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from scapy.all import rdpcap, ICMP

class CryptoRecoverer:
    def __init__(self, master_seed):
        self.master_seed = master_seed
        self._k1 = b'Bloodharbor!2024'
        self._k2 = b'Silent_Update!!!'
        base = master_seed + self._k1
        self.key_layer1 = PBKDF2(base, self._k2 + b'\x01', dkLen=32, count=10000)
        self.key_layer2 = PBKDF2(base + self.key_layer1, self._k2 + b'\x02', dkLen=32, count=10000)

def icmp_fields(idx):
    val = (idx * 2654435769 + 305419896) & 0xFFFFFFFF
    return (val >> 16) & 0xFFFF, val & 0xFFFF

def solve(pcap):
    raw = {}
    for pkt in rdpcap(pcap):
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            data = bytes(pkt[ICMP].payload)
            if len(data) > 16:
                raw[(pkt[ICMP].id, pkt[ICMP].seq)] = data[16:]

    meta = next(v for v in raw.values() if v.startswith(b'EX1L'))
    crypto_seed = meta[4:20]
    scramble_seed = int.from_bytes(meta[20:24], 'big')

    chunks, idx = {}, 1
    while True:
        key = icmp_fields(idx)
        if key not in raw:
            break
        chunks[idx] = raw[key]
        idx += 1

    rng = random.Random(scramble_seed)
    order = list(range(len(chunks)))
    rng.shuffle(order)
    reordered = [None] * len(chunks)
    for new_pos, orig in enumerate(order):
        reordered[orig] = chunks[new_pos + 1]
    blob = b''.join(reordered)

    rec = CryptoRecoverer(crypto_seed)
    for trim in range(225):
        ct = blob[32:] if trim == 0 else blob[32:-trim]
        try:
            layer1 = AES.new(rec.key_layer2, AES.MODE_GCM, nonce=blob[:16]).decrypt_and_verify(ct, blob[16:32])
            break
        except ValueError:
            continue

    for trim in range(225):
        ct = layer1[28:] if trim == 0 else layer1[28:-trim]
        try:
            plain = ChaCha20_Poly1305.new(key=rec.key_layer1, nonce=layer1[:12]).decrypt_and_verify(ct, layer1[12:28])
            size = struct.unpack('>I', plain[:4])[0]
            open('recovered.bin', 'wb').write(plain[4:4 + size])
            print('ok', size)
            break
        except ValueError:
            continue

solve('challenge.pcap')
```

说明：以上为原文脚本的等价精简版；原文后续解压出 100 张图片并用 OCR 定位目标手机号。PoC 未在本机复跑。

## 变体与关联

- **信道变体**：ICMP payload、ICMP TTL/ID/Seq 位、DNS TXT、HTTP header、WebSocket ping、CAN 帧尾字节；共同点是“把数据藏在协议的非业务字段/填充中”。
- **加密变体**：单层 XOR/RC4、AES-CBC + HMAC、双层 AEAD、每条消息独立 nonce；密钥可能来自随机种子 + 硬编码盐、时间戳、DH 交换。
- **乱序变体**：按 seed shuffle、按哈希排序、按包序号异或、分片编号藏在 ID/Seq/TTL；取证时需找到排序种子或约束。
- **关联卡片**：[[ctf-forensics-icmp-echo-payload-concatenation]]（ICMP payload 直接拼接）、[[ctf-forensics-icmp-ttl-bit-stego]]（TTL 位隐写）、[[ctf-forensics-can-repeated-frame-trailing-byte-covert-channel]]（CAN 帧尾字节信道）、[[pentest-c2-linux-mmap-rwx-rolling-xor-shellcode-loader]]（隐蔽载荷加载）。
- **边界**：丢包/乱序无法恢复完整文件；若种子/盐被加密或不了解算法，需逆向样本；AEAD 会拒绝错误裁剪，但大量尝试可能造成误判。

## 检测与防御

- **检测**：统计 ICMP Echo Request 的频率/大小/目的地址；检查 payload 固定前缀 + 高熵数据；对 `EX1L`、`Bloodharbor` 等特征字符串告警；监控非常规 ICMP 出站（尤其到公网）与大数据量 ping。
- **防御**：在网络边界限制 ICMP 出站/入站类型与大小；对 ICMP payload 做熵/长度异常检测；终端侧监控 scapy/raw socket 行为与异常子进程。
- **取证**：保留完整 pcap 与哈希；记录元数据块、种子、算法、索引公式；对解出的文件做 MD5 校验并继续分析（图片 OCR、文档元数据等）。
- **演练**：红队可用类似信道验证 DLP/NDR 对 ICMP 隐蔽隧道的检测能力；蓝队应把“ping 流量”纳入异常基线，而不是默认放行。
