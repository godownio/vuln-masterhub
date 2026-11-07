---
id: defense-forensics-vshell-config-aes-cbc-traffic-aes-gcm-decrypt
title: VShell C2 配置提取与流量解密：0x5000 AES-CBC 配置块、md5(salt) 派生的 AES-GCM 帧
type: scenario
domain: defense
path: defense/forensics
technique: vshell-config-aes-cbc-traffic-aes-gcm-decrypt
aliases:
- VShell 流量解密
- V(N)shell
- VShell config 解密
- 0x5000 配置块
- AES-CBC key=IV
- md5 salt AES-GCM
- l64 XOR 0x99
- gift stage1
tags:
- forensics
- traffic-analysis
- c2
- vshell
- go
- aes-gcm
- aes-cbc
- config-extraction
- reverse
- pcap
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:49:51+08:00'
  notes: 已对照原文与全部 14 张图核对：shell.php→open→gift 链、stage1 l64/XOR 0x99/memfd+fexecve、0x5000 配置块、AES-CBC key=IV、gdb 断点 encoding_json_Unmarshal 取 JSON、vkey 校验、4+12+密文+16 tag 帧格式均吻合。卡片已把原文误称的末尾 16 字节纠正为 GCM tag，并明确 key 为 md5(salt) 的 32 字节 ASCII 十六进制串；PoC 未复跑
---

## 一句话结论

VShell（V(N)shell）把配置以约 `0x5000`（20480）字节的加密块嵌在 Go 主木马中，算法是 AES-CBC 且 key 与 IV 都取该块前 16 字节，明文为 JSON（含 `server`、`vkey`、`salt`）；通信流量用 AES-GCM，key 为 `md5(salt)` 的 32 字节十六进制字符串，帧格式为 `[4 字节小端长度][12 字节 nonce][密文][16 字节 GCM tag]`。拿到样本/pcap 后即可离线提取配置并解密全部 C2 命令。

## 原理

- **多级加载**：WebShell 执行 `bash open`，`open` 脚本运行 `gift`（stage1 加载器）；`gift` 连接硬编码/配置中的 C2（示例 `192.168.56.1:11451`），先发送 `l64   `、监听端口与地址字符串，随后接收 stage2，逐字节 XOR `0x99`，写入 `memfd_create("a", 0)` 得到的匿名内存文件，最后 `fexecve` 执行，`argv[0]` 伪装为 `[kworker/0:2]`。因此 pcap 中 stage1 与 stage2 的传输是 XOR 0x99 的原始 TCP，不是 TLS。
- **配置块定位**：stage2 是 Go 二进制；VShell 各模式的加密配置最终都占 `0x5000`（20480）字节。逆向时在 IDA 中搜索 `5000h` 大小的数据块/引用，或在二进制中找 20480 字节的高熵块；示例中该块位于 `0x8C6339`。
- **配置解密**：加密块前 16 字节同时作为 AES-CBC 的 key 和 IV，其后为密文；解密后按 `0x00` 去掉零填充（原文实测是零填充而非 PKCS#7，遇到 PKCS#7 实现时需两种都试），得到 JSON。典型字段：`server`（C2 地址）、`type`（tcp/ws 等）、`vkey`（通信校验密钥）、`proxy`、`salt`（流量密钥派生盐）、`l`/`e`/`d`/`h` 等。
- **动态提取技巧**：在 IDA 中搜索 JSON 字符串/`encoding_json_Unmarshal` 的交叉引用，选中最早调用 `encoding_json_Unmarshal` 的位置（示例 `0x598FB8`），在 gdb/pwndbg 下断点；断下时 `RAX`/`RSI` 指向已解密的 JSON 明文，可直接 `x/s` 读取，省去手写 AES-CBC 解密。
- **流量密钥**：VShell 的 C2 流量用 AES-GCM。原文脚本中 `key_hex = md5(salt).hexdigest(); key = key_hex.encode('ascii')`，即 AES key 是 **MD5 的 32 字节 ASCII 十六进制字符串**（AES-256-GCM），不是 16 字节原始摘要；这一点容易看错原文“密钥为 salt 的 md5 值”的表述。
- **帧格式**：每帧开头 4 字节为小端长度（原文示例 `d7000000` = 0xD7 = 215），长度覆盖其后的 `nonce + 密文 + tag`；随后 12 字节 nonce、变长密文、最后 16 字节 GCM 认证 tag。原文把最后 16 字节称为“垃圾数据”，实际它是 GCM tag，必须随密文一起传给 AES-GCM 解密/校验，不能丢弃。
- **vkey 校验**：主木马建立通信时会先检查 `vkey`，不匹配直接退出；因此解密流量前必须从配置中取得正确的 `vkey`，否则无法复现协议。
- **为什么能离线解密**：对称密钥（salt 派生）与 vkey 都存在样本配置中，pcap 只是密文；一旦提取配置，历史流量可全部还原，包括攻击者执行的命令、回显与后续凭据。

## 触发条件

- 捕获到 VShell 客户端回连的 pcap/TCP 流，或取得 stage1/stage2 样本。
- 能逆向 stage2（Go 二进制）并定位 `0x5000` 配置块，或能在 gdb 中断到 `encoding_json_Unmarshal` 取明文。
- 配置中的 `salt`/`vkey` 未被额外保护（VShell 默认嵌入样本）。
- 流量为原始 TCP（非 TLS），帧完整；stage1 阶段需按 XOR 0x99 还原 stage2。

## 利用步骤

1. 在 pcap 中过滤 `shell.php`、`open`、`gift` 相关请求，导出 `open` 脚本与 `gift` 文件；`open` 通常是执行 `gift` 的 sh 脚本。
2. 逆向 `gift`：确认 C2 地址、`l64` 握手、XOR `0x99`、`memfd_create`/`fexecve`；从后续 TCP 流中提取 XOR 后的 stage2。
3. 在 stage2 中定位 `0x5000` 加密配置块（IDA 搜索 `5000h` 引用或 20480 字节高熵块），导出该块。
4. 用前 16 字节作 key 和 IV 做 AES-CBC 解密，去零填充，解析 JSON；或按方法二在 `encoding_json_Unmarshal` 调用处下断点直接读明文。
5. 计算 `key = md5(salt).hexdigest().encode('ascii')`，用 AES-GCM 解密流量：按 4 字节小端长度切帧，取 12 字节 nonce，剩余部分（含末尾 16 字节 tag）作为 `ciphertext_with_tag`。
6. 按时间顺序还原命令/回显；从命令中提取密码、路径、外带数据等，继续后续分析（如 zip2john 哈希恢复）。

## PoC

配置块 AES-CBC 解密（示意，未在本机执行）：

```python
from Crypto.Cipher import AES
import json

blob = open("config_block.bin", "rb").read()   # 0x5000 字节块
key_iv = blob[:16]
pt = AES.new(key_iv, AES.MODE_CBC, key_iv).decrypt(blob[16:])
pt = pt.rstrip(b"\x00")                         # 原文实测为零填充；PKCS#7 需另处理
print(json.loads(pt.decode("utf-8")))
```

流量 AES-GCM 解密（示意）：

```python
import hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

salt = b"<从配置提取的 salt>"
key = hashlib.md5(salt).hexdigest().encode("ascii")   # 32 字节 ASCII，AES-256-GCM
aead = AESGCM(key)

stream = open("tcp_stream.raw", "rb").read()
off = 0
while off + 4 <= len(stream):
    n = struct.unpack("<I", stream[off:off + 4])[0]   # 4 字节小端长度
    blob = stream[off + 4:off + 4 + n]
    if len(blob) < 12 + 16:
        break
    nonce, ct_tag = blob[:12], blob[12:]              # 末尾 16 字节是 GCM tag
    try:
        print(aead.decrypt(nonce, ct_tag, None).decode("utf-8", "replace"))
    except Exception as e:
        print("frame failed:", e)
    off += 4 + n
```

原文的解密脚本还把明文中的 ANSI 转义序列清掉后打印；PoC 未在本机复跑，`salt`/路径/帧长度需按样本调整。

## 变体与关联

- 变体：VShell 可能使用 ws/tcp 等不同 `type`；握手与帧头可能随版本变化，需以 stage2 反编译为准。
- 变体：配置块可能是 PKCS#7 填充或非 0x5000 大小；动态断点法不依赖填充假设，优先使用。
- 变体：流量密钥可能是 `md5(salt)` 原始 16 字节（AES-128）而非十六进制字符串；按反编译代码确认，不要只凭文章描述。
- 关联：[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（同样的 4+12+密文+16 tag 帧格式，但 key 来自 PyInstaller 样本命令行）、[[defense-forensics-c2-server-sqlite-conf-artifacts]]（VShell 服务端目录/SQLite 取证）、[[pentest-c2-linux-memfd-create-fileless-elf-execution]]（stage1 的 memfd/fexecve 无文件执行）、[[ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt]]（本链后续从流量密码恢复压缩包内容）。
- 边界：配置被二次加密/剥离、salt/vkey 不在样本、流量走 TLS、stage2 被截断、加密实现改动（key 派生/填充/帧头）时需重新逆向；不要直接运行未知 C2 样本，分析应在隔离环境进行。

## 检测与防御

- 检测：Go 二进制中出现 20480 字节高熵块、`encoding_json_Unmarshal` 附近出现 `vkey`/`salt`/`server` 字段；进程 `argv[0]` 伪装为 `[kworker/*]`、使用 `memfd_create`+`fexecve`；回连固定端口、原始 TCP 帧以 4 字节小端长度开头且内容高熵。
- 检测：pcap 中 WebShell 请求后出现 `bash open`、`gift` 下载与 XOR 0x99 的二进制流；同一主机随后向配置中的 `server` 地址发起长连接。
- 防御：禁止在 Web 目录执行上传文件、限制 `shell.php` 等脚本；EDR 监控 `memfd_create`/`fexecve` 与进程名伪装；出站限制未知 C2 地址/端口；对 Go 样本做配置块扫描与沙箱分析。
- 响应：隔离主机、保存样本与 pcap；提取配置后解密全部流量还原攻击者操作；轮换 vkey/salt、封禁 C2、排查横向与数据外带。
