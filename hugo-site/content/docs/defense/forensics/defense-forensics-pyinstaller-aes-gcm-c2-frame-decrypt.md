---
id: defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt
title: PyInstaller 木马 C2 流量解密：4 字节长度 + 12 字节 nonce + 密文 + 16 字节 GCM tag
type: scenario
domain: defense
path: defense/forensics
technique: pyinstaller-elf-aes-gcm-c2-frame-decrypt
tags:
- forensics
- traffic-analysis
- malware
- pyinstaller
- aes-gcm
- c2
- reverse
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:43:19+08:00'
  notes: 已对照原文图12-18核对：/var/tmp/out为PyInstaller(2.1+/Python3.9)样本、implant.pyc可见AESGCM、set_aes_key(base64)校验16/24/32字节、encrypt_data用os.urandom(12)返回nonce+ciphertext、decrypt_data取data[:12]/data[12:]，key为命令行--aes-key IhbJfHI98nuSvs5JweD5qsNvSQ/HHcE/SNLyEBU9Phs=(32字节)，TCP 38162→7788帧为4字节小端长度(如1f000000=31=12+3+16)+12字节nonce+密文+16字节tag，解密得pwd/echo等，末段Base58+Base64得flag，均与图文一致。未验证点：未用原文tcp_stream.raw复跑（截图hex手工切帧易错），仅理论上核对；CTF题无组件版本，未设置versions；frontmatter无sources/source_url。
url: /docs/defense/forensics/defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt/
draft: false
kb_aliases:
- PyInstaller 木马流量
- AES-GCM C2 解密
- 4字节长度 12字节nonce 16字节tag
- 自定义 C2 协议逆向
- pyinstxtractor 木马
- implant.pyc
---

## 一句话结论

PyInstaller 打包的 ELF 木马把 Python 逻辑与 AES-GCM 密钥一起带在样本里；用 pyinstxtractor 解包、反编译 `implant.pyc` 拿到通信实现后，按 `[4 字节长度][12 字节 nonce][ciphertext][16 字节 GCM tag]` 切分回连 TCP 流，用样本命令行传入的 Base64 key 做 AES-GCM 解密，即可还原攻击者命令、回显与最终 flag。

## 原理

- **样本识别**：上传到 `/var/tmp/out` 的可执行文件具有 PyInstaller 特征（运行输出/文件结构含 `PYZ`、`pyiboot01_bootstrap`、`_MEI` 等）；`pyinstxtractor` 识别 PyInstaller 2.1+、Python 3.9，导出 `implant.pyc`、`PYZ.pyz_extracted` 等。
- **反编译定位协议**：`implant.pyc` 反编译后可见 `from cryptography.hazmat.primitives.ciphers.aead import AESGCM`、`set_aes_key(key_b64)` 用 `base64.b64decode` 解 key 并校验长度 16/24/32，`encrypt_data` 生成 `nonce = os.urandom(12)` 并返回 `nonce + ciphertext`，`decrypt_data` 取 `nonce = data[:12]`、`ciphertext_with_tag = data[12:]`。AES-GCM 的密文尾部自带 16 字节认证 tag。
- **key 的来源**：木马启动命令为 `./out --aes-key <Base64>`，密钥在进程命令行/样本参数中；Base64 解码得到 32 字节，对应 AES-256-GCM。拿到样本或命令行即可离线解密。
- **帧格式**：回连 TCP 会话中每个消息前有 4 字节长度，随后是加密数据包；样本中长度值为小端（如 `1f000000` = 31 = 12 字节 nonce + 3 字节密文 + 16 字节 tag），因此单帧为 `[4 字节长度][12 字节 nonce][ciphertext][16 字节 GCM tag]`。按该结构切分，nonce 作 IV、密文+tag 作 GCM 输入即可解密。
- **为什么可行**：AES-GCM 同时提供机密性与完整性，但 nonce 与 tag 均随包传输，密钥又在样本/命令行中；对称加密无法在密钥泄露后保护历史流量。协议长度字段使 TCP 流可稳定分帧，不依赖应用层分隔符。
- **结果**：解密得到 `pwd`、`/var/tmp`、`ls`、`out`、`echo Congratulations`、`echo <长串>`、`echo bye` 等命令与回显；长串再经 Base58+Base64 解码得到 `dart{...}` 形式的 flag。

## 触发条件

- 捕获到恶意样本回连的 pcap/TCP 流（如 `10.1.33.69:38162 -> 10.1.243.155:7788`）。
- 能取得木马样本或其启动命令行中的 `--aes-key` Base64 密钥。
- 样本使用 PyInstaller 打包且可解包（版本兼容；必要时用同版本 Python 反编译）。
- 流量为明文 TCP（非 TLS），且帧完整、未被截断。

## 利用步骤

1. 从流量或主机侧取得上传的可执行文件，确认 PyInstaller 特征；用 `pyinstxtractor` 解包。
2. 用对应 Python 版本反编译 `implant.pyc`（如 Decompile++/pycdc/decompyle3），定位 `AESGCM`、`nonce`、`decrypt_data` 与 key 初始化逻辑。
3. 从启动命令 `./out --aes-key <Base64>` 或样本配置提取 key，Base64 解码确认长度为 16/24/32 字节。
4. 在 Wireshark 中跟随 TCP 流（Follow TCP Stream，Raw），按 4 字节长度前缀切帧；跳过长度字段，取 12 字节 nonce、剩余部分为 ciphertext+tag（最后 16 字节为 tag）。
5. 用 AES-GCM 解密每帧，按时间顺序还原命令与回显；对回显中的长串继续按样本/题目提示做 Base58、Base64 解码。
6. 交叉验证：用样本代码中的 `decrypt_data` 逻辑写脚本批量解密，避免手工漏帧。

## PoC

```python
import base64, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = base64.b64decode("IhbJfHI98nuSvs5JweD5qsNvSQ/HHcE/SNLyEBU9Phs=")
assert len(key) == 32
aead = AESGCM(key)

stream = open("tcp_stream.raw", "rb").read()   # Wireshark Follow TCP Stream -> Raw
off = 0
while off + 4 <= len(stream):
    n = struct.unpack("<I", stream[off:off + 4])[0]   # 样本中为小端长度
    blob = stream[off + 4:off + 4 + n]
    if len(blob) < 12 + 16:
        break
    nonce, ct_tag = blob[:12], blob[12:]              # GCM tag 在密文尾部
    try:
        print(aead.decrypt(nonce, ct_tag, None).decode("utf-8", "replace"))
    except Exception as e:
        print("frame failed:", e)
    off += 4 + n
```

说明：PoC 按文中 `implant.pyc` 的 `decrypt_data` 与 Wireshark 帧结构整理，未在本机复跑。

## 变体与关联

- 变体：key 可能来自命令行、环境变量、硬编码或与 C2 协商；key 长度 16/24/32 对应 AES-128/192/256-GCM。
- 变体：长度字段可能为大端或包含自身；nonce 长度可能非 12；tag 可能单独传输而非附在密文尾；需以反编译代码为准。
- 变体：PyInstaller 版本/ Python 版本不同，解包与反编译工具不同；可参考库内 PyInstaller 解包卡。
- 变体：同族木马可能改用 ChaCha20-Poly1305、AES-CBC+HMAC 等；识别 AEAD/加密库调用是关键。
- 关联：[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（PyInstaller 解包细节）、[[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]（本链上一阶段冰蝎流量）、[[defense-forensics-c2-server-sqlite-conf-artifacts]]（C2 服务端取证）、[[defense-forensics-godzilla-java-webshell-traffic-decode]]（其他加密 WebShell 流量）。
- 边界：样本被强混淆/加密且无法反编译、key 未泄露、流量走 TLS、帧被截断或经过代理改写时，无法直接解密。

## 检测与防御

- 检测：`/var/tmp`、`/tmp` 等目录出现 PyInstaller 特征 ELF；进程命令行含 `--aes-key` 或 Base64 长串；回连固定高端口、长连接、每帧前有 4 字节长度且内容高熵。
- 检测：PyInstaller 解包后出现 `implant.py`、`AESGCM`、`os.urandom(12)`、`nonce`/`tag` 等特征；主机上出现 `pyinstaller` 解包工具痕迹。
- 防御：禁止在临时目录执行上传文件（noexec）、应用白名单、EDR 监控 ELF 落盘与执行；出站限制到已知 C2 端口/域名；对 PyInstaller 单文件样本做沙箱与内存取证。
- 响应：隔离主机、保存样本与 pcap；用提取的 key 解密全部 C2 流量还原攻击者操作；轮换主机凭据并排查横向。
