---
id: defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt
title: AdaptixC2 Gopher TCP 配置提取与流量解密：Listener Key、INIT_PACK 会话密钥与多层 msgpack 帧
type: scenario
domain: defense
path: defense/forensics
technique: adaptixc2-gopher-tcp-listener-session-key-decrypt
aliases:
- AdaptixC2 流量解密
- GopherTCP 解密
- listener_gophertcp
- AdaptixC2 Gopher Agent 配置提取
- INIT_PACK 会话密钥
- msgpack AES-GCM C2
tags:
- forensics
- traffic-analysis
- c2
- adaptixc2
- gopher
- tcp
- go
- aes-gcm
- msgpack
- config-extraction
- pcap
- session-key
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:49:02+08:00'
  notes: 已对照原文与 img01-32 核对：配置块 16B Listener Key + 12B nonce + AES-GCM(msgpack Profile)、3969 字节块、INIT_PACK 会话密钥、4 字节大端长度帧、三层 msgpack 与三帧解密结果均与原文一致；因原文仅把 Adaptix Framework v0.8/go1.24.4 作为测试环境，已按 brief 清除 affected_versions。未验证点：PoC 未在本机复跑，未重新提取样本配置。
---

## 一句话结论

AdaptixC2 的 Gopher TCP Agent 把配置以 `[16 字节 Listener Key][12 字节 nonce][AES-GCM(msgpack Profile)]` 嵌在二进制中；上线包用 Listener Key 加密并携带新的 16 字节 Session Key，之后的每帧为 `[4 字节大端长度][12 字节 nonce][AES-GCM(msgpack Message)]`，用 Session Key 加密。拿到样本或 pcap 后，按这两级密钥与 msgpack 嵌套即可还原全部 C2 命令与回显。

## 原理

- **Listener Key 与配置块**：创建 GopherTCP 监听器时服务端生成 16 字节随机 `EncryptKey`（Listener Key）。生成 Agent 时把 Profile（CallBack 地址、TCP banner 长度、重连超时/次数、`use_ssl`、`ssl_cert`/`ssl_key`/`ca_cert`）先 `msgpack.Marshal`，再用 Listener Key 做 AES-GCM 加密（输出 `nonce || ciphertext+tag`），最后把 Listener Key 拼在最前面：`[16B Listener Key][12B nonce][密文+16B tag]`。
- **Agent 启动**：Agent 从二进制中取出这段配置，前 16 字节作为 Listener Key 解密其余部分，得到 C2 地址、TLS 证书等；随后收集 Process/PID/User/Host/Ipaddr/Elevated/Os/OSVersion 等信息，并生成新的 16 字节 Session Key，一起打包成 `SessionInfo`。
- **INIT_PACK**：Agent 把上线信息封装为多层 msgpack 的 INIT_PACK，最外层使用 Listener Key 加密；服务端 `handleConnection` 用 Listener Key 解密并从中解析出 `SessionInfo.encrypt_key`，后续通信改用 Session Key。因此 pcap 中第一帧用 Listener Key，之后的所有帧用 Session Key。
- **帧格式**：`sendMsg` 先写 4 字节大端长度 `len(data)`，再写 `data`；`data` 是 AES-GCM 输出（12 字节 nonce + 密文 + 16 字节 tag）。接收端 `recvMsg` 先读 4 字节长度，再读满该长度。
- **三层 msgpack**：
  - 上线包：顶层 Message（含 `id`/`type`/`data`）→ `data` 是一层 msgpack → 再解一层得到 `SessionInfo`（字段名 `process`、`pid`、`user`、`host`、`ipaddr`、`elevated`、`acp`、`oem`、`os`、`os_version`、`encrypt_key`）。
  - 任务下发/回传：顶层 `Message{type:1, object:[...]}`，`object` 中每项是 msgpack 序列化的 `Command{id, code, data}`；`data` 再解一层 msgpack 得到命令参数（如 `program`/`args`）或执行结果（如 `output`）。
- **TLS 层**：GopherTCP 可启用 mTLS。Agent 的 `tls.Config` 设置了 `InsecureSkipVerify: true`，即不校验服务端证书（`RootCAs` 实际失效），但服务端仍要求客户端证书；这为流量拦截提供了条件，具体见关联卡。
- 根因是“配置与流量都只用对称密钥 + 可预测的二进制帧结构保护”，密钥又嵌在 Agent 内部；只要取得样本（或从内存/流量中取得密钥），历史流量即可离线解密。

## 触发条件

- 捕获到 GopherTCP Agent 回连的 pcap/TCP 流，或取得 agent 二进制/内存镜像；
- 配置块未被额外剥离或二次加密；能定位并提取 `[Listener Key][nonce][密文]`；
- 若是 mTLS 流量，需先完成 TLS 解密（客户端私钥 + 代理/SSLKEYLOGFILE，见关联卡）才能看到帧；
- 帧完整、按顺序；长度字段与实际 TCP 流一致。

## 利用步骤

1. 确认监听器类型为 GopherTCP、Agent 为 Gopher（banner 常为 `AdaptixC2 server`，端口如 6666）。
2. 从 agent 二进制定位配置块：用 Ghidra + GolangAnalyzerExtension 打开，进入 `main.main`，找到 `github.com/vmihailenco/msgpack/v5.Unmarshal` 调用；回溯其输入全局变量（如 `encProfile` 的指针）到数据地址，读取前面的长度值（原文为 `0xF81` = 3969 字节），按精确长度复制该数据块。
3. 配置解密：取前 16 字节为 Listener Key，接着 12 字节 nonce，其余为 `ciphertext+tag`；AES-GCM 解密后 msgpack 解析，得到 `addresses`、`banner_size`、`use_ssl`、`ssl_cert`、`ssl_key`、`ca_cert` 等。
4. 解密第一帧：按 4 字节大端长度切帧，用 Listener Key 解密，解析出 INIT_PACK/SessionInfo，取其中的 `encrypt_key` 作为 Session Key。
5. 解密后续帧：用 Session Key 解密，解析 Message；遍历 `object`，对每项做 msgpack 解析得到 Command；再解析 `data` 得到参数或回显。
6. 与服务端日志/命令输出交叉验证（如 `shell whoami` 的输出与解密结果一致）。

## PoC

```python
import struct
import msgpack
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def gcm_open(blob, key):
    nonce, ct_tag = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct_tag, None)

# 1) 配置块：[16B Listener Key][12B nonce][密文+tag]
raw = open("encProfile.bin", "rb").read()
listener_key = raw[:16]
profile = msgpack.unpackb(gcm_open(raw[16:], listener_key), raw=False)
print(profile["addresses"], profile.get("use_ssl"))

# 2) 单帧：[4B 大端长度][12B nonce][密文+tag]
def decrypt_frame(frame, key):
    n = struct.unpack(">I", frame[:4])[0]
    payload = frame[4:4 + n]
    return msgpack.unpackb(gcm_open(payload, key), raw=False)

# 3) 第一帧用 Listener Key；之后用 init 中的 session key
init_msg = decrypt_frame(init_frame, listener_key)
inner = msgpack.unpackb(init_msg["data"], raw=False)
session_info = msgpack.unpackb(inner["data"], raw=False)
session_key = session_info["encrypt_key"]

# 4) 任务/回传
msg = decrypt_frame(task_frame, session_key)
for obj in msg["object"]:
    cmd = msgpack.unpackb(obj, raw=False)
    data = msgpack.unpackb(cmd["data"], raw=False) if cmd.get("data") else None
    print(hex(cmd["id"]), cmd["code"], data)
```

说明：原文用完整 3969 字节配置块与三帧样例验证了上述流程，解密出的 `process/pid/user/host/ipaddr/os_version/encrypt_key` 与服务端显示一致；PoC 未在本机复跑。

## 变体与关联

- 变体：`UseSSL=false` 时帧直接跑在 TCP 上；启用 mTLS 时先解 TLS（见 [[pentest-c2-mtls-insecureskipverify-client-cert-mitm]]），再按本卡解析。
- 变体：不同版本的 Profile 字段、INIT_PACK 层级和 Command 字段可能变化；以反编译代码为准，不要硬编码字段名。
- 变体：也可从运行中 Agent 的内存（gdb/Volatility）直接 dump 配置块或 Session Key，绕过二进制静态定位。
- 关联：[[defense-forensics-vshell-config-aes-cbc-traffic-aes-gcm-decrypt]]（同为 Go C2 的配置提取 + AES-GCM 帧，帧头与密钥派生不同）、[[defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt]]（4 字节长度 + nonce + 密文 + tag 的同类帧）、[[defense-forensics-danderspritz-modular-backdoor-rsa-aes-protocol]]（RSA 封装 AES 会话密钥的另一种设计）。
- 边界：配置被二次加密、Listener/Session Key 被清除、流量经过无法解密的 TLS 且没有客户端私钥、或帧被截断/重排时，需要结合内存取证或重新逆向。

## 检测与防御

- 检测：Go 二进制中出现高熵、约 3969 字节的配置块和 `vmihailenco/msgpack`/AES-GCM 调用；网络中出现 banner `AdaptixC2 server`、4 字节大端长度后接高熵数据、固定心跳长连接；Agent 进程读取自身配置、创建到固定地址的 TCP 连接。
- 防御：C2 侧不要只依赖嵌入样本的对称密钥，敏感配置使用 OS 密钥库/TPM；启用 TLS 并在客户端校验服务端证书；定期轮换 Listener/Session Key；mTLS 客户端私钥不要可导出。
- 取证响应：隔离主机、保存样本与 pcap；从配置块提取 Listener Key、从 INIT_PACK 提取 Session Key，离线解密全部帧；按 Command/输出还原攻击者操作与数据外带。
