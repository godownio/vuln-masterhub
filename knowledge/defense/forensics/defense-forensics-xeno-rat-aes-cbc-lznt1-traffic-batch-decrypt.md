---
id: defense-forensics-xeno-rat-aes-cbc-lznt1-traffic-batch-decrypt
title: Xeno-RAT 通信协议与批量解密：4+1 字节帧、AES-CBC（零 IV、key=SHA256 密码）、LZNT1 压缩与插件 DLL 还原
type: scenario
domain: defense
path: defense/forensics
technique: xeno-rat-frame-aes-cbc-lznt1-batch-decrypt
aliases:
- Xeno-RAT 流量解密
- Xeno-RAT 通信模型
- RtlDecompressBuffer 流量解密
- LZNT1 C2 解密
- Xeno-RAT 批量解密脚本
tags:
- forensics
- traffic-analysis
- c2
- rat
- dotnet
- aes-cbc
- lznt1
- plugin-dll
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V411-fix
  verified_at: '2026-11-09T15:02:31+08:00'
  notes: V411 核对指出：原理中『内层标志 2……首个会话中可见 64 字节随机数据』原文与 28 张截图均无佐证（按原文样例帧实际解密首帧为 100 字节高熵数据，长度不符）。已删除该 64 字节细节，改为『特殊块，脚本原样返回；具体内容原文未展开，按脚本处理即可』。其余帧结构/AES 参数/LZNT1/插件 MD5 核对不变。
---

## 一句话结论

Xeno-RAT（原文分析 v1.8.7）的 TCP 通信帧为“4 字节小端长度 + 1 字节标志 + 载荷”，载荷用 AES-256-CBC（key = SHA256(配置密码)，IV 全零，PKCS7）加密，并按标志选择 LZNT1（ntdll `RtlDecompressBuffer`，格式 2）压缩/解压；按帧结构解密后可还原上线信息、目录/进程等远控数据，明文以 `4D5A` 开头时即为内存加载的插件 DLL，可按 MD5 映射回插件名并对多个会话批量落盘。

## 原理

- **帧结构**：每次发送为 `[4 字节小端载荷长度][1 字节标志][载荷]`。接收端先读长度再读满载荷，因此按长度切分 TCP 流即可恢复消息边界。
- **三类报文（按外层标志）**：
  1. `flag=0`：载荷就是 AES 密文，直接解密；
  2. `flag=1`：`[origSize 4B][LZNT1 压缩的 AES 密文]`——先解压再解密（即“先加密后压缩”的发送顺序）；
  3. `flag=3`：载荷为 AES 密文，解密后是内层结构 `[内层标志][可选 4 字节原始长度][数据]`；内层标志 `0` 表示后面是明文载荷，`1` 表示后面是 LZNT1 压缩数据（先解压），`2` 为特殊块（脚本原样返回；具体内容原文未展开，按脚本处理即可）。
  另有外层 `flag=2` 的特殊帧，脚本只打印不处理。
- **密码学参数**：C# 端 `Encryption.Encrypt/Decrypt` 用 `Aes.Create()`，`Key` 为 32 字节（AES-256），`IV = new byte[16]`（全零），默认 CBC + PKCS7；key 来自配置密码的 SHA256（见关联卡）。
- **压缩算法**：客户端通过 `[DllImport("ntdll.dll")]` 调用 `RtlCompressBuffer`/`RtlDecompressBuffer`，`CompressionFormat=2`（LZNT1）；解密脚本同样 `LoadDLL("ntdll.dll")` 后调用 `RtlDecompressBuffer`，按解密出的 `OriginalFileSize` 分配缓冲区。
- **会话模型**：第 1 个会话上报系统基本信息（用户名、主机/域、客户端版本、OS、杀软、是否管理员）；第 2 个会话用于心跳并开启第 3 个主会话；主会话传输远控指令。插件按需下发：`DllHandler` 先收 DLL 名，再收 DLL 字节，`Assembly.Load` 后反射创建实例并调用 `Run`；FileManager 会开 2 个子会话（传插件 + 通信），ProcessManager 只需 1 个。
- **可还原的证据**：解密后可见主机信息（用户名、`DESKTOP-*` 主机名、Windows 版本、杀软组合、是否 Admin）、文件管理器回传的盘符/目录（`C:\`、`$Recycle.Bin`、`Program Files` 等）、进程列表（含 `xeno rat server.exe`、安全软件进程），以及传输中的插件 DLL 本体（MZ 头）。
- **为什么批量脚本可行**：帧头长度自校验 + 固定标志位 + 固定密码学参数，使 Wireshark 导出的每个会话都能机械解密；插件 DLL 判据是解密明文以 `4D5A`（`MZ`）开头，MD5 与官方插件一一对应，可自动命名落盘。

## 触发条件

- 捕获到 Xeno-RAT 的 TCP 流量（明文 TCP，无 TLS 封装）。
- 取得通信密钥：样本 `Program.EncryptionKey` 或配置密码的 SHA256（见关联卡）；仅有 pcap 时也可对弱密码字典尝试。
- 解 LZNT1 需要 Windows 的 ntdll（或自行实现 LZNT1 解压）；批量脚本输入为 Wireshark “Follow TCP Stream → Save as → C Arrays” 导出的文件。

## 利用步骤

1. 从样本/控制端取得 `EncryptionKey`（32 字节 SHA256）。
2. Wireshark 中对每条 TCP 流执行 Follow TCP Stream，保存为 C Arrays（行为形如 `char peer0_0[] = { /* Packet 4 */ 0x71, 0x00, ... };`）。
3. 脚本按 `char peerN_M[] = { ... };` 解析十六进制数组，取出前 4 字节小端长度并校验与剩余长度一致，再按第 5 字节标志分派解密：
   - flag 0 → `AES-CBC-decrypt(body)`；
   - flag 1 → `AES-CBC-decrypt(LZNT1-decompress(body[4:]))`；
   - flag 3 → `p = AES-CBC-decrypt(body)`；`p[0]=0` 取 `p[1:]`；`p[0]=1` 取 `LZNT1-decompress(p[5:])`；`p[0]=2` 原样输出。
4. AES 参数：key=SHA256 密钥，IV=16 个 0x00，CBC，PKCS7 去填充。
5. 解密结果以 `4D5A` 开头则判为插件 DLL：计算 MD5，按已知插件 MD5 表命名保存（如 `File manager.dll`=`0746F23B…`、`ProcessManager.dll`=`4DAC21B4…`、`Shell.dll`=`5E3E4438…`，共 17 个），便于后续静态分析。
6. 其余结果按十六进制/字符串写入 `.dec` 日志，按“send/recv”方向还原会话：上线信息 → 心跳 → 主会话指令 → 插件通信。
7. 对目录下所有导出的会话批量重复，形成完整时间线。

## PoC

```text
frame = LE32(len) || flag || body          # 按 4 字节长度切帧
key   = SHA256(password)                   # 32B，AES-256
dec   = AES_CBC_dec(key, iv=0x00*16, body) # PKCS7

if flag == 3:
    t = dec
    if t[0] == 0: out = t[1:]
    if t[0] == 1: out = LZNT1_decompress(t[5:])   # t[1:5] = 原始长度
    if t[0] == 2: out = t                        # 特殊块
elif flag == 1:
    out = AES_CBC_dec(key, iv=0x00*16, LZNT1_decompress(body[4:]))
else:  # flag == 0
    out = dec
if out[:2] == b"MZ": save_plugin_by_md5(out)
```

```text
# 明文示例（解密后字符串）
moom825 ; 847F7D802320BB4704B800\admin\DESKTOP-A11RBL8\admin\1.8.7\Microsoft Windows 10 ... \Windows Defender, 火绒安全软件\False
C:\ ; C:\$Recycle.Bin ; C:\$WinREAgent ; C:\Program Files ...
```

## 变体与关联

- 变体：同族样本可能改 KDF（加盐/迭代）或压缩格式（XPRESS/LZ4），需按客户端 `Compression`/`Encryption` 类重新核对；无 Windows 环境时可用纯 Python 的 LZNT1 实现替代 ntdll。
- 关联：与 [[defense-forensics-eaglemonitorrat-traffic-protocol-decrypt]]（4+1 帧 + PBKDF2 + QuickLZ + BinaryFormatter）、[[defense-forensics-adaptixc2-beacon-http-rc4-session-key-traffic-decrypt]]（会话密钥）同属“配置/密钥驱动的 C2 流量批量解密”；插件 DLL 判定与落盘可对照 [[defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt]] 的多层解码思路。
- 与冰蝎/哥斯拉 webshell 流量解密卡的共同点：都是“固定帧 + 对称密钥 + 可选压缩”，差异只在帧头标志与 KDF。

## 检测与防御

- 检测：TCP 载荷呈 `4 字节长度 + 0x00/0x01/0x03 标志` 的重复结构；进程导入 `ntdll!RtlDecompressBuffer/RtlCompressBuffer`（C#/Go 远控少见组合）；`Assembly.Load` 加载网络接收的字节；内存中出现 `xeno_rat_client`、`Xeno_rat_` 互斥体；外联行为与心跳延时（如 5000ms）一致。
- IOC：插件 MD5 表（`File manager.dll` 0746F23B790FD439980D155A75E6275B、`ProcessManager.dll` 4DAC21B4F2984931B9710CA50329023A、`Shell.dll` 5E3E4438045C426410122210759CC0C8 等 17 项）、默认/示例互斥体与端口。
- 防御/取证：查获样本先提 key 再离线解 pcap；对导出的插件 DLL 做 MD5 与家族比对；对“长度+标志+高熵载荷”的明文 TCP 流量建规则；EDR 阻断反射加载网络字节并调用 `Run` 的行为。
