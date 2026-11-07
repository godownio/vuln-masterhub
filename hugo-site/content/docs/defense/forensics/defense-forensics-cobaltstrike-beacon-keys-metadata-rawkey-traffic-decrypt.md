---
id: defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt
title: Cobalt Strike C2 流量解密：beacon_keys 私钥解元数据得 Raw Key，再用 cs-parse-http-traffic 还原命令
type: scenario
domain: defense
path: defense/forensics
technique: cobaltstrike-beacon-keys-traffic-decrypt
tags:
- forensics
- traffic-analysis
- c2
- cobalt-strike
- rsa
- aes
- metadata
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: Cobalt Strike 3.x / 4.x（原文按版本区分元数据特征）
verification:
  verified_by: verifier-V212
  verified_at: '2026-11-07T04:20:03+08:00'
  notes: 已对照原文与32张图片核对：哥斯拉 XOR_BASE64 特征与跳过理由成立；CS checksum8/1768.py /IC7z→/ptj+/submit.php、Cookie 元数据、cs-decrypt-metadata 输出 rawkey b0dbd2e7…、cs-parse-http-traffic 解出 ipconfig/whoami 与压缩包密码 This_iMp0rTant_pASsw0rD 均与截图一致；affected_versions 按原文 CS3.x/4.x 版本特征保留（与库内取证卡惯例一致）；未实际复跑解密脚本
url: /docs/defense/forensics/defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt/
draft: false
kb_aliases:
- CS 流量解密
- Cobalt Strike 流量分析
- .cobaltstrike.beacon_keys
- cs-decrypt-metadata
- cs-parse-http-traffic
- checksum8 beacon 下载
- Raw Key AES HMAC
---

## 一句话结论

拿到捕获的 CS 流量与 TeamServer 的 `.cobaltstrike.beacon_keys`（Java 序列化 RSA 密钥对）后，用 `cs-decrypt-metadata.py` 解开 Beacon 首个心跳 Cookie 中的元数据，得到 16 字节 Raw Key；对 Raw Key 做 SHA-256，前 16 字节作 AES 密钥、后 16 字节作 HMAC 密钥，再用 `cs-parse-http-traffic.py -r <rawkey>` 解密全部 GET/POST，即可还原攻击者下发的命令（如 `ipconfig`、`whoami`）与回传结果、压缩包密码等。

## 原理

- **CS 通信模型**：TeamServer 生成 RSA 密钥对，Beacon 用 TeamServer 的公钥加密上线元数据（用户名、主机名、进程等），放在 HTTP Cookie 或 POST 数据中 Base64 传输；TeamServer 用私钥解密。拿到私钥即可解开元数据中的 16 字节随机 Raw Key。
- **会话密钥派生**：`AES_key = SHA256(RawKey)[:16]`，`HMAC_key = SHA256(RawKey)[16:]`；后续所有 C2 请求/响应数据用 AES 加密、HMAC 校验。Raw Key 是解密整段流量的关键。
- **beacon_keys 文件**：TeamServer 首次运行生成 `.cobaltstrike.beacon_keys`，是 Java 序列化对象，含 RSA 公私钥；可用 `javaobj` 等库解析并导出 PEM。攻击者 TeamServer 被取证、备份/镜像泄露或样本打包时可能拿到。
- **元数据解密**：`cs-decrypt-metadata.py -f <beacon_keys> <Base64 metadata>` 输出 Raw Key、AES key、HMAC key；Cookie 中的长 Base64 串（x64 约 344 字符、x86 约 172 字符）就是元数据密文。
- **流量解密**：`cs-parse-http-traffic.py` 读取 pcap，用 Raw Key 派生密钥，解密 GET（任务下发/心跳）与 POST（结果回传）；配合 Wireshark 显示过滤器只保留 C2 主机对，避免非 CS HTTP 流量干扰。
- **备选密钥来源**：无法获取 beacon_keys 时，可从受害主机进程内存转储提取：CS 3.x 元数据常以 `0x0000BEEF` 开头，可直接定位并取 Raw Key；CS 4.x 无该特征，需枚举 16 字节候选做碰撞解密。破解版 TeamServer 可能共享同一 beacon_keys，可尝试公开已知私钥。
- **识别前提**：Stager 下载路径满足 checksum8（32 位和 92、64 位和 93，4 字符随机路径），响应为 `application/octet-stream` 的 PE（MZ）；心跳 Cookie 携带长 Base64 元数据；默认证书 CN 为 `Major Cobalt Strike`，JA3/JA3s 也可能是固定指纹。

## 触发条件

- 已捕获 CS 的 HTTP/HTTPS（或 DNS）C2 流量（pcap/pcapng）。
- 已取得 `.cobaltstrike.beacon_keys` 私钥文件，或能从受害主机内存转储中提取 Raw Key，或使用共享密钥的破解版私钥。
- 具备 Didier Stevens 的 `cs-decrypt-metadata.py`、`cs-parse-http-traffic.py` 等工具与 Python 环境。
- HTTPS 流量需已解密（SSLKEYLOGFILE/中间人）或在内存中直接提取会话密钥；仅密文 pcap 且无私钥时无法解密。
- 仅用于授权取证、应急响应和恶意流量分析。

## 利用步骤

1. 在 pcap 中识别 CS 流量：过滤 `http.request.uri matches "/....$"` 找 4 字符 stager 路径，计算 checksum8（92/93）；下载响应 PE 并用 `1768.py` 解析配置（C2 地址、端口、GET/POST URI）。
2. 从 TeamServer 目录、样本包或取证镜像中取出 `.cobaltstrike.beacon_keys`；用 `javaobj`/脚本提取 RSA 私钥并导出 PEM（如需要）。
3. 在心跳请求 Cookie 中提取 Base64 元数据字符串。
4. 运行 `cs-decrypt-metadata.py -f <.cobaltstrike.beacon_keys> <metadata>`，记录输出的 Raw key、AES key、HMAC key。
5. 运行 `cs-parse-http-traffic.py -r <rawkey> -Y "http and ((ip.src==C2 and ip.dst==victim) or (ip.src==victim and ip.dst==C2))" capture.pcapng`，解密 GET/POST。
6. 按时间线查看任务下发与回传：命令（ipconfig/whoami 等）、输出、文件、压缩包密码等；结合流编号（如流 91/92/93）定位首次空响应、命令下发与结果回传。
7. 若没有 beacon_keys，尝试从受害进程内存转储提取 Raw Key（CS3 找 `0x0000BEEF`；CS4 枚举候选碰撞），或用公开的破解版共享密钥。

## PoC

元数据解密：

```bash
python3 cs-decrypt-metadata.py -f "C:\download\1758378387.6662319\.cobaltstrike.beacon_keys" \
  "COqHjGXBGBLBSaR4HNHCDXQ786ES6WdwZTyai0ooSV6DGc0ZFXoGr4v+bTxCivZeptBp72cApufj9T4ff1lpb0PoIjLtcOu/qTribyQPyRQJ/N3KHpBs47O4/EAy43Bl9AUORn9Kmvpoqzr76zkhXuJdNbn7mm6m/LR13Dfqbos="
```

输出（示例）：

```text
Raw key:  b0dbd2e724e2a68105ba599a1ad8f30d
aeskey:   e2d919d0bff758aeb1167e38ff293edf
hmackey:  25a496ed7274cb32d46d600205781afb
```

流量解密：

```bash
python3 cs-parse-http-traffic.py -r b0dbd2e724e2a68105ba599a1ad8f30d \
  -Y "http and ((ip.src == 192.168.33.143 and ip.dst == 192.168.33.142) or (ip.src == 192.168.33.142 and ip.dst == 192.168.33.143))" \
  attack.pcapng
```

文章实测解密出 `ipconfig`、`whoami` 及回传结果，并从流量中得到压缩包密码。

## 变体与关联

- **私钥来源变体**：TeamServer 的 beacon_keys、样本包/备份泄露、共享破解版密钥、受害主机内存转储。
- **内存提取**：CS 3.x 元数据以 `0x0000BEEF` 开头，易定位；CS 4.x 无固定头，需枚举 16 字节候选做碰撞（计算量大）。
- **协议变体**：DNS Beacon 的加密原理类似，但数据在 TXT 的 Base64 或 A/AAAA 记录的异或编码中；解密仍需 AES/HMAC 密钥。
- **流量识别**：stager checksum8（92/93）、PE 响应、心跳周期与固定长度、Cookie 长 Base64、默认证书 `Major Cobalt Strike`、JA3/JA3s 指纹；但 Malleable C2 可改变 URI/头/证书，需综合判断。
- **关联**：[[pentest-c2-cs-malleable-10086-traffic-masquerade]]（CS 流量伪装，增加识别难度）、[[defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt]]（另一 C2 的会话密钥提取与解密）、[[defense-forensics-godzilla-php-webshell-traffic-decode]]（WebShell 流量解密）。

## 检测与防御

- **流量侧**：监控 checksum8 为 92/93 的 4 字符 URI、`application/octet-stream` 的 PE 下载、周期性心跳与长 Base64 Cookie、默认 `Major Cobalt Strike` 证书、已知 JA3/JA3s；对异常 POST 高熵数据与长度突变告警。
- **主机侧**：检测 rundll32/mshta 等进程的异常网络行为；对可疑进程做内存转储并搜索元数据/密钥特征；审计 TeamServer 端口与证书。
- **取证**：保存完整 pcap、beacon_keys、内存转储与解密脚本输出作为证据链；记录解密出的命令与数据外传范围。
- **防御**：限制出站、TLS 检查与 JA3 指纹、证书白名单；对 C2 常用端口/URI/心跳模式做威胁狩猎；及时轮换可能泄露的密钥。
- **注意**：只有密文流量而没有私钥/Raw Key 时无法解密；HTTPS 需先解密或从内存取密钥。
