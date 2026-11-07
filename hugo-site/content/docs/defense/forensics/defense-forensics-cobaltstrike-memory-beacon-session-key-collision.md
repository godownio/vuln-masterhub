---
id: defense-forensics-cobaltstrike-memory-beacon-session-key-collision
title: 无 beacon_keys 时从进程内存提取 CobaltStrike 4.x Beacon 会话密钥：sha256 结构定位与 16 字节候选碰撞
type: scenario
domain: defense
path: defense/forensics
technique: cobaltstrike-memory-beacon-session-key-collision
tags:
- forensics
- memory
- c2
- cobalt-strike
- volatility
- session-key
- aes
- hmac
- traffic-analysis
cve: []
severity: high
confidence: high
status: verified
affected_versions: Cobalt Strike 4.x（原文明确 4.x Beacon 已无未加密元数据头，需用 16 字节候选碰撞；并与 CS 3.x 的 0x0000BEEF 元数据头对比）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:57:39+08:00'
  notes: V263 复核：已完整重读 content.md 与全部7张图。卡面对应原文“通过进程内存提取”段：windows.cmdline/pslist 定位 PID 6492 可疑 exe（图06 的 HTTP 对象列表为同一 pcap 的 25 TJvI/296KB、submit.php?id=1389642286）；windows.memmap --pid 6492 --dump；cs-extract-key.py 先按 sha256\x00 定位，输出 AES a6f4a04f…、HMAC 35d34ac8…、SHA256 raw key 35d3…:a6f4…；原文第一轮两个 0000BEEF 结构解出的值失败，最终用包103密文碰撞  得到正确密钥，再用 cs-parse-traffic.py -k HMAC:AES 解出 PS/LS/EXECUTE_JOB type secret.txt/CALLBACK_OUTPUT_OEM UUID/GETPRIVS/GETUID/getsystem failed，卡内步骤与 PoC 与原文一致，并明确“必须用实际密文验证”。图07 云沙箱 CobaltStrike 报毒与原文一致。affected_versions 按原文 CS4.x 与 CS3.x 0x0000BEEF 对比保留。dedup 最高分为卡自身 exact；beacon_keys 解密卡（cos 0.9038）为有私钥的标准链，属 related 不同前置，不合并。未复跑 Volatility/cs-extract-key；frontmatter 无 sources/source（符合禁用要求），亦无 source_url。
url: /docs/defense/forensics/defense-forensics-cobaltstrike-memory-beacon-session-key-collision/
draft: false
kb_aliases:
- CS 内存取密钥
- Beacon 内存密钥
- cs-extract-key
- CobaltStrike 密钥碰撞
- Raw Key 碰撞
- CS 4.x 流量密钥
---

## 一句话结论

只有受害主机内存转储和加密的 C2 pcap、拿不到 TeamServer 的 `.cobaltstrike.beacon_keys` 时，用 Volatility3 转储 Beacon 进程内存，先从 `sha256\x00` 标记后取出 32 字节 SHA-256 摘要（前 16 字节 AES key、后 16 字节 HMAC key）或按 `0x0000BEEF` 元数据头提取 Raw Key；CS 4.x 没有固定头时，则把进程内存中所有 16 字节非空序列当作密钥字典，对已知 C2 密文做碰撞解密，命中后再用 `cs-parse-traffic.py -k <hmac>:<aes>` 还原攻击者下发的命令与回显。

## 原理

- **Beacon 需要把会话密钥留在内存**：Beacon 上线后要与 TeamServer 用对称密钥加解密每个任务/回传，密钥必须在进程内存中可用。CS 3.x 会在内存中保留带 `0x0000BEEF` 头的元数据块，头后偏移 8–24 字节就是 16 字节 Raw Key，定位后可直接派生 AES/HMAC；这是 `cs-extract-key.py` 早期的主要路径。
- **CS 4.x 的变化**：原文指出，CS 4.x Beacon 在内存中不再保留可识别的未加密元数据头，单纯的 16 字节序列没有区分特征。工具仍可搜索 `sha256\x00` 字符串，其后通常紧跟 32 字节 SHA-256 摘要——前 16 字节作 AES key、后 16 字节作 HMAC key（即 `SHA256(rawkey)` 的两段切分）。原文样本中 cs-extract-key 在 `sha256\x00` 后定位到 AES key `a6f4a04f...`、HMAC key `35d34ac8...`，并以 `35d34ac8...:a6f4a04f...`（HMAC:AES）格式交给 cs-parse-traffic 后成功解密。
- **碰撞法的依据**：若内存结构定位失败或命中的是假密钥，可以枚举进程中所有 16 字节长的非空字节序列作为候选密钥字典，逐个尝试解密已知的 C2 请求/响应密文；只有正确的密钥能通过 HMAC 校验并解出合法命令结构，碰撞成功即找到会话密钥。代价是候选数量大、需要已知密文或已知明文作为判定标准。
- **为什么不能直接分解公钥**：从 Beacon 配置能拿到 RSA 公钥及 n/e，但常见 CS 公钥为 1024 位，用 yafu 等工具在常规算力下无法分解（原文样本即分解失败），因此没有 beacon_keys 时，内存提取/碰撞才是现实路径。
- **误报与验证**：内存中可能有多处 `0x0000BEEF` 或疑似密钥结构，工具输出的 AES/HMAC 未必能解密；原文第一轮从两个 `0000BEEF` 结构取出的值解密即失败，最终靠已知密文（包 103）碰撞才得到正确密钥。因此必须用实际 C2 密文验证，不能只看工具是否打印了 key。

## 触发条件

- 已有受害主机内存转储（raw/dmp）与对应的 C2 流量 pcap/pcapng；流量可为 HTTP，HTTPS 需先取得 TLS 会话密钥或在内存中同时定位 TLS 密钥。
- 没有 TeamServer 的 `.cobaltstrike.beacon_keys` 私钥，也没有其他可用的 Raw Key 来源。
- 具备 Volatility3（windows.info/cmdline/pslist/memmap 等）与 DidierStevensSuite 的 `cs-extract-key.py`、`cs-parse-traffic.py`。
- 适用于 CS 4.x（需要碰撞/结构搜索）；CS 3.x 可直接按 `0x0000BEEF` 元数据头提取，成本更低。
- 仅用于授权取证、应急响应与恶意流量分析；内存转储可能含敏感数据，需按证据链保管。

## 利用步骤

1. 用 `vol.py -f <内存镜像> windows.info` 确认系统与符号，`windows.cmdline`/`windows.pslist` 找出可疑进程（如桌面伪装文档名、无签名的 exe），记录 PID。
2. 用 `windows.filescan`/`windows.dumpfiles` 可先把可疑样本落盘送沙箱确认家族（原文样本被沙箱标记为 CobaltStrike 后门）；核心证据仍是进程内存。
3. 用 `windows.memmap --pid <PID> --dump` 转储该进程全部内存页，得到 `pid.<PID>.dmp`。
4. 运行 `python cs-extract-key.py pid.<PID>.dmp`：先看是否有 `0x0000BEEF` 元数据块及 Raw Key/AES/HMAC 输出；若输出的密钥无法解密流量，不要采用。
5. 若结构定位失败或结果不可信，用已知 C2 密文做碰撞：先 `python cs-parse-traffic.py -k unknown capture.pcapng > key.txt` 导出可分析的密文/参考，再把目标包（如包 103）的密文十六进制传给 `cs-extract-key.py -t <hex> pid.<PID>.dmp`，让工具在内存中搜索能匹配的密钥；必要时自行枚举 16 字节非空序列构造字典，逐个用 HMAC/AES 校验。
6. 找到正确密钥后，运行 `python cs-parse-traffic.py -k <hmac>:<aes> capture.pcapng`，按包号查看 GET（任务下发、心跳）与 POST（命令回显、文件、进程列表等），还原攻击者操作时间线。
7. 用已知明文交叉验证：例如解密出的 `COMMAND_EXECUTE_JOB` 参数 `%COMSPEC% /C type secret.txt` 与随后 `CALLBACK_OUTPUT_OEM` 的 UUID 输出应对应同一时间线；若 HMAC 校验失败或命令结构乱码，说明密钥错误。

## PoC

Volatility3 定位并转储进程：

```bash
python3 vol.py -f DESKTOP.raw windows.cmdline
python3 vol.py -f DESKTOP.raw windows.pslist
python3 vol.py -f DESKTOP.raw windows.memmap --pid 6492 --dump
```

从内存提取密钥（原文关键输出）：

```text
> python cs-extract-key.py -t 0253784e...c1225f92 pid.6492.dmp
File: pid.6492.dmp
Searching for AES and HMAC keys
Found 2 instance(s) of string sha256\x00
Searching after sha256\x00 string (0x61a44)
AES key position: 0x00068c60
AES Key:  a6f4a04f8a6aa5ff27a5bcdd5ef3b9a7
HMAC key position: 0x00068c70
HMAC Key: 35d34ac8778482751682514436d71e09
SHA256 raw key: 35d34ac8778482751682514436d71e09:a6f4a04f8a6aa5ff27a5bcdd5ef3b9a7
```

解密流量（`-k` 为 `HMAC:AES` 顺序）：

```bash
python cs-parse-traffic.py -k 35d34ac8778482751682514436d71e09:a6f4a04f8a6aa5ff27a5bcdd5ef3b9a7 DESKTOP.pcapng
```

原文解密结果节选：`COMMAND_PS`、`COMMAND_LS`（列出 `C:\Users\JohnDoe\Desktop\*`，含 `secret.txt`）、`COMMAND_EXECUTE_JOB`（`%COMSPEC% /C type secret.txt`）、`CALLBACK_OUTPUT_OEM`（回显 UUID `5c1eb2c4-0b85-491f-8d50-4e965b9d8a43`）、`COMMAND_GETPRIVS`、`COMMAND_GETUID`（`DESKTOP-OKEP6GL\JohnDoe`）与 `COMMAND_INLINE_EXECUTE_OBJECT`（getsystem failed）。

## 变体与关联

- **CS 3.x 更简单**：内存中保留 `0x0000BEEF` 元数据块，直接从偏移 8 取 16 字节 Raw Key，再按 `SHA256(rawkey)` 派生 AES/HMAC；无需碰撞。
- **CS 4.x 的 `sha256\x00` 结构**：若 Beacon 版本/编译方式保留了该标记，优先按标记搜索，比全量 16 字节碰撞快得多；不同版本标记位置与摘要布局可能变化，需以实际解密验证。
- **纯碰撞路径**：没有任何结构线索时，枚举内存中所有 16 字节非空序列，用已知密文的 HMAC 校验筛出正确 key；计算量大，应先用可疑进程/内存页缩小范围。
- **HTTPS 变体**：需要同时从内存或 SSLKEYLOGFILE 取 TLS 密钥；否则只能看到加密隧道元数据。
- **关联**：[[defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt]]（有 beacon_keys 时的标准解密链）、[[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]（先用 checksum8/JA3/1768.py 识别并提取配置）、[[defense-forensics-openssh-session-key-memory-sshenc-pcap-decrypt]]（同类“内存取会话密钥解 pcap”思路）。

## 检测与防御

- **取证侧**：内存转储要覆盖 Beacon 进程全部可读页（memmap 而非仅 strings）；同时保存 pcap、进程列表、样本文件与工具输出，记录密钥提取的中间位置与校验过程；对多个候选密钥必须用实际密文验证。
- **主机检测**：监控异常的进程内存转储行为（如 DumpIt、任务管理器转储、EDR 的 memdump）；对 rundll32/dllhost/伪装文档名进程的反射加载与网络外联做关联；检测 `sha256\x00` 附近的高熵 32 字节结构可作为 Beacon 内存扫描规则之一。
- **防御**：缩短 Beacon 存活时间、及时隔离受感染主机并轮换 C2 基础设施；启用 Credential Guard/内存完整性等可提高内存窃取成本，但不能阻止管理员权限下的进程转储；对高价值主机限制调试权限与内存转储工具。
- **注意**：内存密钥提取依赖攻击者未使用强内存加密/睡眠混淆；若 Beacon 对密钥做额外保护，`sha256\x00` 结构与碰撞都可能失效，需要结合样本逆向定位密钥使用点。
