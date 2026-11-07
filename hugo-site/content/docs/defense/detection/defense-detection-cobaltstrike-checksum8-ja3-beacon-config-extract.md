---
id: defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract
title: CobaltStrike 流量识别与 Beacon 配置提取：checksum8 92/93、JA3/JA3s 与 1768.py 解析 stager
type: scenario
domain: defense
path: defense/detection
technique: cobaltstrike-traffic-identify-beacon-config-extraction
tags:
- cobaltstrike
- c2
- traffic-analysis
- ja3
- checksum8
- beacon-config
- threat-hunting
- detection
cve: []
severity: high
confidence: high
status: verified
affected_versions: Cobalt Strike 4.4（原文 1768.py 对样本判定为 4.4；JA3S 指纹标注为 CentOS CS4.4）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:57:36+08:00'
  notes: V263 复核：已完整重读 content.md 与全部7张图。checksum8 原文逐字核对：/FJwV → 70+74+119+86=349 → 349%256=93（64位），卡内一致；图01 可看到 GET /FJwV、GET /en_US/all.js、POST /submit.php?id=1603726794；图02 JA3 过滤器显示 28a2c9bd18a11de089ef85a160da29e4（SNI=go.microsoft.com），与原文 Windows10 HTTPS Beacon JA3 一致；图03 导出对象列表显示 /FJwV 265KB application/octet-stream；图05 GET /en_US/all.js 的 Cookie 即 Base64 元数据、UA 为 IE10。1768.py 输出/payload type/server,get-uri/post-uri/useragent/header 变换/spawnto/Guessing 4.4(max 0x0049)/sanity OK 与原文一致，卡内 PoC 为忠实节选。affected_versions 按原文样本 CS4.4（JA3S 为 CentOS CS4.4）保留，与库内 CS 取证卡惯例一致。dedup 最高分为卡自身 exact；beacon_keys 解密卡、域前置卡、Malleable 伪装卡均为不同前置/不同输出，verdict=new/related，不合并。未复跑 1768.py；frontmatter 无 sources/source（符合禁用要求），亦无 source_url。
url: /docs/defense/detection/defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract/
draft: false
kb_aliases:
- CS 流量识别
- checksum8 92/93
- CobaltStrike JA3 指纹
- 1768.py Beacon 配置
- stager 载荷解析
- Beacon 配置提取
---

## 一句话结论

在 pcap 中先用四条路径字符的 checksum8（和值 % 256 = 92/93）或 JA3/JA3s 指纹锁定 CobaltStrike 的 stager 下载流量，导出 `application/octet-stream` 载荷后交给 `1768.py` 解析，即可在不解密后续 C2 密文的情况下还原 payload 类型、C2 地址与 GET/POST URI、User-Agent、RSA 公钥、注入目标进程等 Beacon 配置。

## 原理

- **checksum8 路径特征**：CobaltStrike 的 stager URI 通常是 4 个随机字符，路径字符 ASCII 码之和对 256 取余等于 92（32 位后门）或 93（64 位后门）。例如 `/FJwV`：`70+74+119+86=349`，`349 % 256 = 93`，可判定为 64 位 Beacon 的下载路径。该特征来自 stager 的路径校验逻辑，未改 profile 时可直接用于筛选。
- **默认 URI 与请求形态**：未修改的 CS 常见 `/submit.php?id=xxx`、`/pixel.gif`、`/q.cgi` 等路径；HTTP Beacon 默认用 GET 拉取任务/心跳、用 POST 回传数据，POST 常见 `/submit.php?id=<beacon id>`。stager 下载阶段路径形如 `/Yle2`、`/cKTZ`，同样落在 checksum8 规则内。
- **JA3/JA3s 指纹**：TLS ClientHello/ServerHello 的扩展、曲线与密码套件顺序由客户端/服务端实现决定，Malleable C2 profile 改不了。因此同一操作系统上的同版本 Beacon 会有稳定 JA3；原文给出的样本中，Windows 10 HTTPS Beacon 的 JA3 为 `28a2c9bd18a11de089ef85a160da29e4`，CentOS 上 CS4.4 的 JA3S 为 `00447ab319e9d94ba2b4c1248e155917`。指纹与操作系统、CS 版本相关，换环境需重新采集。
- **stager 与 Beacon 的分工**：首次心跳由 stager 发起，目的是下载完整的 Beacon（约 200–300KB 的反射 DLL 或 shellcode）。stager 请求通常无加密或仅简单 XOR、一次性、无固定心跳；响应体就是 Beacon 二进制。Beacon 下载并注入内存后才发起真正的首次心跳，携带主机信息、经 RSA 公钥加密后放在 Cookie 或 POST 数据中，之后按 sleep/jitter 周期通信。
- **为什么 1768.py 能解出配置**：Beacon 载荷内部保存一份 XOR 混淆的配置块（payload type、端口、sleep、jitter、publickey、server/get-uri、post-uri、useragent、HTTP header 变换、spawnto、CryptoScheme 等），`1768.py` 会搜索配置块、试解 XOR key，并按配置项最大 ID 猜测 CS 版本（如 `max 0x0049` 对应 4.4）。因此无需私钥，只要拿到 stager 下载的明文 Beacon 就能还原 C2 作战参数。
- **边界**：HTTPS stager 若无法解密 TLS 或拿不到证书私钥，就导不出载荷；Malleable profile 可改 URI、Header、证书，checksum8/固定 URI 会失效，但 JA3/JA3s 仍可能保留；反过来，仅凭 JA3 命中也不能单独定性，需要结合路径、响应体、周期与主机侧行为。

## 触发条件

- 已捕获 CS 的 HTTP/HTTPS 流量（pcap/pcapng）；HTTPS 需已解密或能导出 stager 响应体。
- 流量中存在 stager 下载阶段：4 字符随机 URI、`application/octet-stream` 的 PE/Shellcode 响应（常见 200–300KB）。
- 具备 `1768.py`（DidierStevensSuite）与 Python 环境；DNS Beacon、SMB Beacon 等非 HTTP 变体需另用对应解析方式。
- 仅用于授权取证、应急响应、CTF 与恶意流量分析。

## 利用步骤

1. 在 Wireshark 中过滤 `http`，按 Info 列找 4 字符路径（如 `/FJwV`），对路径逐字符求 ASCII 和再 `% 256`，结果为 92/93 即高度疑似 CS stager；同时留意 `/submit.php?id=`、`/pixel.gif`、`/q.cgi` 等默认路径。
2. 对 HTTPS 流量查看 TLS 握手：用 JA3/JA3s 工具或 Wireshark 计算指纹，与已知版本指纹比对；结合 SNI、证书 CN、请求周期排除误报。
3. 用“文件 → 导出对象 → HTTP”或“导出 HTTP 对象列表”按 Host/URI 找到 stager 响应（Content-Type 常为 `application/octet-stream`），导出二进制载荷。
4. 运行 `python 1768.py <导出的载荷>`，读取输出：payload type、port、sleeptime、jitter、publickey、server/get-uri、post-uri、useragent、http_get_header/http_post_header 的变换链、spawnto_x86/x64、CryptoScheme、进程注入参数，以及猜测的 CS 版本与 sanity check 结果。
5. 将 `server,get-uri`、`post-uri`、User-Agent、publickey（或其哈希）、证书、JA3/JA3s 录入 IOC/检测规则；若后续取得 `.cobaltstrike.beacon_keys` 或内存密钥，可继续解密会话（见关联卡）。
6. 若需要利用 publickey 求私钥：把配置中的 publickey 去掉尾部补零后按 DER 导入，可得到 RSA 的 n/e；但 1024 位模数在常规算力下无法分解（原文样本用 yafu 亦未成功），因此该路径通常只用于指纹比对，实际解密应优先寻找 beacon_keys 或内存密钥。

## PoC

checksum8 判定（原文样本）：

```text
路径: /FJwV
70 (F) + 74 (J) + 119 (w) + 86 (V) = 349
349 % 256 = 93  -> 64 位 CobaltStrike 后门
```

stager 载荷配置解析（节选关键字段）：

```text
$ python 1768.py FJwV
xorkey(chain): 0x1f6828ff
0x0001 payload type        0x0001 0x0002 0 windows-beacon_http-reverse_http
0x0002 port                0x0001 0x0002 80
0x0003 sleeptime           0x0002 0x0004 60000
0x0005 jitter              0x0001 0x0002 0
0x0008 server,get-uri      0x0003 0x0100 '192.168.31.170,/en_US/all.js'
0x0009 useragent           0x0003 0x0100 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0; MASP)'
0x000a post-uri            0x0003 0x0040 '/submit.php'
0x000c http_get_header     Cookie + BASE64
0x000d http_post_header    Content-Type: application/octet-stream; SessionId -> id
0x001f CryptoScheme        0x0001 0x0002 0
0x001d spawnto_x86         '%windir%\syswow64\rundll32.exe'
0x001e spawnto_x64         '%windir%\sysnative\rundll32.exe'
Guessing Cobalt Strike version: 4.4 (max 0x0049)
Sanity check Cobalt Strike config: OK
```

原文另给出同一流量的心跳请求形态：`GET /en_US/all.js`，`Cookie: <Base64 元数据>`，UA 为 IE10；POST 为 `/submit.php?id=1603726794`，响应 `Content-Type: application/octet-stream`，可作为流量侧关联依据。

## 变体与关联

- **Malleable C2 变体**：自定义 URI、Header、证书后 checksum8 与固定路径失效，但 `1768.py` 仍可从载荷配置中读出实际 URI/UA/Header 变换；结合 JA3/JA3s、心跳周期、包长分布补偿。
- **HTTPS 变体**：stager 走 TLS 时需先解密；JA3/JA3s 与证书 CN（默认 `Major Cobalt Strike`）可辅助识别，载荷导出依赖 TLS 解密或内存取证。
- **DNS/SMB Beacon 变体**：不走 HTTP 的 stager/Beacon 需要按各自协议解析，checksum8 规则不适用；但 Beacon 配置块与密钥体系同源。
- **关联**：[[defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt]]（拿到 beacon_keys 后解元数据与命令）、[[defense-forensics-cobaltstrike-memory-beacon-session-key-collision]]（无 beacon_keys 时从内存提取会话密钥）、[[defense-detection-cobaltstrike-domain-fronting-config]]（域前置场景的配置识别）、[[pentest-c2-cs-malleable-10086-traffic-masquerade]]（Malleable 伪装增加识别难度）。

## 检测与防御

- **网络检测**：对 4 字符 URI 批量计算 checksum8=92/93 并告警；监控 `application/octet-stream` 的大体积 PE/Shellcode 下载；对 `GET /en_US/all.js`、`POST /submit.php?id=` 等默认路径和 IE/旧版 UA 组合降权/告警；维护已知 CS JA3/JA3s 指纹库，定期随版本更新。
- **配置侧**：把 `1768.py` 解出的 payload type、publickey、URI、UA、spawnto、证书写入 IDS/YARA/威胁情报；同一 publickey/证书指纹可跨样本关联同源 TeamServer。
- **主机侧**：检测 rundll32/mshta/dllhost 等进程的异常网络行为与反射加载；对可疑进程做内存转储并搜索 Beacon 特征（配置块、`sha256\x00`、睡眠混淆路由）。
- **防御**：出站白名单与 TLS 检查；限制未知域名的长连接和周期心跳；对高分 JA3 与异常 URI 组合做阻断；及时轮换/封禁泄露的 C2 基础设施。
- **注意**：JA3/JA3s 与版本和操作系统强相关，不能跨环境硬套；checksum8 也可能被非 CS 程序偶然命中，需多信号联合判定。
