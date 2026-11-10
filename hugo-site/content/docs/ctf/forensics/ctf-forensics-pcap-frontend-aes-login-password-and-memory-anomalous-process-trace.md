---
id: ctf-forensics-pcap-frontend-aes-login-password-and-memory-anomalous-process-trace
title: 数据泄露溯源：从 PCAP 还原前端 AES 加密的登录口令 + 内存镜像定位异常外联进程
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-http-frontend-aes-hardcoded-key-decrypt-and-volatility-anomalous-process-path-trace
tags:
- ctf
- forensics
- pcap
- wireshark
- http-object
- frontend-crypto
- aes-cbc
- hardcoded-key
- volatility
- memory
- incident-response
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:52:00+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。Wireshark 过滤 http.request.uri contains "i.php" and http.response and not frame contains "denied"、AES-CBC key 05df244d../iv 1158aa.. 与测试密文 cOMb/w12MUUCZQdVdB1cXQ==、volatility imageinfo/filescan/dumpfiles -Q 0x000000013fbf5f20/netscan 与 Mfpmp.exe 路径异常判断、bwmforpy3.py decode 均与正文一致。未验证点：从 PCAP 导出前端 JS 取 key/iv 的细节正文未展开（key/iv 直接在解密脚本中给出），卡内已用「通常」表述；正文自述恶意 IP 未最终确认，卡内未写结论；全部命令未复跑。
url: /docs/ctf/forensics/ctf-forensics-pcap-frontend-aes-login-password-and-memory-anomalous-process-trace/
draft: false
kb_aliases:
- 流量里还原前端加密口令
- http object 导出 JS 取硬编码密钥
- 排除 denied 定位成功登录
- Volatility netscan 异常进程路径
- 镜像流量数据泄露溯源
---

## 一句话结论

镜像流量里出现「登录接口高频访问 + 请求体密码是 base64 密文」时，先用 Wireshark/tshark 过滤出**响应不含 denied** 的那批请求锁定成功登录，再从同一份 PCAP 的 HTTP 对象里导出前端 JS，把其中的 AES key/IV（通常硬编码在 `encrypt` 函数里）搬进 Python 复现解密，即可还原明文口令；同案的办公机内存镜像则用 Volatility `imageinfo → filescan → dumpfiles → netscan` 交叉比对，抓出「进程名合法但可执行文件路径不在 `System32`」的可疑外联进程。

## 原理

- **前端加密不保护传输**：页面用 JS 对密码做 AES 加密再提交，密钥/IV 必然随 JS 一起下发，属于「混淆而非机密」。拿到 JS 就能离线解密所有同站点的历史密文。
- **高频访问不等于攻击成功**：爆破会产生大量失败登录（响应含 `denied`/`failed` 等字样），真正有价值的样本是**成功那条**。用「URI 匹配登录接口 + 有响应 + 帧内容不含失败关键字」的组合过滤，可直接把成功请求筛出来，这比逐条翻包高效得多。
- **数据库层可二次确认**：除 HTTP 层外，抓包通常同时含 MySQL 协议流量，`mysql.query` 过滤能看到实际执行的查询与返回，用来判断攻击者到底取走了哪些表/列。
- **内存镜像的进程路径基线**：合法 Windows 系统进程应当位于 `C:\Windows\System32\`；`netscan` 给出「进程名 + 本地/外联 IP + 端口」，`filescan` 给出「文件对象路径」，把两者按进程名对齐，凡是同名进程的路径出现在 `Temp`、`Users\Public`、`ProgramData`、盘符根目录等位置的，基本可判为伪装进程。本题即 `Mfpmp.exe`（正常应为 `c:\windows\system32\mfpmp.exe`）出现在异常路径并对外连接。
- **压缩包与图片也可能藏密码**：泄露包常常加了密，密码藏在同案的图片（盲水印）、聊天记录、邮件、内存残留字符串里；本题的拓扑图压缩包密码来自另一张图片的盲水印解码结果。

## 触发条件

- 有完整的镜像流量（PCAP/PCAPNG），其中包含登录接口的请求与响应，且密码字段为前端加密后的密文。
- 前端 JS 可从同一 PCAP 的 HTTP 响应中导出（或能从站点直接获取），且密钥/IV 硬编码在 JS 中（非服务端下发的一次性密钥）。
- 有对应的主机内存镜像或磁盘镜像，可用于定位恶意进程与落地文件。
- 存在加密压缩包时，密码线索（盲水印图、日志、邮件、内存字符串）在同批证据内可获取。

## 利用步骤

1. 粗看流量分布：按 HTTP 请求 URI 统计，锁定被高频访问的登录接口（如 `i.php`）。
2. 抽一条请求-响应对，确认密码字段是密文（base64/hex 形态），响应里有成功/失败标志。
3. 用组合过滤只留成功样本：`http.request.uri contains "<登录接口>" and http.response and not frame contains "denied"`。
4. 从 PCAP 导出 HTTP 对象（`File → Export Objects → HTTP`），取回页面 JS；搜索 `AES`、`CryptoJS`、`key`、`iv`、`encrypt`，抠出算法（模式/填充/base64 编码顺序）与硬编码的 key、iv。
5. 用 Python（pycryptodome）复现同一算法解密请求体中的密文，得到明文口令；再用 `mysql.query` 过滤核对攻击者执行的查询与返回字段，确定泄露的数据范围。
6. 内存侧：`volatility -f <镜像> imageinfo` 确认 profile → `filescan` 导出文件对象列表 → 对可疑压缩包/文档 `dumpfiles -Q <物理地址> -D ./output/` 落地（落地文件常无扩展名，按文件头 `PK`/`Rar!` 手动修正）→ `netscan` 列出外联连接。
7. 把 `netscan` 的进程名与 `filescan` 的路径对齐，找出路径不符合系统基线的同名进程，与 HTTP 层的时间线交叉印证。
8. 若证据含加密压缩包，先解决密码（盲水印解码：`python bwmforpy3.py decode <原图> <水印图> <输出>`），再解包取拓扑图/flag。

## PoC

筛选成功登录（Wireshark display filter）：

```text
http.request.uri contains "i.php" and http.response and not frame contains "denied"
```

复现前端 AES-CBC 解密（密钥/IV 来自导出的 JS）：

```python
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = binascii.unhexlify('05df244d45e1b157100baccff7fadae5')
iv  = binascii.unhexlify('1158aa515ed5b2c9e3409181c27cce78')

def decrypt_password(b64_ct):
    ct = binascii.a2b_base64(b64_ct)
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size).decode()

print(decrypt_password('cOMb/w12MUUCZQdVdB1cXQ=='))
```

内存镜像取证：

```bash
volatility -f Mem.raw imageinfo
volatility -f Mem.raw --profile=Win7SP1x64 filescan > files.txt
volatility -f Mem.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000013fbf5f20 -D ./output/
volatility -f Mem.raw --profile=Win7SP1x64 netscan
```

```text
判断要点：netscan 中的进程名与 filescan 中同名文件的路径是否一致；
本题 Mfpmp.exe 正常应在 c:\windows\system32\，实际路径明显不符，且存在对外连接。
```

## 变体与关联

- 变体（前端加密算法）：不一定是 AES-CBC，也可能是 RSA（公钥加密，需找私钥或改包绕过）、SM4、DES、甚至自写置换；思路一致——从 JS 还原算法与常量。
- 变体（无 JS 可导出）：密文可用已知明文攻击（弱密钥/固定 IV）或直接改包把密文换成「已知口令的密文」重放（若服务端不复用 nonce）。
- 变体（进程基线）：除路径外还应对比 `netscan` 的父进程、`pstree`、`malfind`（注入内存段）、`cmdscan/consoles`（历史命令）与 `shimcache`；路径不符只是最直观的一类信号。
- 关联：[[ctf-forensics-volatility-filescan-wallpaper-atbash-cmdscan]]（同一套 filescan + dumpfiles 的落地取证手法）、[[ctf-forensics-http-c2-aes-init-png-text-command-channel]]（流量里的 AES key/IV 还原思路）、[[mobile-miniprogram-custom-aes-key-sign-recompute-id-enumeration]]（前端 JS 硬编码密钥这一根因在移动端的同类表现）。
- 边界：若前端密钥由服务端每次会话下发（响应里带 key），历史密文无法用单一 key 批量解密，需要逐会话配对；若 PCAP 未抓到成功登录那一条（只有请求无响应），需换用数据库层或日志侧证据。

## 检测与防御

- 传输层：前端加密不能替代 TLS；登录必须走 HTTPS 且启用 HSTS，避免口令密文与 JS（含密钥）在明文流量中同时出现。
- 前端设计：不要把可逆加密的密钥硬编码进 JS 并当作安全措施；如需防重放，应由服务端下发一次性 challenge 并做签名校验。
- 主机侧：监控系统目录外出现的系统同名进程（`Mfpmp.exe`、`svchost.exe`、`lsass.exe` 等），尤其是 `Temp`/`Users\Public`/`ProgramData` 路径；对 `netscan` 中陌生外联 IP 做情报比对。
- 应急取证：镜像流量与内存镜像应同时留存，HTTP 对象、MySQL 查询、进程列表三侧交叉印证，避免只凭单侧证据下结论。
