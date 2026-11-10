---
id: ctf-forensics-dns-binary-label-qr-password-transactionid-pgp
title: DNS 隧道隐写：二进制子域名还原二维码口令 + 按事务 ID 分流 zip/PGP，私钥 rev+hex+rev 修复后解密
type: scenario
domain: ctf
path: ctf/forensics
technique: dns-binary-label-qr-pgp-multichannel
aliases:
- CISCN 2024 DNS
- DNS 二进制子域名
- dns.id 分流
- 二维码得到压缩包密码
- rev+hex+rev 修复 PGP 私钥
- download.dat PGP
tags:
- ctf
- forensics
- pcap
- dns
- exfil
- binary-label
- qr
- zip
- pgp
- gpg
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:38:07+08:00'
  notes: 已对照原文与全部36张图片核对：dns.qry.name 为二进制标签(如1111111101001011111.baidu.com)、二维码内容15f9792dba5c(版本1,L,掩码3)、dns.id 0x6421/0x4500 双通道分流、rev→hex→rev 私钥修复(CyberChef 输出 eab9f5ae-0b9e)、gpg 1024-bit RSA key ID 51457644D5D8B1B5 解出 flag{79830a47-faf7-4067-b585-145776f833cd}，均与截图一致。二进制标签→二维码点阵的每包位数/排布原文未给脚本，卡内已注明需按实际数据调整并标 confidence medium，保留合理；无版本/CVE，无 sources/URL，路径 ctf/forensics 合法。
---

## 一句话结论

PCAP 中的 DNS 查询子域名由二进制位组成（如 `1111111101001011111.baidu.com`），把每条查询的标签按顺序拼成位图/二维码可解出口令 `15f9792dba5c`；再按 DNS 事务 ID 把流量分成两路（`dns.id==0x6421` 与 `dns.id==0x4500`），一路的重组数据是加密 zip（用二维码口令解压），另一路是 PGP 密文；提供的私钥材料需经过 `rev -> hex -> rev` 处理才能被 `gpg --import` 接受，`gpg --decrypt download.dat` 即得 flag。

## 原理

- **QNAME 作为数据通道**：DNS 查询的域名标签可携带任意字符串；本题把二进制位写成 `1111111101001011111` 这类全 0/1 标签，拼成一张位图后用二维码工具（CQR/QR 生成器）还原二维码，版本 1、纠错 L、掩码 3，内容为 zip 密码。
- **事务 ID 区分通道**：同一抓包里存在两组 DNS 流量，分别使用固定事务 ID `0x4500` 与 `0x6421`；按 `dns.id` 过滤即可把两路数据分开，各自按顺序重组。
- **多载体**：一路重组为加密压缩包（密码来自二维码）；另一路 `file` 识别为 PGP 数据。PGP 私钥文件的字节被做了字符反转+十六进制（或十六进制+反转）包装，直接 import 会失败；用 CyberChef `Reverse(Char) -> From Hex(Space) -> Reverse(Char)` 还原后即可成功导入（截图输出 `eab9f5ae-0b9e...`）。
- **解密**：导入后的 1024-bit RSA 私钥（ID 51457644D5D8B1B5）可解 `download.dat`，gpg 输出 `flag{79830a47-faf7-4067-b585-145776f833cd}`。

## 触发条件

- 拿到 DNS 查询量很大的 PCAP；域名前缀是长串 0/1、Base64/Base32 等异常字符。
- 抓包中存在可区分的固定 DNS 事务 ID 或不同查询类型/目标，对应多条数据通道。
- 需要解 ZIP/密文；附件包含疑似密钥文本，可能经过 hex/反转处理。

## 利用步骤

1. `tshark -r dns.pcap -Y 'dns' -T fields -e dns.id -e dns.qry.name` 浏览查询；观察到子域名由 0/1 组成。
2. 按查询顺序提取 0/1 标签，拼接为位流/点阵图，用 CQR 或二维码生成器还原二维码并扫码，得到口令（示例 `15f9792dba5c`）。
3. 按事务 ID 分流：
   - `tshark -r dns.pcap -Y 'dns.id==0x4500' ...` 收集一路标签并重组；
   - `tshark -r dns.pcap -Y 'dns.id==0x6421' ...` 收集另一路。
4. 对第一路重组文件 `file` 识别为 zip；用二维码口令解压。另一路识别为 PGP 数据。
5. 处理私钥：CyberChef `Reverse(Character) -> From Hex(delimiter=Space) -> Reverse(Character)`，保存为 key 文件后 `gpg --import key`；确认 key ID 与加密文件匹配。
6. `gpg --decrypt download.dat` 输出 flag；如提示未知 key，检查 import 是否成功与 keyring。

## PoC

```bash
# 1) 观察 DNS 查询与事务 ID
tshark -r dns.pcap -Y 'dns.flags.response==0' -T fields -e dns.id -e dns.qry.name | head

# 2) 分流提取（按实际 ID 替换）
tshark -r dns.pcap -Y 'dns.id==0x6421' -T fields -e dns.qry.name > ch1.txt
tshark -r dns.pcap -Y 'dns.id==0x4500' -T fields -e dns.qry.name > ch2.txt

# 3) 二维码口令解 zip
unzip -P 15f9792dba5c secret.zip

# 4) 私钥 rev->hex->rev 后用 gpg 解密
# CyberChef: Reverse(Character) -> From Hex(Space) -> Reverse(Character) 后保存 key.asc
gpg --import key.asc
gpg --decrypt download.dat
# gpg: encrypted with 1024-bit RSA key, ID 51457644D5D8B1B5
# flag{79830a47-faf7-4067-b585-145776f833cd}
```

说明：二进制标签→二维码的点阵排布与每包位数需按题目实际数据调整，文章未给出完整提取脚本。

## 变体与关联

- 变体：QNAME 编码换 Base32/Base64/hex；分流条件换成查询类型（TXT/A/AAAA）、目标域名、源端口、时间窗口；二维码承载密码、密钥或直接承载 flag 分片。
- 关联卡片：[[ctf-forensics-dns-a-base64-label-dedup-reassemble]]（A 记录 Base64 标签重组去重）、[[ctf-forensics-dns-txt-chunk-reassembly-jar-validator]]（TXT 分块重组 JAR）、[[ctf-forensics-soc-dns-tunnel-base32-pat-exfil]]（Base32 PAT 隧道外传）、[[ctf-forensics-1bpp-qr-row-shift-frame-recovery]]（二维码位图恢复）。
- 边界：DNS 标签有长度/字符限制，长数据需分包编号；事务 ID 可能被复用或随机化，需先统计频次再分流；PGP 私钥有口令时需要额外爆破。

## 检测与防御

- 检测：DNS 查询名前缀为长串 0/1 或高熵字符串；同一域名的高频重复查询；单一/少数事务 ID 的批量查询；TXT/A 记录异常负载。
- 防御：出口 DNS 日志与长度/熵异常告警；限制内网直连外部 DNS；对异常 QNAME 做 DNS sinkhole；禁止客户端任意 DNS 解析。
