---
id: ctf-forensics-dns-a-base64-label-dedup-reassemble
title: DNS A 查询子域携带 Base64 分片：固定偏移提取、去重拼接后还原命令会话与 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: dns-a-query-base64-label-dedup-reassembly
aliases:
- 武功山杯 龙鳞石阶
- DNS 外带 base64
- 子域编码外带
- dns.pcapng 分析
- DNS A 查询分片
tags:
- ctf
- forensics
- dns
- exfiltration
- base64
- pcap
- wireshark
- tshark
- covert-channel
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:21:43+08:00'
  notes: 已对照原文与全部25张图核对：dns过滤与base筛选（图17-18）、导出分组解析结果（图19）、line[12:23]提取11字节base64分片（图21）、去重拼接Base64解码得到whoami/root/ls/cat flag及flag{WuGongShan_Welcome_Yooooou}（图22）均一致。未验证点：未重新解析pcap；固定偏移仅适用原文导出格式，卡内已注明。
---

## 一句话结论

攻击者把命令输出按块 Base64 编码后塞进 DNS A 查询的子域（形如 `base<base64分片>.ctf.org.cn`），Wireshark 过滤 `dns` 即可看到大量标准查询；导出分组解析结果后按固定偏移截取查询名中的数据段，去掉重复分片再拼接，Base64 解码即还原 `whoami`、`ls /`、`cat /flag` 的会话与 flag。

## 原理

- **DNS 外带通道**：DNS 查询名可携带任意合法标签字符，攻击者把数据编码进子域标签，向自己的权威 DNS 发送 A 查询；即使响应只是 `127.0.0.1`，查询名本身已经把数据带出。本例每个查询名为 `base` + 11 字符 Base64 分片 + `.ctf.org.cn`。
- **分片与重复**：被外带的输出被切成多个 Base64 片段，每片段对应一次 A 查询；抓包中同一片段会出现多次（重传/重复请求），直接拼接会产生重复字节，需要按出现顺序去重。
- **抓包特征**：Wireshark 显示大量发往 `114.114.114.114`/`192.168.0.100` 的 DNS 标准查询，查询名都是 `<base64>.ctf.org.cn`，响应为 `A 127.0.0.1`；按 `dns` 过滤、再按查询名包含 `base` 过滤可缩小范围。
- **提取方式**：把分组解析结果导出为文本（Wireshark“导出分组解析结果”），每行形如 `... <base64>.ctf.org.cn: type A, class IN`；原文脚本用 `line[12:23]` 截取 11 字节数据段。偏移量取决于导出格式，需按实际行首内容调整（也可用 tshark `-T fields -e dns.qry.name` 直接取查询名）。
- **解码**：去重后的 Base64 片段拼接成一个字符串，Base64 解码得到多行文本，包含 `whoami`/`root`/`ls /`/`cat /flag` 及 `flag{WuGongShan_Welcome_Yooooou}`；说明这是一次通过 DNS 通道执行的命令会话。
- **为什么成立**：出站 DNS 通常被放行，查询名没有被内容检查；数据编码在合法字符集内，且没有长度/频率异常检测时，24 小时内的 DNS 日志就完整记录了外带内容。

## 触发条件

- 获得包含 DNS 流量的 pcap/pcapng，目标是某个域名（本例 `ctf.org.cn`）的 A 查询，子域带 Base64 特征。
- 查询名标签长度/字符符合 Base64（`A-Za-z0-9+/=`，URL 场景可能为 `-_`），且存在重复查询。
- 可用 Wireshark 导出分组解析结果，或用 tshark 按字段提取 `dns.qry.name`。
- 知道分片在查询名中的固定偏移/前缀（本例前缀 `base`，数据段 11 字符；不同题目需先观察样本）。

## 利用步骤

1. 用 Wireshark 打开 pcap，过滤 `dns`，观察查询名是否呈 `<base64>.ctf.org.cn` 形式；再用 `dns.qry.name contains "base"`（或 `frame contains "base"`）缩小到数据查询。
2. 导出分组解析结果（Wireshark：文件 → 导出分组解析结果 → 纯文本），或用 tshark 导出查询名字段。
3. 编写脚本逐行筛选包含 `.ctf.org.cn: type A, class IN` 的行，按固定偏移截取数据段（原文 `line[12:23]`，取 11 字节）。
4. 按抓包顺序输出去重（相邻/全局重复片段只保留一份），把片段拼接成一个 Base64 字符串。
5. Base64 解码，得到命令输出/会话文本，提取其中的 flag；若解码失败，检查片段顺序、是否有遗漏或前缀未剥离干净。

## PoC

原文提取脚本：

```python
with open('dns.txt', 'rb') as f:
    for line in f:
        if b".ctf.org.cn: type A, class IN" in line:
            print(line[12:23])
```

替代的 tshark 提取（更稳，不依赖导出文本偏移）：

```bash
tshark -r dns.pcapng -Y 'dns.flags.response == 0 && dns.qry.name contains "ctf.org.cn"' \
       -T fields -e frame.number -e dns.qry.name
# 取查询名第一段标签，去掉固定前缀 "base"，按 frame.number 排序后去重拼接
```

CyberChef：拼接后的字符串 → From Base64 → 得到 `whoami / root / ls / ... / cat /flag / flag{...}`。

要点：片段去重和顺序是关键；固定偏移 `line[12:23]` 只适用于原文导出格式，换工具需重新确认偏移。

## 变体与关联

- **记录类型变体**：数据也可放在 DNS TXT、CNAME、AAAA 记录；TXT 常见“编号+Base64 分片”，需按编号排序（见同族卡 `ctf-forensics-dns-txt-chunk-reassembly-jar-validator`）。
- **编码变体**：Base32（无 `+/`，适合域名标签）、hex、URL-safe Base64；解码前需还原字符集。
- **多标签/多级子域**：数据可分布在多个标签或多个子域层级，提取时需按 `dns.qry.name` 全名按 `.` 切分并还原顺序。
- **同类流量分析**：`ctf-forensics-soc-dns-tunnel-base32-pat-exfil` 从 SOC 日志中的 DNS 解析事件还原 base32 令牌，与本卡从 pcap 查询名还原 Base64 命令会话的数据源不同。

## 检测与防御

- 出站 DNS 只允许经内部解析器，阻断直连外部 DNS；对未知域名/高熵长标签做检测（长度、字符集、查询频率、同域名多子域）。
- 记录并保留 DNS 查询日志（含完整 qname），用于事后还原外带数据；部署 DNS 隧道检测规则（长标签、编码特征、响应固定为 127.0.0.1 等）。
- 主机侧限制非必要进程发起 DNS 查询；对异常 `nslookup`/`dig`/自定义 DNS 客户端行为告警。
- 事件响应时按本卡方法提取查询名分片、去重解码，还原攻击者执行的命令与窃取内容。
