---
id: defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois
title: APT 域名基础设施拓线：单 IOC 经父域/IP 被动 DNS，叠加正则+日期+注册商+ASN 过滤迭代扩线，再用 WHOIS 富化与公开报告归因
type: scenario
domain: defense
path: defense/detection
technique: apt-domain-infrastructure-pivot-regex-whois
tags:
- threat-hunting
- detection
- osint
- passive-dns
- whois
- domain
- apt
- infrastructure
- ioc
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T01:04:39+08:00'
  notes: 已对照原文与35张图核对：初始域 docs.mofa-services-server.top→188.114.97.3/Cloudflare ASN13335（图2/3，801666666条）、父域→91.195.240.123/SEDO ASN47846 first_seen 2024-03-20（图4）、IP反查770427条（图5）、regex+first_seen窗口缩到7条（图6/9）、JPATH response.records[*].domain（图8，正文另写 query 字段，卡内已注明二选一）、WHOIS 6/7 NameSilo 2024-03-19 04:09:56–04:10:08（图11）、逐轮放宽（5→11→3→9条，图13/15/17/19）与 BlackBerry/Group-IB 归因均与正文一致。PoC 为查询参数与本地正则示例，未执行外部查询。与 sister 卡为拓线方法与仿冒模式两个不同技术面，与攻击者侧 WHOIS 反查等候选不同场景，非重复。无 affected_versions（狩猎方法论无版本区间）、无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
url: /docs/defense/detection/defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois/
draft: false
kb_aliases:
- APT 域名拓线
- 被动 DNS 关联分析
- 域名基础设施狩猎
- SilentPush 高级查询
- WHOIS 批量富化
- 新注册域名关联
- 域名 IOC 扩展
---

## 一句话结论

从一个域名 IOC 出发做被动 DNS：子域解析到 Cloudflare 共享 IP 时结果量巨大，改查父域及其 IP；再用「域名命名正则 + first_seen 日期窗口 + ASN/托管商 + WHOIS 注册商/注册时间」逐层收窄，每轮保留已建立的共性并放宽一个维度继续扩线，就能把单个指标扩成数十个同基础设施域名，最后用注册时间、命名主题与公开报告归因到具体 APT。

## 原理

- **为什么从父域入手**：攻击者的子域（如 `docs.mofa-services-server[.]top`）可能直接解析到 Cloudflare（ASN 13335）这类共享代理，单个 IP 可对应数亿域名，无法直接用于关联；父域通常由同一实体控制、保护更少，查询父域得到其真实托管 IP（如 `91.195.240[.]123`，SEDO，ASN 47846，first_seen 2024-03-20）后再做被动 DNS，结果量会显著下降（本例 770427 条）。
- **正则 + 日期窗口收窄**：攻击者批量注册时常复用命名模板。把已知域名的结构抽象为 `^[a-z]{1,}\-[a-z]{1,}\-[a-z]{1,}\.top$`（三个连字符分隔的小写单词 + `.top`），并限定 `first_seen` 在已知注册日 ±2 天（2024-03-18 ~ 2024-03-22），770427 条记录可缩到 7 条。
- **JSON 提取**：查询结果是 JSON 数组，用 CyberChef 的 JPATH 表达式 `response.records[*].domain` 只取域名字段，便于下一步批量处理。
- **WHOIS 批量富化建立共性**：对 7 个候选批量查 WHOIS，发现其中 6 个注册商为 `NameSilo`、创建时间集中在 2024-03-19 的 04:09:56–04:10:08（几分钟内批量注册），而 `luxury-get-away[.]top` 主题与时间不符被排除。此时 6 个域名已共享：政府/巴基斯坦主题、三单词连字符命名、`.top`、NameSilo、同 IP/ASN、同注册时间。
- **逐维放宽的迭代扩线**：保留 WHOIS 注册商与时间，先放宽 IP 为「任意 SEDO/ASN 47846 上的域名」，再加入关键词正则（`nitb|pk|paki(stan|)`），得到 5 条并新增 `govt-pk[.]com`、`moma-gov-pk[.]org`；把新关键词并入正则（`gov|govt|government|moma`）得到 11 条；再换 `gov-pk|govpk` 得到 3 条；最后完全去掉 ASN 限制得到 9 条（新增 EP、NADRA、PTA 等主题）。每次只放宽一个维度，既控制结果量又避免漏掉分支。
- **为什么有效**：域名注册是批量行为，注册商、创建时间、命名模板、托管 IP/ASN、目标主题这些元数据会留下稳定指纹；被动 DNS 与 WHOIS 让这些指纹可离线关联，公开报告则提供最后的归因锚点。
- **归因**：把扩出的域名与公开报告中的已知样本域（BlackBerry、Group-IB 对 SideWinder 的报告）比对命名模式、目标国家与政府实体主题、子域使用方式、注册商等共性，从而把新基础设施与已知组织关联。

## 触发条件

- 手上至少有一个初始域名 IOC（如社交平台/厂商披露的恶意域名）。
- 能访问被动 DNS（如 SilentPush PADNS）与批量 WHOIS 查询；可接受一定查询配额与结果量。
- 能推断或猜测攻击者的命名模式与注册时间窗口；未知时可从父子域差异、已知同族域名样本中归纳。
- 目标域名可能使用 CDN/隐私注册，需准备父域、证书透明度、DNS 历史等替代关联维度。

## 利用步骤

1. **初始 IOC**：确定起始域名（示例 `docs.mofa-services-server[.]top`），先做被动 DNS，记录解析 IP、ASN、first_seen/last_seen。
2. **判断共享基础设施**：若 IP 属于 Cloudflare 等共享代理（结果量百万/亿级），不要在该 IP 上硬筛，转而查询父域。
3. **父域被动 DNS**：查父域的解析记录，得到其直接托管 IP（示例 `91.195.240[.]123`/ASN 47846）。
4. **IP 反查 + 过滤**：对该 IP 做被动 DNS，得到候选域名集；用域名正则（命名模板）、first_seen 日期窗口、ASN/托管商过滤，把结果缩到几十条以内。
5. **提取与富化**：用 JPATH（`response.records[*].domain`）或 Python 提取域名列表，批量 WHOIS 获取注册商与创建时间。
6. **建立共性清单**：整理命名、TLD、注册商、注册时间、IP/ASN、目标主题等共性，排除离群项。
7. **迭代扩线**：每轮保留共性、放宽一个维度（IP→任意同 ASN、固定 TLD→任意 TLD、删除 ASN、扩展关键词正则），记录新增域名并去重。
8. **子域扩展**：对扩出的父域查子域记录，寻找与初始域名同构的子域命名（如 `docs`/`pmo` 前缀）。
9. **归因与输出**：与公开 APT 报告比对；整理 IOC（域名/子域）、注册商、时间线与关联证据，交给检测与封禁。

## PoC

查询参数示例（SilentPush 高级查询，其他平台可映射为等价字段）：

```text
qtype=A, qanswer=91.195.240.123,
regex=^[a-z]{1,}\-[a-z]{1,}\-[a-z]{1,}\.top$,
first_seen_after=2024-03-18, first_seen_before=2024-03-22
```

```text
domain_regex=^([^\.]{1,}\-|)(nitb|pk|paki(stan|))(\-[^\.]{1,}|)\.[a-z]{1,}$
registrar=NameSilo, whois_date_after=2024-03-01, asnum=47846
```

JSON 提取与本地过滤示例：

```python
import json, re

records = json.load(open("padns.json"))["response"]["records"]
doms = [r["domain"] for r in records]
pat = re.compile(r"^[a-z]{1,}-[a-z]{1,}-[a-z]{1,}\.top$")
print([d for d in doms if pat.match(d)])
```

CyberChef JPATH：`response.records[*].domain`（或 `response.records[*].query`，取决于返回字段）。

## 变体与关联

- **变体（数据源）**：被动 DNS 之外可用证书透明度日志（crt.sh）、DNS 历史、威胁情报平台的托管/注册商字段、URLScan 等做同类关联。
- **变体（过滤维度）**：注册商、注册商邮箱、nameserver、注册时间窗、证书 issuer、IP 段/ASN、页面 favicon 哈希均可作为扩线条件。
- **变体（CDN 场景）**：目标全站 Cloudflare 时，父域/源站 IP/证书/WHOIS 比共享 IP 更有价值。
- 关联：[[defense-detection-government-domain-impersonation-subdomain-delayed-activation]]（同一活动观察到的政府域名仿冒与子域潜伏模式）、[[defense-detection-cobaltstrike-domain-fronting-config]]（另一类域名基础设施特征）、[[pentest-recon-dns-axfr-ptr-internal-topology]]（DNS 侦察视角）。
- 边界：攻击者使用不同注册商/隐私保护/独立 IP 时会削弱关联；过度放宽条件会导致结果爆炸，需要人工复核与多源交叉。

## 检测与防御

- **狩猎**：定期用已知 APT 命名模板与注册商/时间窗扫描新注册域名；对政府/军事/关键基础设施相关关键词做 NRD（新注册域名）监控；对父域注册后 4–8 周才出现子域的模式专项排查（见关联卡）。
- **防御**：邮件网关与 DNS 层拦截已知恶意域名/子域；对仿冒政府域名的邮件与文档做隔离；启用 DMARC/SPF/DKIM 减少直接仿冒；员工培训识别政府主题钓鱼。
- **响应**：确认恶意域名后封禁并在代理/DNS 日志回溯历史访问；提取注册商/时间线证据，与公开报告和 CERT 共享。
