---
id: defense-detection-government-domain-impersonation-subdomain-delayed-activation
title: 政府域名仿冒与子域潜伏：合法政府 FQDN 作为子域前缀 + 攻击者父域后缀，父域注册约 6 周后才启用恶意子域
type: scenario
domain: defense
path: defense/detection
technique: government-domain-impersonation-delayed-subdomain
tags:
- threat-hunting
- detection
- apt
- sidewinder
- domain
- impersonation
- phishing
- subdomain
- ioc
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T01:04:41+08:00'
  notes: 已对照原文与35张图核对：govt-pk.com 仿冒 gov.pk、合法政府FQDN作子域前缀（pubad.gov.lk.govt-pk.com 等，图22共15条含孟加拉/尼泊尔/斯里兰卡）、docs 子域2024-05-01 vs 父域2024-03-20 约6周（图20）、pmo.documents-server-pk.top 2024-05-01 vs 父域2024-03-19 约6周（图21）、paknavy-govpk.info 关联 MoITT_federalemp.docx 26/66 与 cve-2017-0199 标签（图29/30/31）、PDF→密码ZIP（pmo@letter 图32、ND#2024@ 图34）、旧 SideWinder 域 NameSilo 佐证（图35）均一致。CVE-2017-0199 仅作投递背景，cve 留空合理（非本卡主题）。PoC 为本地域名结构匹配脚本未执行外部查询。与拓线方法卡为不同技术面，与仿冒登录页/域前置等候选不同链。无 affected_versions、无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。
url: /docs/defense/detection/defense-detection-government-domain-impersonation-subdomain-delayed-activation/
draft: false
kb_aliases:
- 政府域名仿冒
- 子域潜伏
- SideWinder 域名模式
- govt-pk.com 仿冒
- 父域养域
- 新注册域名过滤绕过
- 武器化文档投递
---

## 一句话结论

SideWinder 式活动用 `govt-pk[.]com` 这类仿冒政府父域承载子域，子域前缀直接拼接受害组织的真实政府 FQDN（如 `pubad.gov.lk.govt-pk[.]com` 冒充 `pubad.gov.lk`），且父域注册后约 6 周才出现首个恶意子域，疑似规避「新注册域名 <30 天」类过滤；检测要点是「合法政府域 + 可疑父域后缀」的拼接模式，以及「父域年龄 4–8 周后新增子域」的时间模式。

## 原理

- **仿冒构造**：攻击者注册与目标国家机关域名相近的父域（如 `govt-pk[.]com` 对应合法的 `gov[.]pk`），再把受害者组织的合法政府域名整体作为子域前缀：`pubad.gov.lk.govt-pk[.]com`（冒充斯里兰卡 `pubad.gov.lk`）、`investinnepal.gov.np.govt-pk[.]com`、`mod.gov.bd.govt-pk[.]com`、`lgcd.punjab.gov.pk.govt-pk[.]com` 等。邮件/浏览器里前缀看起来像官方域名，实际注册域是最后的 `govt-pk[.]com`。
- **潜伏（养域）模式**：初始域名 `docs.mofa-services-server[.]top` 的子域首次出现于 2024-05-01，而父域首次注册于 2024-03-20，相差约 6 周；扩线得到的 `pmo.documents-server-pk[.]top` 也呈现父域注册约 6 周后才出现子域的模式。一种解释是威胁行为者先在父域上"潜伏"，等域名年龄超过新注册域名过滤阈值（如 30 天）后再通过子域实施恶意活动。
- **目标与命名**：15 个子域覆盖巴基斯坦政府实体（MOD 国防部、ECP 选举委员会、CTD 反恐部、LGCD 地方政府、PUBAD 公共行政、prisons、mindef）以及孟加拉、尼泊尔、斯里兰卡的政府部门；大量使用连字符与 gov/govpk/govt-pk 等关键词。
- **投递与武器化文档**：公开报告显示 SideWinder 以政府主题武器化文档做初始访问，利用 CVE-2017-0199 远程模板注入下载 RTF/JS；本次观察中 `paknavy-govpk[.]info` 关联到 `MoITT_federalemp.docx`（多引擎 26/66，标签含 cve-2017-0199），文档伪造巴基斯坦信息技术与电信部；随后观察到 PDF 链接到密码保护 ZIP 的新变化（密码示例 `pmo@letter`、`ND#2024@`），说明投递 TTP 在演进但"文件武器化"的主线不变。
- **归因依据**：与 BlackBerry、Group-IB 公布的 SideWinder 域名集共享连字符命名、政府实体主题、巴基斯坦/斯里兰卡/尼泊尔目标、大量子域、以及部分域名使用 NameSilo 注册等特征；部分旧域名（如 `sindhpolice-govpk[.]org`、`sbp-pk[.]org`、`fia-gov[.]com`、`paknavy-gov-pk.downld[.]net`）同样在 NameSilo 注册，构成弱但有用的关联。

## 触发条件

- 防守方需要对仿冒政府/军事域名的钓鱼基础设施做检测或回溯狩猎。
- 可获得 DNS/被动 DNS、证书透明度、WHOIS 数据，或邮件网关日志。
- 已知目标组织的合法政府域名清单，才能构造"合法 FQDN 出现在子域中"的匹配规则。
- 攻击者尚未启用子域时只能看到父域，需要结合注册时间与后续监控。

## 利用步骤

1. **整理合法域名清单**：收集本单位/行业相关的政府域名（`*.gov.pk`、`*.gov.lk`、`*.gov.np`、`*.gov.bd` 等）及常见子域。
2. **匹配拼接模式**：在 DNS/被动 DNS/证书数据中搜索形如 `<legit-gov-fqdn>.<suspect-parent>` 的域名，重点看注册域（最后两段）是否为 `govt-pk[.]com`、`gov-pk[.]icu`、`govpk[.]info` 等仿冒父域。
3. **时间分析**：对可疑父域查 WHOIS 注册时间，对子域查 first_seen，计算差值；重点关注父域注册后 4–8 周内首次出现的子域。
4. **富化验证**：批量 WHOIS 注册商、NS、注册邮箱；证书透明度查证书与 SAN；被动 DNS 查解析 IP/ASN；与已知 APT 报告比对命名与目标。
5. **邮件与文档关联**：在邮件网关/沙箱中检索指向这些域名的邮件与附件；检测 CVE-2017-0199 类远程模板注入文档，以及 PDF → 密码保护 ZIP 的投递链（密码常写在 PDF 正文）。
6. **输出与封禁**：按父域、子域、投递文件哈希、发件人/邮箱整理 IOC；封禁域名并在 DNS/代理日志回溯历史访问。

## PoC

扫描拼接模式的 Python 示例（输入为被动 DNS/证书导出的域名列表）：

```python
import re
import tldextract  # 或自行按最后两段解析注册域

legit = {"pubad.gov.lk", "mod.gov.bd", "mod.gov.np", "mofa.gov.bd", "mofa.gov.np"}
suspect_parents = {"govt-pk.com", "gov-pk.icu", "govpk.info", "gov-pk.live"}

def suspicious(domain: str) -> bool:
    ext = tldextract.extract(domain)
    parent = f"{ext.domain}.{ext.suffix}"
    if parent in suspect_parents:
        return True
    # 合法政府 FQDN 作为中间标签出现，且注册域不是官方域
    return any(d in domain and not domain.endswith(d) for d in legit)

for d in ["pubad.gov.lk.govt-pk.com", "investinnepal.gov.np.govt-pk.com",
          "docs.mofa-services-server.top"]:
    print(d, suspicious(d))
```

时间模式检查：`子域 first_seen - 父域 whois_created_date` 落在约 4–8 周区间时提高优先级；示例初始域父子相差约 6 周。

## 变体与关联

- **变体（仿冒方式）**：同形异义/IDN 域名、连字符拆分（gov-pk）、拼写变体（goverment）、TLD 替换（.icu/.info/.live/.cloud）等；本卡是「合法 FQDN 作为子域前缀 + 仿冒父域」的组合。
- **变体（投递）**：CVE-2017-0199 远程模板注入文档 → RTF/JS 下载；或 PDF 链接密码保护 ZIP；密码常写在文档正文并通过邮箱/聊天传递。
- **变体（潜伏时间）**：约 6 周是本次观察值；改版可能更长或更短，应以「父域年龄 > 新注册域名过滤阈值」为一般规律。
- 关联：[[defense-detection-apt-domain-infrastructure-pivot-passive-dns-whois]]（如何从单个域名扩线到本卡的仿冒父域/子域）、[[defense-forensics-email-header-spoof-detection]]（邮件头溯源）、[[defense-forensics-chrome-extension-url-telemetry-exfiltration]]（URL 遥测取证）。
- 边界：攻击者改用完全不同命名/注册商、或子域尚未启用时，只能先监控父域并等待；不能仅凭域名相似就定性，需要域名数据+文档哈希+报告多源印证。

## 检测与防御

- **检测规则**：匹配「合法政府 FQDN + 仿冒父域」的域名结构；监控 `govt-pk`、`govpk`、`gov-pk` 等关键词与 `.icu/.info/.live/.cloud` 等 TLD 组合；对父域注册后 4–8 周新增子域的情况告警；邮件网关检测 CVE-2017-0199 文档与 PDF→密码 ZIP 链。
- **防御**：启用 DMARC/SPF/DKIM 与外部域名相似度告警；对员工开展政府主题钓鱼识别培训；对官方域名做品牌保护与域名监控（NRD 服务）；终端禁用 Office 远程模板/宏或加白限制。
- **响应**：发现仿冒域名后封禁并上报注册商/CERT；搜索邮件网关与代理日志中的历史访问与下载；隔离打开过相关文档的主机并排查后续载荷。
