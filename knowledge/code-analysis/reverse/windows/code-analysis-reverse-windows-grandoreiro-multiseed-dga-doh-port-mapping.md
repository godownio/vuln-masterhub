---
id: code-analysis-reverse-windows-grandoreiro-multiseed-dga-doh-port-mapping
title: Grandoreiro 多种子 DGA：日期/月/日驱动 366 个顶级域、31 组 26 字符替换与 12 功能种子，域名经 DoH 解析并按 IP 前四位映射端口
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: grandoreiro-multiseed-dga-doh-port-mapping
aliases:
- Grandoreiro DGA
- 多种子 DGA
- 366 顶级域
- 26 字符替换
- DoH 解析 C2
- IP 端口映射
- dns.google resolve
tags:
- malware-analysis
- reverse
- dga
- grandoreiro
- doh
- c2
- banking-trojan
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T19:21:53+08:00'
  notes: 已对照原文与图 17-20 核对：图 17 DGA 流程图（day-of-year→两套各 366 apex 域、day-of-month→31 组 26 字符替换、月份两位→3 字符/数字、功能模式→12 seeds、xretsmzrboitzia→wondbbhonandhnd、DoH→15.229.211.175、digit-to-digit→4917）与卡一致；图 18 的 12 个域名与卡 PoC 列表逐条一致；图 19 四个巴西 IP 与卡一致；图 20 感染国家占比为背景。注意：正文写样本含 14 个种子/每天 14 个域名，图 17 写 List of 12 seeds，卡标题用 12、正文用 14，两者均有原文依据但卡内未说明差异，建议后续统一为“12（图）/14（正文）”，不影响技术正确性。原文无版本，已 --clear。dedup 仅自匹配；dup-scan(19:10)无本卡 pair。
---

## 一句话结论

Grandoreiro 的 DGA 用当前日期驱动多张表：一年 366 天映射到两组各 366 个顶级域（主 C2 与功能 C2），月份两位数字按“每数字→3 字符”的硬编码表扩展后与种子拼接，月内每天再选一组 26 字符替换表生成子域名；每个样本带主种子与一组功能种子（原文 14 个种子，每天生成 14 个域名）。域名通过 `https://dns.google/resolve?name=<C2>` 做 DoH 解析以绕过 DNS 阻断，端口由解析出的 IP 前四位数字经自定义数字映射得到。

## 原理

- **顶级域选择**：DGA 从域名的顶级开始，为一年中的每一天映射一个顶级域。有两套映射：主 C2 用一套、所有功能专属 C2 用另一套；732 个顶级域中只有 337 个唯一。原文 2024-04-17 的主顶级域是 `dnsfor[.]me`，次顶级域是 `neat-url[.]com`。
- **月份数字扩展**：把主种子（原文 `xretsmzrb`）与两位格式化的当前月份拼接；每个数字用三个硬编码字符替换，原文数字 `0`→`oit`、`4`→`zia`，于是 4 月得到 `xretsmzrboitzia`。
- **每日子域名替换**：对每个月中的每一天，DGA 有一张自定义的“字符→字符”替换表；原文 17 号经 26 个字符的替换迭代后得到子域名 `wondbbhonandhnd`。
- **多种子**：样本包含一个主种子（配置丢失时的默认）和一组功能专属种子；原文样本有 14 个不同种子，每天生成 14 个候选 C2 域名，把不同 C2 任务分给多个操作者（MaaS）。种子会轮换，感染几周后可能只剩主种子的 C2 存活。
- **DoH 解析**：计算出的域名通过 `https://dns.google/resolve?name=<C2 server>` 用 DNS over HTTPS 解析，避免明文 DNS 被阻断/监控；拿到 IP 后，取 IP 的前 4 位数字，按自定义数字到数字映射生成 4 位端口号（原文示例 `15.229.211.175` → 端口 `4917`）。
- **为什么这样设计**：多套顶级域 + 每日替换 + 多种子让基于域名黑名单/固定 DGA 模型的检测困难；DoH 让 DNS 查询看起来是到 Google 的正常 HTTPS；端口不固定进一步增加扫描/封锁难度。
- **边界**：DGA 依赖日期、种子和表；一旦逆向出表，可离线枚举未来/过去域名。DoH 可用性、域名注册/解析状态、种子轮换会影响实际可用 C2；原文确认 2024-04-17 至少有 4 个域名解析到巴西 IP。

## 触发条件

- 拿到 Grandoreiro 样本，能提取主种子、功能种子列表、366 个顶级域表、31 组 26 字符替换表、端口数字映射表。
- 知道目标日期（DGA 按天变化）；样本/配置中可能有默认种子。
- 样本具备网络访问，能向 `dns.google` 发 HTTPS DoH 查询。
- 分析者需要 Python/脚本环境复现 DGA。

## 利用步骤

1. 从样本/配置中提取种子列表与各张表（顶级域、替换、端口映射）。
2. 按当前日期计算：取一年中的第几天选顶级域；取月份两位数字，按 3 字符/数字表扩展；与主种子拼接。
3. 取月内第几天选 26 字符替换表，对拼接串做替换得到子域名。
4. 拼接为完整域名（主 C2 与各功能 C2 分别计算），得到当天 12–14 个候选域名。
5. 用 DoH 解析：`https://dns.google/resolve?name=<domain>`，取 `Answer` 中的 A 记录 IP。
6. 取 IP 前 4 位数字，按数字映射表生成端口；拼接 `http://<IP>:<port>/` 作为 C2。
7. 验证：与样本实际流量/OIOC 对比；原文给出 2024-04-17 的 12 个域名与 4 个巴西 IP。

## PoC

原文 2024-04-17 计算出的部分域名（已做 defang）：

```text
lndddkhnnndandhnd.dnsfor[.]me
bfnwhnonakdandhnd.dnsfor[.]me
noowbnwqnbdandhnd.dnsfor[.]me
kbnbnnfokddandhnd.dnsfor[.]me
annboobkbddandhnd.dnsfor[.]me
fdhbonbadwbandhnd.dnsfor[.]me
bnonbdnkbadandhnd.dnsfor[.]me
bkbbalbnbandhnd.dnsfor[.]me
nohbbdnowandhnd.dnsfor[.]me
bnkndhdabandhnd.dnsfor[.]me
bkdnbhdandanhdnd.dnsfor[.]me
wondbbhonandhnd.neat-url[.]com
```

解析出的部分 IP（原文）：

```text
18.231.181[.]227
18.231.158[.]159
15.228.245[.]103
15.229.211[.]175
```

DoH 查询形态：

```text
https://dns.google/resolve?name=<C2 domain>
```

端口映射示意（原文 `15.229.211.175` → `4917`）：取 IP 前四位 `1522`，按自定义数字映射逐位转换得到 4 位端口。

## 变体与关联

- **主 C2 vs 功能 C2**：两套顶级域表、不同种子；Outlook 收集模式使用 DGA 种子 7 做数据外泄，日志/状态仍发主 C2。
- **其他 DGA**：Festi 的日期种子 + `chrfun` 短 `.com` DGA（`code-analysis-reverse-windows-rootkit-dga-date-seed-chrfun`）机制不同；本卡是多表/多种子/DoH。
- **检测逃避**：DoH 让 DNS 监控失效；可用 HTTPS 流量分析、SNI/证书、IP 归属与端口不固定特征补偿。
- **配置种子**：若 `.CFG` 存在，可能覆盖默认种子；分析时要同时看配置与硬编码。

## 检测与防御

- **网络检测**：监控到 `dns.google` 的 DoH 查询及其中 `name=` 参数；对解析结果 IP 的前四位与端口映射做关联；对高熵子域名/多级域做 DGA 评分。
- **域名侧**：DGA 域名通常未注册或短期注册；可做 sinkhole/预注册、证书透明度监控、被动 DNS 关联。
- **主机侧**：监控进程读取系统日期、拼接域名、向 DoH 服务发请求；内存中出现 366 域/替换表；样本字符串解密后可提取种子/表。
- **防御**：封锁未知 DoH 解析器或强制企业 DNS；对银行/税务域名做白名单；EDR 拦截可疑银行木马加载器；邮件网关拦截税务/发票诱饵。
- **分析**：逆向出表后可批量生成历史/未来域名，用于 IOC 扩展与 C2 追踪。
