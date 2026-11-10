---
id: defense-incident-response-expired-domain-hijack-ownership-verification
title: 过期/被劫持域名的归属核验：WHOIS 到期 + 工信部 ICP 备案 + 证书与内容交叉验证，避免把已易主域名算作原单位资产
type: scenario
domain: defense
path: defense/incident-response
technique: expired-domain-hijack-ownership-verification
aliases:
- 域名归属核验
- 过期域名被劫持
- 备案过期判定
- 域名易主识别
- 安全情报归属研判
- 工信部备案核验
tags:
- incident-response
- threat-intel
- attribution
- osint
- whois
- icp-filing
- domain-hijack
- due-diligence
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V475
  verified_at: '2026-11-10T17:05:21+08:00'
  notes: 已对照原文及图7-8核对：域名imaponline.com.cn已过期而第三方备案仍显示事业单位、QLXFDC.COM为clientHold状态、算命站点使用Let's Encrypt免费证书，均与原文一致；与attacker-ip-attribution卡方向相反（域名是否仍属原单位 vs 攻击IP归因），判 related 保留；原文未给工信部备案缺失的直接截图，属流程归纳，未实测。
---

## 一句话结论

威胁情报里"某单位站点被劫持"有可能其实是域名到期未续费后被抢注或停放：先用 WHOIS 看注册到期时间、注册人和域名状态，再到工信部备案系统核对备案是否仍存在（第三方备案查询站数据滞后不可信），结合证书类型与页面内容是否偏离单位业务做交叉验证，才能判断该域名还能不能归属原单位。

## 原理

- **域名生命周期**：到期未续费 → 赎回期 → 删除 → 被他人抢注。抢注后注册人、NS、解析 IP 全部更换；WHOIS 的到期时间、更新时间、注册人是否为空、域名状态（如 clientHold、clientTransferProhibited）是判断是否易主的直接证据。
- **备案绑定关系**：ICP 备案按"域名 + 主体"登记。域名易主或主体注销后，工信部备案库中该域名备案不再存在。第三方备案查询/站长工具是缓存数据，更新滞后，会把已失效的备案继续显示在原单位名下，从而把黑产站点错误归属给单位。
- **证书线索**：抢注者/停放页常用 Let's Encrypt 等免费 90 天证书，证书 CN 往往只有域名、无组织信息，签发时间很新；原单位通常使用带组织信息的商业证书或国密证书。证书只能作辅助，不能单独定性。
- **内容与基础设施线索**：页面内容与单位业务不符（如事业单位出现算命、星座、博彩内容）、解析 IP 在境外/香港、端口与指纹和单位其他站点不一致。
- **为什么必须交叉验证**：单看内容异常可能是服务器被黑（域名仍归原单位，应按入侵处理）；单看备案缺失可能是备案信息尚未同步；只有"注册信息变化 + 备案不存在 + 内容/证书异常"同时成立，才能判定域名已不归属原单位。
- **情报意义**：归属算错会把无关黑产站点报成单位安全事件（误报），或把真正被黑的单位资产排除在外（漏报）。

## 触发条件

- 正在做威胁情报收集或资产归属研判，需要对一个疑似被劫持的域名定性。
- 能访问 WHOIS、工信部 ICP 备案系统（可能含文字点击验证）和浏览器证书查看器。
- 有单位业务背景可用于内容比对；掌握域名解析 IP 归属地查询手段。

## 利用步骤

1. WHOIS 查询：注册时间、到期时间、更新时间、注册人（是否为空/隐私保护）、域名状态、NS。到期时间早于当前时间，或注册人/NS 近期变更，高度可疑。
2. 工信部备案系统按域名或备案号查询主体与备案状态；遇到文字点击验证时人工完成。可先用 Hunter/FOFA 域名详情里的 ICP 字段做快速初筛，但以工信部结果为准。
3. 浏览器证书查看器看颁发者、CN/O/OU 与有效期；免费短期证书、CN 不含单位信息作为辅助信号。
4. 解析 IP 归属地/ASN，并将页面内容与单位业务比对（正常事业单位不应出现算命、星座、博彩内容）。
5. 综合定性：
   - 注册已过期/被抢注 + 备案不存在 + 内容异常 → 域名不再归属原单位，不能作为该单位资产上报；
   - 注册与备案均正常、仅内容异常 → 更可能是服务器被黑或暗链，转入应急响应排查。
6. 记录证据（WHOIS 快照、备案查询结果、证书信息、页面截图、解析记录），按情报平台要求提交。

## PoC

无 PoC（归属核验流程，不是攻击手法）。可用的最小查询命令：

```bash
whois <domain> | grep -Ei 'creat|expir|updat|registrar|registrant|status|name server'
```

核验清单：WHOIS 到期/注册人/状态 → 工信部备案主体与状态 → 证书 issuer/CN/有效期 → 解析 IP 归属地与页面内容。

## 变体与关联

- 变体一：仅 ICP 备案过期但域名注册仍由原单位持有（单位可能忘记续费备案，站点仍是自己的）。
- 变体二：域名注册过期后被抢注，备案随之消失，完全易主。
- 变体三：域名与备案都正常，只是服务器被黑/被植入暗链——归属不变，处置方式完全不同。
- [[defense-incident-response-attacker-ip-attribution-icp-aliyun-recovery-cross-validation]]：从攻击 IP 反查 ICP/WHOIS 把主机归到实名主体；本卡是反方向——核验"这个域名是否仍属该单位"。
- [[pentest-recon-whois-registrant-email-reverse-ip-pivot]]：WHOIS 注册人反查扩展到关联域名。
- [[pentest-recon-icp-number-spatial-engine-reverse-query]]：按备案号在空间引擎反查同主体站点。
- [[defense-incident-response-hidden-link-source-dom-triage]]：备案正常但内容异常时的暗链排查。
- 边界：隐私保护会隐藏注册人；备案系统有验证码；历史 WHOIS 需要第三方历史记录辅助。

## 检测与防御

- 资产侧：域名到期自动续费与到期告警；ICP 备案信息定期核对；证书到期监控与 Certificate Transparency 日志监控（如 crt.sh）。
- 情报侧：对"单位域名"定期批量 WHOIS + 备案复查，发现到期或备案消失即从资产台账剔除并标记易主风险；提交情报前必须完成归属核验。
- 防御：开启域名锁（clientTransferProhibited/registrar lock）、保护注册邮箱与账号、启用多因素认证，防止域名被转移或抢注。
