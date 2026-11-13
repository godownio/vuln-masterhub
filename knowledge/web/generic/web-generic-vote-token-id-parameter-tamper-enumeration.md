---
id: web-generic-vote-token-id-parameter-tamper-enumeration
title: 投票凭证 token 改一位即视为新用户 + id/vid 选项号遍历：按参数维度计数导致无限刷票
type: scenario
domain: web
path: web/generic
technique: vote-token-id-parameter-enumeration
aliases:
- 投票 token 篡改
- 投票 id 遍历
- vid id 刷票
- Intruder 遍历投票
- 投票参数枚举
- 加位绕过次数限制
tags:
- business-logic
- vote
- parameter-tampering
- token
- id-enumeration
- intruder
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V664
  verified_at: '2026-11-13T08:17:45+08:00'
  notes: 已对照原文与案例截图核对：改token首字符5→1后响应由『今天已投太多票数』变ok（原token 5A503FAF224...，改后 1A503FAF224...，64位十六进制）、Burp Intruder遍历、刷到22748票；案例2请求 vid=173&id=3、Cookie PHPSSID=123 与 XFF 均不校验、id递增/加位、原文明确『刷之后，稳定排名第二』。修正：PoC token 原缺一个F（仅63位）已补全为1A503FAF224...；『最终排名第一』改为原文的稳定排名第二；『0-9/a-i payload』改为截图可见的 a-i 等字符；『40位十六进制』改为64位。未验证点：未复跑PoC。
---

## 一句话结论

投票请求中的身份/选项标识若由客户端提交且服务端不做签名或身份绑定，就能被批量篡改：原文案例1 把 POST 里的 `token=5A503FA...` 首字符改成 `1`（`1A503FA...`）后立即从「今天已投太多票数」变成投票成功，随后用 Burp Intruder 遍历 token 字符即可持续刷票；案例2 的 `vid`（学校）与 `id`（选项编号）直接递增遍历，达到该 id 的计数上限后把 id 增加一位（如从个位变十位）继续投，最终把学校刷到稳定排名第二（原文：刷之后稳定排名第二）。

## 原理

- **服务端以客户端提交的 token 作为「用户/票据」**：案例1 中服务端似乎只判断 token 是否已在「已投票集合」里——token 值不同就当作新票据。token 没有签名、没有与登录用户/设备绑定、也不是服务端一次性签发，因此攻击者改动任意一个字符就能绕过「今日已投」限制，遍历所有可能值即可无限投票。
- **计数维度由客户端参数决定**：案例2 的请求是 `...&vid=173&id=3&tp=`，服务端按 `id`（选项编号）维度累计票数/限次，而不是按投票人；`id` 递增遍历即可给不同编号投票。当同一 `id` 投到上限后，把 `id` 增加一位（换一个不存在/未计入的编号位）仍被服务端接受，绕过次数限制继续刷。
- **参数可直接枚举**：token 是字符串（案例1 为 64 位十六进制串/256-bit，但服务端不校验完整性），id 是数字，均可用 Burp Intruder/脚本批量遍历；原文 Intruder 用 a-i 等字符 payload 对 token 逐位测试、对 id 递增遍历均返回 200。
- **为什么成立**：防重与计数依赖「客户端可枚举的键」，服务端既未验证 token 的真实性/唯一签发，也未把投票行为与不可伪造的用户身份绑定；任何枚举值都能成为新票据。

## 触发条件

- 投票接口通过 token/id/vid 等客户端参数识别票据或计数对象。
- 服务端不校验 token 签名/来源/与账号绑定，或计数键不绑定真实用户。
- 无账号级频次限制或限制只针对单个 id 值。

## 利用步骤

1. 抓取投票请求，识别关键参数（案例1：`token`；案例2：`vid` 学校、`id` 选项编号）。
2. 单点试探：改 token 一位（`5A50...`→`1A50...`）或 id+1，观察响应是否从"已投太多/失败"变为成功（案例1 改一位即 `ok`）。
3. 批量遍历：Burp Intruder 对 token 逐位/逐值、对 id 数字递增或加位（4→14、4→104）遍历；或脚本循环发包。
4. 观察票数增长与排名变化（原文案例2 持续几十票后原 id 失效，id 加一位继续，最终排名第二；案例1 刷到 22748 票）。
5. 控制节奏使票数不超过阅读量/业务合理值，避免触发人工审核（原文提示）。

## PoC

```python
import requests

# 案例2 形式：vid/id 遍历，id 加位绕过次数上限
base = 'http://target/vote.php?vid=173&id='
for i in range(3, 200):
    r = requests.get(base + str(i), headers={'Cookie': 'PHPSSID=123'})
    if 'status":1' in r.text:
        print(i, r.text[:80])
```

```text
# 案例1：Burp Intruder 遍历 token（改首字符后响应 ok）
POST /vote HTTP/1.1
token=1A503FAF224C2460E8502958963C9CCC54FE333ACF1008F16E4A92EBC0D863A1&projectid=9421&...
```

## 变体与关联

- 变体：id 加位/溢出绕过（同库 [[web-generic-auth-content-site-packed-id-2pow32-step-paywall-bypass]] 的 id 维度绕过思路）、优惠券 id 篡改（[[web-generic-auth-coupon-id-parameter-tampering-idor]]）。
- 关联：[[web-generic-vote-anti-replay-client-ua-cookie-ip-bypass]]（同一文章：客户端/UA/Cookie/IP 校验薄弱面）。
- 边界：token 若是服务端签发的 HMAC/一次性票据且与账号绑定，篡改即失效；id 若是数据库主键且按用户唯一约束计数，遍历无效。

## 检测与防御

- 检测：大量 token 值仅相差个别字符、id 连续递增/位数突变的请求；同一账号/设备对多个 id 的批量投票；票数与阅读量/独立访客严重背离。
- 修复：投票票据由服务端生成并签名（绑定用户/设备、一次性、带有效期与 HMAC）；投票计数按「用户+活动」唯一键约束；id 必须为服务端已存在的合法对象并做归属校验；对加位/超范围 id 直接拒绝；账号级与设备级频次限制。
- 加固：服务端校验投票对象合法性、记录审计日志；对异常投票模式（token 相似度高、id 跳变）实时告警。
