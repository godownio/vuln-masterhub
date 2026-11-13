---
id: web-generic-vote-anti-replay-client-ua-cookie-ip-bypass
title: 投票防重只靠客户端/UA/Cookie/IP：逐层绕过实现批量刷票
type: scenario
domain: web
path: web/generic
technique: vote-anti-replay-weak-identity-bypass
tags:
- business-logic
- vote
- rate-limit
- client-side-validation
- user-agent
- cookie
- x-forwarded-for
- proxy-pool
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V664
  verified_at: '2026-11-13T08:17:43+08:00'
  notes: 已对照原文与30张图核对：前端弹框不阻断、换浏览器/清缓存、按钮disabled、UA改手机UA（案例1 Win UA→iPhone UA 后由『请使用**投票』变为『今天已投太多票数』）、Cookie PHPSSID=123 与 X-Forward-For 186.123.66.3 均不校验、代理池代码、票数>阅读量提醒、接码平台列表均与原文一致。修正：原文案例1客户端名称脱敏为**，卡内『请使用 App 投票』改为如实标注原文脱敏。未验证点：未复现目标站点。affected_versions 原文无标记保持 null。
url: /docs/web/generic/web-generic-vote-anti-replay-client-ua-cookie-ip-bypass/
draft: false
kb_aliases:
- 刷票逻辑漏洞
- 投票防重绕过
- UA 绕过投票限制
- Cookie 绕过投票限制
- X-Forwarded-For 绕过 IP 限制
- 代理池刷票
---

## 一句话结论

投票/计票功能的「一人一票」若只靠前端弹框、按钮禁用、User-Agent、Cookie 或来源 IP 等易伪造标识来防重，攻击者可逐层绕过：直接向服务端发包跳过前端限制、把 UA 改成手机 UA（原文案例1：客户端投票提示「请使用**投票」（原文脱敏），换手机 UA 后即可投票）、修改/清空 Cookie（原文案例2 Cookie `PHPSSID=123` 任意改仍正常）、伪造 `X-Forwarded-For`/`Client-IP`（原文把 XFF 改为任意 IP 仍返回成功）或使用代理池/重拨换 IP，从而无限次刷票。

## 原理

- **客户端验证不是安全边界**：投票后的弹框提示、按钮 `disabled`、倒计时等都只是前端 UI；请求已经或仍可直接发往服务端，服务端若不独立校验，刷新页面/换浏览器/清缓存/删除前端代码/直接重放请求即可继续投票。
- **UA 是客户端自报头**：服务端用 `User-Agent` 判断"是否用指定 App/浏览器"，攻击者抓包后把 UA 改成目标值（原文案例1 把 Windows 客户端 UA 换成 iPhone Safari 的 UA）即可通过校验；UA 可任意伪造，不能作为身份或防重依据。
- **Cookie 可任意改写**：若防重只认 Cookie 中的标记（如 `PHPSSID=123`），攻击者修改任意字符、清空或换浏览器即可获得"新身份"；原文案例2 中 Cookie 值随便改，服务端仍返回 `status:0`（投票成功），说明根本没有把它与用户绑定。
- **IP 头可伪造**：`X-Forwarded-For`、`Client-IP`、`X-Real-IP` 等由客户端提交，若服务端直接信任这些头做「一 IP 一票」，攻击者每次请求塞入不同/任意 IP 即可绕过（原文图 04 直接把 XFF 设为 `172.21.1.1`）；若服务端取真实连接 IP，则可用代理池、路由器重拨、手机飞行模式换 IP 绕过。
- **手机号验证码**：使用在线接码平台接收验证码，即可批量完成需要手机号验证的投票。
- **为什么成立**：这些校验都基于「客户端可控制或可替换的标识」，没有一个是服务端与真实身份绑定的不可伪造凭证；防重计数应发生在服务端账号/设备维度并要求不可伪造的凭证。

## 触发条件

- 投票接口存在防重逻辑，但依据是前端状态、UA、Cookie 值或客户端可控的 IP 头。
- 服务端直接信任 `X-Forwarded-For` 等代理头，或未做账号级频次限制。
- 攻击者可抓包重放/脚本化请求（有 Python、Burp 等工具即可）。

## 利用步骤

1. 正常投票并抓包，记录投票请求（URL、方法、参数、Cookie、UA）。
2. **跳过客户端**：删除前端校验代码或直接用 `requests` 重放请求，确认票数增长。
3. **UA 绕过**：当提示"请使用指定 App/浏览器投票"时，把请求头 `User-Agent` 改为目标 App/手机 UA（原文示例 iPhone Safari UA），重放后成功。
4. **Cookie 绕过**：修改 Cookie 中任意字符或清空 Cookie 后重放，观察是否被当作新用户。
5. **IP 绕过**：添加/修改 `X-Forwarded-For`、`Client-IP` 头为不同 IP；若无效则切换到代理池脚本（原文给出的随机代理请求代码）或重拨换 IP。
6. **手机号验证**：用接码平台号码完成短信验证后投票。
7. 循环发包批量刷票，注意保持票数与阅读量/业务合理范围一致（原文提醒：票数大于阅读量会暴露刷票行为，可能被人工降级）。

## PoC

```python
import requests
url = 'http://www.domain.com/comment.php?aid=123&who=1&t=1385710179528'
while True:
    requests.get(url)  # 无任何验证时直接循环
```

```python
# UA 绕过 + XFF 伪造示例
headers = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_0 like Mac OS X) AppleWebKit/602.1.38 (KHTML, like Gecko) Version/10.0 Mobile/14A5297c Safari/602.1',
    'X-Forwarded-For': '172.21.1.1',
}
requests.post(vote_url, data=payload, headers=headers, cookies={'PHPSSID': '123'})
```

```python
# 代理池随机换 IP（原文）
from random import choice
proxy = choice(['http://ip1:port1', 'http://ip2:port2'])
requests.get('http://www.example.com', headers=headers, proxies={'http': proxy})
```

## 变体与关联

- 变体：CSRF 刷票——利用已登录用户身份在第三方页面自动提交投票（参见 web/generic/csrf 目录）；XSS 打 Cookie 后遍历 cookie 批量发包（xss 目录）。
- 变体：并发/条件竞争刷票——多线程/Fiddler 批量发包让服务端在校验完成前处理大量请求（参见 web/generic/race-condition 目录）。
- 关联：[[web-generic-purchase-quantity-limit-client-side-only-bypass]]（客户端限购同样不可信）、[[web-generic-client-side-race-distance-tamper]]（客户端数据篡改的业务逻辑变体）。
- 边界：若服务端使用账号绑定的强随机一次性 token、设备指纹+频次限制、服务端验证码，以上绕过失效。

## 检测与防御

- 检测：同一账号/设备短时间大量投票请求；同一来源不同 XFF 值；UA 与业务客户端不符；票数增长与阅读量/活跃用户严重背离（票数 > 阅读量是刷票强特征，原文专门提到厂商以此人工判定）。
- 修复：防重计数放服务端账号维度；投票凭证由服务端签发、与用户/会话绑定、一次性且带 HMAC；不信任客户端 IP 头（只取可信代理链的真实地址）；对投票接口做账号/IP/设备多维频次限制与验证码（服务端校验）；手机号验证做号码与账号唯一绑定。
- 加固：监控票数与阅读量比例、异常 UA/来源分布；对高价值投票活动做人审或延迟结算。
