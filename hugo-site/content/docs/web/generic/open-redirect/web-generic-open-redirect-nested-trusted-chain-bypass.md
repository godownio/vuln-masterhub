---
id: web-generic-open-redirect-nested-trusted-chain-bypass
title: 开放重定向的嵌套参数与可信站 302 接力：改最内层 url 或借白名单内站点的跳转，绕过只允许可信域的校验
type: scenario
domain: web
path: web/generic/open-redirect
technique: nested-redirect-trusted-chain-bypass
tags:
- open-redirect
- redirect-chain
- whitelist
- trust-abuse
- phishing
- web
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:29:54+08:00'
  notes: 已对照原文『多重验证&跳转绕过限制』与『可信站点超链接』段落核对：嵌套 url 参数改最内层、借百度收录链接的 302 形成『可信域->攻击者域』接力，均忠实于原文。未验证点：百度 link 具体形态随搜索引擎版本变化（原文本人提示 302 较长可加密），未实测；无组件版本。与同批 URL 解析卡/上传中转卡机制不同、已互链。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-nested-trusted-chain-bypass/
draft: false
kb_aliases:
- 多重跳转绕过
- 嵌套 url 参数
- 可信站点 302 接力
- Baidu site 302 跳转
- redirect chain bypass
---

## 一句话结论

当跳转白名单只允许“公司域/可信域”时，不一定需要直接伪造目标域名：一是利用**嵌套跳转参数**（外层 url 指向允许的登录页，内层再带一个 url 参数，改最内层即可到达任意站）；二是借**白名单内可信站点自身的 302 跳转**（如已被百度收录的链接经百度 302 中转）形成重定向接力，最终落到攻击者域。

## 原理

- **嵌套参数**：很多 SSO/登录/回调页面的 URL 形如 `https://victim.com/abc?url=https://login.victim.com/abc?url=https://login.victim.com`。外层目标 `login.victim.com` 在白名单内，校验通过；但该页面自身又会读取其 `url` 参数继续跳转，于是最终目标由最内层参数决定。攻击者保持外层为合法域，只把最内层改成 `https://evil.com`，形成“合法域 → 合法域 → 攻击者域”的链。
- **可信站 302 接力**：白名单只允许 `victim.com`（或只放行 baidu.com 等常用站）时，攻击者可以找这些可信站上“会 302 到外部 URL”的功能：
  - 搜索引擎的收录跳转：先在百度搜索自己的域名（`site:evil.com`），点击搜索结果时百度会先返回 302 再跳到目标站；把该百度跳转链接作为跳转参数值，就借百度完成了“可信域 → 攻击者域”的跨越。
  - 可信站的其他外链跳转/短链/分享中转页同理；把这些链接再做短链/编码包装，可进一步隐藏最终目标。
- **协议切换**：`http`↔`https` 转换、省略 scheme 等变体有时也能让只比对的域名前缀逻辑误判（见 URL 解析歧义卡）。
- 为什么有效：校验器只看“第一跳是否可信”，而浏览器会跟随整条重定向链；可信域的 302 是白名单机制无法拒绝的“合法行为”，攻击者只是选择了一个会外跳的可信入口。

## 触发条件

- 目标站点存在多层跳转页面（登录/统一认证/业务回跳），且内层参数未校验；
- 或白名单允许的某个可信域上存在会 302 到任意外部 URL 的功能，且攻击者能构造出该中转链接（如搜索引擎收录跳转）；
- 用户浏览器会跟随 302 链（默认行为）。

## 利用步骤

1. 观察正常跳转 URL 的结构，找嵌套的 `url=`/`redirect=` 参数（可能是 URL 编码的二次参数）。
2. 保持外层指向白名单域不动，解码并修改最内层参数为攻击者 URL，重新编码后提交。
3. 若结构不允许嵌套，找白名单可信站的开放跳转/短链/搜索收录 302：搜索攻击者域名并复制搜索结果链接（如百度 `/link?url=...`），作为跳转参数值。
4. 跟踪整条 302 链，确认最终落到攻击者钓鱼页；必要时用短链服务再包一层。
5. 构造钓鱼链接投递给受害者，链接开头仍是可信域，降低警觉。

## PoC

```text
嵌套示例（原文形态）:
  https://www.aaa.com.abc?url=https://login.aaa.com/abc?url=https://login.aaa.com
  修改最内层 -> https://www.aaa.com.abc?url=https://login.aaa.com/abc?url=https://evil.com

可信站 302 接力:
  在百度搜索 site:evil.com，取得搜索结果跳转链接（形如
  https://www.baidu.com/link?url=...），其会先 302 到 evil.com；
  把该链接作为 victim 跳转参数值，即形成 victim -> baidu -> evil.com 的链。
```

说明：原文对“百度的 302 比较长，可加密/短链处理”有提示；实际链接结构会随搜索引擎版本变化，需实测。

## 变体与关联

- 变体：多层嵌套可有三层以上，只需改最后一段；外层参数可能被 URL 编码，需先解码再修改。
- 变体：可信站不限于搜索引擎，任何允许外跳的短链、分享、OAuth 中转、统计跳转页都可作为接力点。
- 关联：URL 解析歧义绕过见 [[web-generic-open-redirect-url-parser-confusion-bypass]]；白名单子串缺陷见 [[web-generic-open-redirect-whitelist-substring-lookalike-domain]]；OAuth 重定向链与 code 窃取见 [[web-generic-oauth-arbitrary-redirect-uri-code-theft]]。
- 关联：分享/二维码生成接口的跳转参数见 [[web-generic-open-redirect-qrcode-share-url-param]]。

## 检测与防御

- 对跳转参数做“只允许一跳”策略：校验后直接输出目标，不再让目标页面读取新的跳转参数；嵌套场景要对每一层都校验，且禁止跳转目标包含可再次跳转的参数。
- 白名单不要放行“会任意外跳的可信站中转链接”；若必须支持搜索引擎/合作方跳转，要求其签名或使用专用短链域名并校验最终目标。
- 前端与后端共用同一校验；对 302 链做最终目的域校验（跟随重定向后比对 host），而不是只看第一跳。
- 检测：日志中出现 `url=` 嵌套、跳转参数值为搜索引擎 link/短链、302 链跨域多次跳转等模式；对最终外域跳转做审计。
