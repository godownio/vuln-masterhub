---
id: web-generic-open-redirect-interaction-triggered-and-post-param
title: 被交互触发的开放重定向测试盲点：登录按钮点击后才跳转、POST 图片地址预览/审核点开触发
type: scenario
domain: web
path: web/generic/open-redirect
technique: interaction-triggered-open-redirect
tags:
- open-redirect
- post-parameter
- interaction
- phishing
- admin-review
- web
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:30:57+08:00'
  notes: 已对照原文『点击触发达到绕过URL跳转限制』与『POST参数中URL跳转』两段核对：登录/认证按钮点击后才触发跳转（凭据不一定正确）、POST 图片完整地址在预览页裂图后右键查看图像触发跳转、可钓后台审核员、Burp Change request method 转 GET 等均忠实。未验证点：原文为经验描述、无具体漏洞实例，卡片 confidence medium；两类场景同属『交互后才触发』的测试盲点，且都依赖同一跳转参数/图片地址控制机制，属一个主题的两种载体而非两个独立动作，无需拆分；无组件版本。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-interaction-triggered-and-post-param/
draft: false
kb_aliases:
- 点击登录触发跳转
- POST 参数跳转
- 图片地址预览跳转
- 审核员点击图片钓鱼
- Burp Change request method
---

## 一句话结论

有些开放重定向不会在“改参数然后刷新”时触发：登录/认证页改了 `url` 参数后仍停留原地，只有输入账号（甚至任意账号）并点击登录后才执行跳转；另一些场景把图片 URL 放在 POST 参数里，页面上只显示裂图，右键“查看图像”或后台审核点开时才触发跳转。把这两类交互点纳入测试，才不会漏掉“看起来没反应”的跳转漏洞。

## 原理

- **登录后跳转**：登录页的跳转参数常被读取后存进隐藏字段/会话，在认证成功（或登录流程完成）时才拼进 302 Location；直接改 URL 刷新不会触发，于是测试者容易误判不存在漏洞。实际上只要走完登录动作（凭据正确与否视实现而定，常见是任意用户名/密码或注册即登录）就会触发。
- **POST 参数跳转**：多步表单（上传图片→下一步预览→提交）中，图片完整地址可能在 POST body 里传给预览页；预览页把该地址作为 `<img src>` 输出，页面本身不跳转，但图片加载失败时用户/审核员右键“查看图像”会直接导航到该 URL，从而触发跳转。
- **危害升级**：第二种场景的目标往往是后台审核员——审核时看到图片加载失败，习惯性点开查看，攻击者可在落地页做钓鱼/浏览器 0day 诱饵，形成对高权限人员的攻击面。
- **Burp 小技巧**：若跳转参数在 POST 里，可右键 `Change request method` 把请求改成 GET，若服务端同时接受 GET 参数，就能直接在地址栏/复现脚本里测试。
- 为什么容易漏：自动化爬虫/扫描器只改参数发请求，不点按钮、不右键看图，因此发现不了这些交互后才发生的跳转。

## 触发条件

- 登录/注册/支付/认证流程中存在跳转参数，且跳转动作绑定在“点击提交并完成流程”之后；
- 或存在多步表单/图片上传，预览页把用户可控 URL 作为图片地址输出，且展示页允许右键查看图像/点击图片；
- 目标有后台审核流程（客服、内容审核、商品审核）时危害更高；
- 浏览器会跟随最终导航（默认）。

## 利用步骤

1. 在登录/认证页修改跳转参数（如 `url`、`redirect`、`return_url`），直接刷新确认不跳转后，输入任意凭据点击登录，观察是否在成功/失败页触发跳转。
2. 在多步表单中上传图片并进入预览，抓包查看 POST 参数中的图片地址（常为完整 URL），改成攻击者 URL。
3. 预览页图片变为裂图；右键“查看图像”或点击图片，确认浏览器跳到攻击者页。
4. 若目标有后台审核，将表单提交给审核员，利用其“点开裂图”习惯把审核员导向钓鱼页（仿登录页窃取凭据）。
5. POST 跳转参数可尝试改为 GET（Burp Change request method）以便批量测试与复现。

## PoC

```text
登录后触发:
  修改前: https://victim.com/login?url=https://login.victim.com
  修改后: https://victim.com/login?url=https://evil.example
  直接访问不跳转；输入任意账号密码点击“登录”后跳到 evil.example

POST 图片地址:
  POST /preview HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  title=x&imageUrl=https://evil.example/pixel.png
  -> 预览页 <img src="https://evil.example/pixel.png"> 裂图
  -> 审核员右键“查看图像” -> 浏览器导航到 evil.example
```

说明：原文强调“用户名密码不一定要对，视系统而定”；POST 场景“点击图片右键查看图像”即可触发，同时可用于钓后台审核员。

## 变体与关联

- 变体：更新资料/绑定银行卡/充值成功/问卷提交后的回跳均可出现“业务完成后才跳转”；测试时要走完整流程。
- 变体：POST 图片地址也可换成 `<video>`/`<a>` 等媒体/链接标签，触发方式相应变化。
- 关联：白名单/解析绕过见 [[web-generic-open-redirect-url-parser-confusion-bypass]]；二维码/分享链接场景见 [[web-generic-open-redirect-qrcode-share-url-param]]。
- 关联：借“任意文件上传的 HTML/SVG 页面”作为中转域、再绕过跳转白名单的思路（原文“漏洞构造漏洞”）与 [[web-generic-open-redirect-meta-refresh-svg-onload-vectors]] 相关。

## 检测与防御

- 对所有登录/业务完成后的跳转目标做 host 白名单校验，且校验发生在最终输出 Location 时，而不是只校验入口参数。
- 预览/审核页不要把用户可控的图片/媒体 URL 直接输出为可导航资源；图片应经服务端代理/重新托管，或限制只能来自受控 CDN 域，禁止右键/点击导航到任意外域（也可用 CSP `img-src` 限制）。
- 审核端使用独立浏览器配置/沙箱与安全意识培训，避免点击不可信资源。
- 检测：审计代码中“流程完成后拼 Location”的路径与预览页的 URL 渲染；对审核页加载外部图片域名做告警。
