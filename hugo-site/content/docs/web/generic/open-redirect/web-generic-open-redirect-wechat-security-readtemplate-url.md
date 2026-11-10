---
id: web-generic-open-redirect-wechat-security-readtemplate-url
title: 微信安全中心 readtemplate 模板的 url 参数开放重定向：高信任域跳转配合滑块验证，可用于钓鱼
type: scenario
domain: web
path: web/generic/open-redirect
technique: wechat-readtemplate-url-open-redirect
tags:
- open-redirect
- wechat
- trusted-domain
- captcha
- phishing
- web
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V445
  verified_at: '2026-11-09T23:31:01+08:00'
  notes: 已对照原文『微信最新url跳转』与图08/09/10核对：shminishort.weixin.qq.com/security/readtemplate?t=w_security_center_website/w_tcaptcha&url=http://www.baidu.com 加载后出现滑块验证，完成后浏览器地址栏为 https://www.baidu.com，子域与参数名一致。未验证点：跳转由 url 参数控制系由『带参请求+滑块后落地百度』推断（原文章节未逐步文字说明），接口 2024 年行为可能已修复/风控，卡片 confidence medium；未实测，无组件版本。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-wechat-security-readtemplate-url/
draft: false
kb_aliases:
- 微信 readtemplate 跳转
- w_tcaptcha url 参数
- 微信开放重定向
- weixin.qq.com 任意跳转
---

## 一句话结论

微信安全中心的模板渲染接口 `https://<sub>.weixin.qq.com/security/readtemplate?t=w_security_center_website/w_tcaptcha&url=<目标>` 会把 `url` 参数作为验证完成后的跳转目标；攻击者把 `url` 换成钓鱼页，受害者看到的是 weixin.qq.com 域名和滑块验证，完成验证后浏览器跳到攻击者站点——高信任域 + 验证交互进一步降低警觉。

## 原理

- `readtemplate` 是微信安全中心的模板页面，`t=w_security_center_website/w_tcaptcha` 指定“网站安全验证（滑块拼图）”模板；模板接受 `url`、`wechat_real_lang`、`aid`、`clientype`、`lang`、`apptype`、`captype`、`disturblevel`、`secticket` 等参数。
- 漏洞点：`url` 参数未对目标 host 做白名单校验（或可被解析歧义绕过），验证通过后模板把 `url` 作为最终跳转地址，形成开放重定向。
- 原文实测请求带 `url=http://www.baidu.com`，页面先显示滑块验证，完成后跳到百度（截图：页面加载 → 拖动滑块 → 百度首页），证明 `url` 可控。
- 危害：链接域名是 `*.weixin.qq.com`，用户/邮件网关/IM 风控普遍信任；配合真实滑块验证（需要用户交互）会让受害者认为是微信官方安全验证流程，落地页仿冒微信登录/账号异常处理页即可窃取账号密码或扫码授权。
- 类似模板可能还接受其它跳转参数（`redirect`、`return_url`），测试时可一并替换。

## 触发条件

- 目标微信安全中心模板页面（`security/readtemplate`）在该版本/时间点未校验 `url` 目标域；
- 受害者完成滑块验证（人机交互）；
- 浏览器可访问 `weixin.qq.com` 与攻击者站点；
- 该接口可能随微信更新失效或被风控，需实测确认。

## 利用步骤

1. 构造 `https://<sub>.weixin.qq.com/security/readtemplate?t=w_security_center_website/w_tcaptcha&url=<攻击者URL>&wechat_real_lang=zh_CN&aid=2000000038&clientype=1&lang=2052`。
2. 浏览器打开，完成滑块拼图验证。
3. 观察是否跳转到攻击者 URL；如被拦截，尝试 URL 编码、`//`、`@`、`?` 等解析歧义变体（见关联卡）。
4. 将最终链接投递给受害者，落地页仿冒微信安全中心/登录页，窃取凭据或诱导扫码授权。

## PoC

```text
https://<sub>.weixin.qq.com/security/readtemplate
  ?t=w_security_center_website/w_tcaptcha
  &url=https://evil.example/wechat-login
  &wechat_real_lang=zh_CN
  &aid=2000000038
  &clientype=1
  &lang=2052
```

实测流程（原文）：访问带 `url=http://www.baidu.com` 的链接 → 页面显示滑块验证 → 拖动完成 → 跳转百度首页。

## 变体与关联

- 变体：改 `url` 为 `//evil.example`、`https:evil.example`、带 `@` 的地址等，测试模板是否只用字符串前缀校验（见 [[web-generic-open-redirect-url-parser-confusion-bypass]]）。
- 变体：其它 `readtemplate` 模板或微信 OAuth/短链跳转页若有类似 `url`/`redirect` 参数，可作为同类入口。
- 关联：高信任域/二维码跳转见 [[web-generic-open-redirect-qrcode-share-url-param]]；OAuth redirect_uri 组合见 [[web-generic-oauth-arbitrary-redirect-uri-code-theft]]。
- 注意：该案例来自 2024 年文章，接口行为可能已修复；使用时须重新验证，置信度 medium。

## 检测与防御

- 模板类接口对跳转参数做 host 精确白名单校验（仅允许 weixin.qq.com 域或官方业务域），拒绝 `//`、`@`、`?`、编码等变体。
- 验证码流程中不要携带最终跳转目标给客户端/模板；验证完成后由服务端按业务 ID 查表生成跳转地址。
- 用户侧：对“weixin.qq.com 链接 + 滑块验证后跳外部站”的情况保持警惕；钓鱼检测可对 readtemplate 跳外域的链接做告警。
- 检测：微信域名下 `readtemplate` 请求的 `url` 参数含外部域名；302/JS 跳转到非微信域。
