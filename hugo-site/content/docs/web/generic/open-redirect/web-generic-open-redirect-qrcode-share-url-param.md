---
id: web-generic-open-redirect-qrcode-share-url-param
title: 分享/二维码生成接口的开放重定向：篡改 url/targeturl 参数让扫码者跳转钓鱼站（附跳转参数与业务位置清单）
type: scenario
domain: web
path: web/generic/open-redirect
technique: open-redirect-qrcode-share-url-param
tags:
- open-redirect
- url-redirect
- qrcode
- share
- phishing
- burp
- parameter
- bugbounty
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T07:48:47+08:00'
  notes: 已对照原文与7张图核对：两案例(targeturl 卖家后台、qrcode?url 分享二维码)与 Location/meta/location 原理一致；参数清单与业务位置与原文一致；未实环境执行PoC
url: /docs/web/generic/open-redirect/web-generic-open-redirect-qrcode-share-url-param/
draft: false
kb_aliases:
- URL 重定向漏洞
- URL 任意跳转
- 二维码跳转漏洞
- targeturl 开放重定向
- qrcode url 参数
- 分享链接重定向
- redirect 参数清单
---

## 一句话结论

当登录、分享、二维码生成、OAuth 回调等业务把 `url`/`targeturl`/`redirect`/`return_url` 等参数直接用于跳转（HTTP `Location`、`<meta http-equiv="refresh">` 或 `window.location`），且未校验目标域名时，攻击者把参数改成自己的站点即可生成一条“看起来来自可信域名”的链接或二维码；受害者点击/扫码后被带到钓鱼页，可进一步窃取账号口令。

## 原理

- 服务端重定向：应用从请求参数取目标 URL，直接写入 `Location` 响应头（常见 301/302/303/307/308），浏览器随后向该 URL 发 GET。示例：`<?php $url=$_GET['URL']; header("Location: $url"); ?>`。
- 前端重定向：`<meta http-equiv="refresh" content="0; url=https://evil/">` 由 `content` 属性控制延迟与目标；或 JavaScript 修改 DOM 的 `window.location`/`window.location.href`/`window.location.replace()`。只要能控制这些内容/执行 JS，就能把用户带走。
- 之所以是漏洞：跳转目标完全由用户输入决定，没有域名白名单/映射表/相对路径限制；攻击者使用可信域名链接做诱饵，用户难以识别最终落地页。
- 二维码/分享场景的特殊性：服务端或前端在生成二维码时把 `url` 参数写进二维码内容；攻击者抓包改参数后重新生成/刷新，二维码图案变化但页面仍显示在可信业务域名下，扫码者直接跳转到攻击者站点。原文案例：视频分享页 `.../h5/pc-client/#/qrcode?url=https%3A%2F%2F...` 把 `url` 改为 `https://www.baidu.com` 后刷新，手机扫码即跳转。
- 常见业务位置（原文清单）：登录/注册完成后的跳转、分享/收藏后的跳转、跨站认证/授权（OAuth callback）、站内点击外链、问卷/客服评价完成跳转、修改密码/绑卡/VIP 办理完成后的返回跳转。
- 常见参数名（原文清单）：`redirect`、`url`、`redirectUrl`、`callback`、`return_url`、`toUrl`、`ReturnUrl`、`fromUrl`、`redUrl`、`request`、`redirect_to`、`redirect_url`、`jump`、`jump_to`、`target`、`to`、`goto`、`link`、`linkto`、`domain`、`oauth_callback`。

## 触发条件

- 应用存在把请求参数直接用于跳转的代码/前端逻辑，且未做目标域名白名单或映射。
- 攻击者能构造带参数的 URL（GET/POST、分享链接、二维码生成接口）并诱导受害者访问/扫码。
- 跳转发生前不需要额外不可控交互（如需登录，则受害者已登录或攻击者利用公开分享页）。
- 受害者对可信域名链接/二维码缺乏核验（钓鱼成功的前提）。

## 利用步骤

1. 在登录、分享、二维码、OAuth 等业务处抓包，观察 GET/POST 参数与响应；重点看 `Location` 头、页面里的 meta refresh、`window.location` 赋值。
2. 用常见参数名清单逐个替换为外部域名（如 `https://www.baidu.com` 或自建钓鱼站），观察是否 302 跳转或前端跳转。
3. 对分享/二维码生成接口：抓生成二维码的请求，改 `url`/`targeturl` 参数后刷新页面/重新生成，确认二维码内容变化。
4. 用手机扫描新二维码或让受害者点击链接，确认最终落地到外部站点；截图/录屏留证。
5. 将落地页做成与目标品牌相似的钓鱼页，收集账号口令/敏感信息；注意仅限授权测试。

## PoC

最简服务端重定向：

```php
<?php
$url=$_GET['URL'];
header("Location: $url");
?>
```

访问 `http://target/rce.php?URL=http://www.baidu.com` 即跳转百度。

卖家后台/供应链跳转参数：

```text
https://www.xxx.com/oauth/authurl/?targeturl=https://www.baidu.com
```

二维码分享页参数篡改：

```text
原始：https://www.xxx.com/aiis/h5/pc-client/#/qrcode?url=https%3A%2F%2Fn.com%2Faiis%2FinvestmentAdvisor
篡改：https://www.xxx.com/aiis/h5/pc-client/#/qrcode?url=https%3A%2F%2Fwww.baidu.com
```

修改后刷新页面，手机扫描新二维码即跳转到 `https://www.baidu.com`。

## 变体与关联

- 变体：前端 SPA 的 hash 路由把 `url` 参数交给 `location.href`/`location.replace`；需在浏览器端复现并注意 hash 参数不会发送到服务端。
- 变体：`<meta http-equiv="refresh">` 注入（需能控制页面内容）、OAuth `redirect_uri` 校验不严、Host 头注入导致登录跳转被劫持。
- 关联：[[web-generic-open-redirect-shiro-login-redirect-host-header]] 是 Host 头注入导致登录重定向劫持；[[web-generic-open-redirect-activiti-formkey-sendredirect]] 是表单 formKey 控制 sendRedirect；[[web-generic-open-redirect-webob-whitespace-urljoin-mismatch]] 是白名单校验被 URL 解析差异绕过。
- 关联：[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]] 等鉴权绕过可与开放重定向组合做钓鱼/会话泄露。

## 检测与防御

- 检测：请求参数中出现外部域名/协议相对 URL（`//evil`、`https://evil`）且响应 `Location`/meta/location 赋值指向该域名；二维码生成接口的 `url` 参数可被替换；Burp 历史中大量含 `url`/`redirect` 参数的请求。
- 防御：跳转目标使用服务端映射表/固定枚举，不直接接收 URL；必须接收时做严格域名白名单（解析后比较 host，不只做前缀/子串匹配）；优先使用相对路径；对 OAuth `redirect_uri` 做注册校验；前端跳转同样校验并拒绝外部协议；对可疑跳转加中间确认页。
