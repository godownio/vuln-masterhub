---
id: web-generic-open-redirect-upload-html-whitelisted-domain-chain
title: 开放重定向 + 任意文件上传链：在白名单文件域上传自动跳转 HTML，借可信域中转绕过跳转白名单
type: scenario
domain: web
path: web/generic/open-redirect
technique: upload-html-whitelisted-domain-redirect-chain
tags:
- open-redirect
- file-upload
- chain
- whitelist
- trusted-domain
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
  verified_at: '2026-11-09T23:31:03+08:00'
  notes: 已对照原文『漏洞构造漏洞』段落核对：任意文件上传无法解析后端语言、只能造成前端危害时，上传自动跳转 HTML，利用存放文件的白名单域名符合跳转范围完成两跳开放重定向并可进一步获取 cookie，忠实于原文。未验证点：原文未给上传绕过 payload、具体文件域与本链逐步复现，PoC 为按叙述构造的最小示例（卡内已注明）；无组件版本。该卡是文件上传+开放重定向的组合链而非两个独立动作的拼盘，最终危害（可信域链接跳钓鱼站）成立，保留。
url: /docs/web/generic/open-redirect/web-generic-open-redirect-upload-html-whitelisted-domain-chain/
draft: false
kb_aliases:
- 漏洞构造漏洞
- 上传 HTML 跳转
- 文件域白名单绕过
- 中转页面跳转
- open redirect chain upload
---

## 一句话结论

当站点对跳转参数只允许白名单域、直接跳外域被拦时，可以先利用同一目标上的任意文件上传漏洞，把一段自动跳转的 HTML（meta refresh/JS）上传到文件服务器；该文件所在域名通常在站点白名单内，于是“跳转参数 → 白名单文件域上的 HTML → 攻击者钓鱼站”组成两跳链，绕过原本无法绕过的开放重定向限制。

## 原理

- 文件上传漏洞即使不能解析后端语言（传 `.php/.jsp` 不执行），只要上传目录允许直接以 `text/html` 访问文件，就获得了一个**同域/白名单域下的可控 HTML 页面**。
- 在该 HTML 中写入 `<meta http-equiv="refresh" content="0;URL=https://evil.example">` 或 `<script>location='https://evil.example'</script>`，访问即跳转。
- 跳转白名单校验的是“目标 URL 的域名”；文件服务器域名属于站点资产（如 `upload.victim.com`、`cdn.victim.com`、`files.victim.com`），通常在白名单内，于是第一跳合法。
- 浏览器跟随第二跳（HTML 内跳转）到攻击者站，完成开放重定向；如果上传目录与主站同域，还可能进一步读取同域 cookie（若 HTML 中写 JS 读取并外带，则升级为 XSS/会话窃取）。
- 为什么值得记录：这是“用另一个漏洞补偿当前漏洞缺失能力”的典型链式思维；单独看文件上传只造成“一点点前端危害”，组合后变成可用于钓鱼/凭据窃取的可信链接。

## 触发条件

- 目标存在任意文件上传（允许 HTML/SVG 等可执行于浏览器的内容，或允许改扩展名/MIME 绕过），且上传文件可通过 URL 直接访问；
- 上传文件所在域名在开放重定向的白名单内（同域上传最理想）；
- 跳转参数校验只看域名/前缀，不校验路径内容；
- 受害者点击最终链接并允许浏览器渲染上传的 HTML。

## 利用步骤

1. 找到允许上传且可直接访问的文件上传点，确认能上传 `.html` 或可通过改名/双扩展/Content-Type 绕过得到 `text/html` 响应。
2. 上传内容为自动跳转的 HTML（meta refresh 或 JS location），目标为攻击者钓鱼页。
3. 取得上传文件的完整 URL（含文件服务器域名），确认其可直接访问且会跳转。
4. 把该 URL 作为开放重定向参数的取值，构造“可信域/白名单域 → 上传 HTML → 钓鱼站”的链接。
5. 投递链接；如需窃取同域 cookie，可在 HTML 中加入读取 `document.cookie` 并外带的脚本（同源上传时）。

## PoC

```html
<!-- 上传的 redirect.html -->
<meta http-equiv="refresh" content="0;URL=https://evil.example/login">
```

```text
利用链:
  https://victim.com/redirect?url=https://upload.victim.com/u/xxxx/redirect.html
      -> 302 到 upload.victim.com（白名单域，校验通过）
      -> 浏览器渲染 redirect.html，meta refresh 跳到 https://evil.example/login
```

说明：原文描述该场景来自一次渗透测试，上传点无法解析后端语言、只能造成前端危害，但文件服务器域名符合站点跳转范围，最终构成 URL 跳转并可进一步获取 cookie；原文未给出具体上传绕过 payload，PoC 为按叙述构造的最小示例。

## 变体与关联

- 变体：上传 SVG（`<svg onload="location=...">`）同样可作为白名单域中转页；若上传目录强制 `Content-Disposition: attachment` 则无效，需要绕过。
- 变体：不限于上传——任何能在白名单域上写入/托管 HTML 的功能（富文本、模板、用户主页、笔记分享）都可作为中转。
- 关联：客户端跳转载体见 [[web-generic-open-redirect-meta-refresh-svg-onload-vectors]]；上传导致 SVG 脚本执行见 [[web-generic-file-upload-svg-inline-script-stored-xss]]。
- 关联：白名单子串/解析歧义绕过见 [[web-generic-open-redirect-whitelist-substring-lookalike-domain]]、[[web-generic-open-redirect-url-parser-confusion-bypass]]。

## 检测与防御

- 修复开放重定向：host 精确白名单 + 只允许一跳；不要白名单“整个文件/CDN 域”，或对文件域上的跳转目标再做签名校验。
- 修复上传：禁止上传可渲染 HTML/SVG，强制 `Content-Disposition: attachment`，上传域使用独立无 cookie 沙箱域，MIME 由服务端校验。
- 检测：上传目录中出现 `.html/.svg` 且内容含 `refresh`/`location`；跳转参数指向自家文件域后再次外跳的链式流量。
- 安全测试：发现“只能前端危害”的上传时，评估其域名是否属于其它白名单/信任边界，尝试组合利用。
