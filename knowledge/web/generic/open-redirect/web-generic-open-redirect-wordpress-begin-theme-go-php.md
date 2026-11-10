---
id: web-generic-open-redirect-wordpress-begin-theme-go-php
title: WordPress begin lts 主题 go.php 开放重定向：/wp-content/themes/begin lts/inc/go.php?url= 直接 302 到任意外站
type: scenario
domain: web
path: web/generic/open-redirect
technique: wordpress-begin-theme-go-php-open-redirect
aliases:
- begin lts go.php
- WordPress 主题开放重定向
- go.php url 跳转
- WordPress 任意跳转
tags:
- open-redirect
- wordpress
- begin-theme
- php
- go-php
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
  verified_at: '2026-11-09T23:30:59+08:00'
  notes: 已对照原文实战案例与图03/04核对：/wp-content/themes/begin%20lts/inc/go.php?url=http://xxx.com/ 实测跳转，换 https://baidu.com/ 后浏览器落到百度首页，路径与 url 参数名一致。未验证点：原文未抓包、未分析 go.php 源码，卡片中『302 Location』为合理推断（卡内已标注『或等价实现』、confidence medium），主题版本未知；2024 年案例，目标站点可能已删改 go.php，未实测。
---

## 一句话结论

安装 begin lts 主题的 WordPress 站点存在一个可直接访问的跳转脚本 `/wp-content/themes/begin lts/inc/go.php`，其 `url` 参数未做目标校验，请求后返回 302 把浏览器带到参数指定的任意外部站点；攻击者可利用可信的 WordPress 站点域名生成钓鱼跳转链接（原文实测跳到百度成功，换钓鱼页即可用于诱骗）。

## 原理

- 主题自带的 `go.php` 用于站内/合作链接跳转：读取 `$_GET['url']` 后直接 `header("Location: " . $url)`（或等价实现），没有对目标域名做白名单/同源校验。
- 由于路径位于 `wp-content/themes/...` 下，脚本随主题文件部署，任何安装该主题且未删除/修改 go.php 的站点都可能暴露该入口；未登录即可访问，GET 请求即可触发。
- 危害形态：链接以受害者可信域名开头（`https://victim/wp-content/themes/begin%20lts/inc/go.php?url=...`），受害者点击后落到攻击者钓鱼页，cookie/凭据可被仿冒登录页窃取；也可用于绕过只校验“链接是否属于可信域”的邮件网关/IM 过滤。
- 原文对该案例的验证方式是访问 `.../go.php?url=http://xxx.com/`，再替换为 `https://baidu.com/`，浏览器成功跳转（截图显示百度首页）。

## 触发条件

- 目标 WordPress 站点安装 begin lts 主题（或包含该 go.php 跳转脚本的主题变体），且文件未被删除/加固；
- `url` 参数存在且无白名单校验；
- 目标站点可从外网访问，攻击者能构造完整路径（主题目录名含空格时需 URL 编码为 `%20`）。

## 利用步骤

1. 识别 WordPress 站点与主题：访问 `/wp-content/themes/begin lts/` 目录/静态资源，或从页面源码的 `/wp-content/themes/begin lts/` 路径判断。
2. 直接访问 `/wp-content/themes/begin lts/inc/go.php?url=https://www.baidu.com/`，确认 302/页面跳转。
3. 将 `url` 换成攻击者钓鱼页，生成以目标域名为前缀的链接投递。
4. 结合 URL 编码/短链隐藏最终目标，提高点击率。

## PoC

```http
GET /wp-content/themes/begin%20lts/inc/go.php?url=https://www.baidu.com/ HTTP/1.1
Host: victim.example
```

```http
HTTP/1.1 302 Found
Location: https://www.baidu.com/
```

验证跳转成立后，把 `url` 参数替换为攻击者站点即可：

```text
https://victim.example/wp-content/themes/begin%20lts/inc/go.php?url=https://evil.example/login
```

说明：原文未给出受影响主题版本，也未分析 go.php 源码；判定基于实测跳转与路径，置信度 medium。

## 变体与关联

- 变体：其它 WordPress 主题/插件也可能自带 `go.php`、`redirect.php`、`link.php` 等跳转脚本，参数名常为 `url`/`link`/`to`，可批量枚举主题静态目录。
- 变体：若 go.php 有前缀校验，可叠加 `@`、`//`、`?` 等解析歧义（见 URL 解析歧义卡）。
- 关联：通用跳转参数与白名单绕过见 [[web-generic-open-redirect-url-parser-confusion-bypass]]；二维码/分享跳转见 [[web-generic-open-redirect-qrcode-share-url-param]]。
- 关联：WordPress 主题/插件目录的其它漏洞可按需检索对应组件卡。

## 检测与防御

- 删除或加固主题中的 go.php：改为白名单域名映射（如 `?id=1` 对应固定 URL），对 `url` 参数解析后做 host 精确校验，禁止任意外站。
- 站点侧：使用 WAF 拦截 `go.php?url=` 指向外部域的请求；定期扫描 `wp-content/themes/*/inc/go.php` 等跳转脚本。
- 检测：访问日志中出现 `/wp-content/themes/` 下 `go.php` 且 `url` 参数为外部域名；302 响应 Location 与站点域不同。
- 钓鱼监测：对使用该路径的可疑链接做封禁与用户提示。
