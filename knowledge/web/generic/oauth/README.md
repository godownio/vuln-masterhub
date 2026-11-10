# OAuth

## 这层是什么

OAuth/OIDC 流程缺陷、redirect_uri 与 token 泄露。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [OAuth access_token 窃取：redirect_uri 穿越到同站评论表单代理页，利用 parent.postMessage(location.href,'*') 泄露 fragment token](web-generic-oauth-token-theft-postmessage-proxy-page.md) | verified | high | 2026-11-08 |
| [OAuth redirect_uri 未做白名单校验：把管理员授权码重定向到攻击者服务器并重放登录（账户接管）](web-generic-oauth-arbitrary-redirect-uri-code-theft.md) | verified | high | 2026-11-08 |
| [OAuth 扫码绑定/登录无二次确认：二维码钓鱼绑定受害者微信接管账号](web-generic-oauth-qr-bind-no-confirm-phishing.md) | verified | medium | 2026-11-08 |
| [OAuth 授权码窃取链：存储型 XSS + postMessage 泄露 code + SSO 绑定提权 + XXE 读文件](web-generic-oauth-postmessage-code-theft-sso-bind-xxe.md) | verified | high | 2026-11-06 |
| [OAuth 缺失 state + 账号绑定 CSRF：举报文章诱导管理员绑定攻击者 OAuth 账号接管后台](web-generic-oauth-missing-state-account-link-csrf-takeover.md) | verified | high | 2026-11-06 |
| [OAuth 隐式流程 access_token 窃取：redirect_uri 路径穿越 + /post/next 开放重定向 + JS 把 fragment token 外带](web-generic-oauth-token-theft-open-redirect-fragment.md) | verified | high | 2026-11-08 |
| [OAuth 隐式流程客户端 /authenticate 信任请求体 email：用自己的 token 改 email 即可登录他人账户](web-generic-oauth-implicit-flow-authenticate-email-trust.md) | verified | high | 2026-11-08 |
| [OpenID 动态客户端注册 logo_uri 服务端拉取 SSRF：注册任意 logo_uri 后 /client/<id>/logo 读取云元数据凭证](web-generic-oauth-dynamic-client-registration-logo-uri-ssrf.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
