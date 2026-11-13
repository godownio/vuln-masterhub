---
title: 开放重定向
weight: 1
---

# 开放重定向

## 这层是什么

重定向绕过与 OAuth/SSO 组合利用。

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
| [Activiti 工作流表单 formKey 未校验：上传 BPMN 控制 formKey 触发 sendRedirect 开放重定向](web-generic-open-redirect-activiti-formkey-sendredirect/) | verified | high | 2026-11-06 |
| [Google DoubleClick adurl 开放重定向：钓鱼 PDF 内嵌广告点击链接把受害者导向恶意 MSI 站点](web-generic-open-redirect-doubleclick-adurl-pdf-phishing/) | verified | high | 2026-11-11 |
| [Shiro 未登录重定向的 Location 取 Host 头：任意 Host 注入导致开放重定向与会话 ID 泄露](web-generic-open-redirect-shiro-login-redirect-host-header/) | draft | high | 2026-11-05 |
| [WebOb <1.8.11 开放重定向：前导空白 + 协议相对 URL 绕过校验（CVE-2026-54770）](web-generic-open-redirect-webob-whitespace-urljoin-mismatch/) | verified | high | 2026-11-05 |
| [WordPress begin lts 主题 go.php 开放重定向：/wp-content/themes/begin lts/inc/go.php?url= 直接 302 到任意外站](web-generic-open-redirect-wordpress-begin-theme-go-php/) | verified | medium | 2026-11-09 |
| [分享/二维码生成接口的开放重定向：篡改 url/targeturl 参数让扫码者跳转钓鱼站（附跳转参数与业务位置清单）](web-generic-open-redirect-qrcode-share-url-param/) | verified | high | 2026-11-08 |
| [客户端重定向载体：meta http-equiv=refresh 与 SVG onload 的 window.location 跳转](web-generic-open-redirect-meta-refresh-svg-onload-vectors/) | verified | high | 2026-11-09 |
| [开放重定向 + 任意文件上传链：在白名单文件域上传自动跳转 HTML，借可信域中转绕过跳转白名单](web-generic-open-redirect-upload-html-whitelisted-domain-chain/) | verified | medium | 2026-11-09 |
| [开放重定向白名单子串缺陷：校验只判断“包含 victim.com”，注册 testvictim.com 类形似域即可通过](web-generic-open-redirect-whitelist-substring-lookalike-domain/) | verified | high | 2026-11-09 |
| [开放重定向的 URL 解析歧义绕过：@、反斜杠/斜杠、问号/井号、协议省略与编码分隔符让白名单与浏览器各看各的](web-generic-open-redirect-url-parser-confusion-bypass/) | verified | high | 2026-11-09 |
| [开放重定向的嵌套参数与可信站 302 接力：改最内层 url 或借白名单内站点的跳转，绕过只允许可信域的校验](web-generic-open-redirect-nested-trusted-chain-bypass/) | verified | high | 2026-11-09 |
| [微信安全中心 readtemplate 模板的 url 参数开放重定向：高信任域跳转配合滑块验证，可用于钓鱼](web-generic-open-redirect-wechat-security-readtemplate-url/) | verified | medium | 2026-11-09 |
| [被交互触发的开放重定向测试盲点：登录按钮点击后才跳转、POST 图片地址预览/审核点开触发](web-generic-open-redirect-interaction-triggered-and-post-param/) | verified | medium | 2026-11-09 |
| [请求走私触发 Host 头重定向：走私 GET 携带攻击者 Host，使下一受害请求收到 301 跳转](web-generic-open-redirect-smuggled-host-header-301/) | verified | medium | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
