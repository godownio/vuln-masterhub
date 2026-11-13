# CSRF

## 这层是什么

CSRF 与 SameSite、Token 绕过。

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
| [CSRF + RPO + CSS 选择器侧信道窃取管理员 Token 与 Flag](web-generic-csrf-rpo-css-selector-side-channel.md) | verified | high | 2026-11-04 |
| [CSRF Token 仅在参数存在时校验：整体删除 csrf 参数即可绕过](web-generic-csrf-token-validation-presence-remove-parameter.md) | verified | high | 2026-11-12 |
| [CSRF Token 只在 POST 校验：切换 GET 方法绕过并借顶级导航完成 CSRF](web-generic-csrf-token-validation-request-method-get-bypass.md) | verified | high | 2026-11-12 |
| [CSRF Token 未绑定会话：用攻击者账户的合法 Token 为受害者构造 CSRF](web-generic-csrf-token-not-bound-to-session-cross-account-reuse.md) | verified | high | 2026-11-12 |
| [CSRF Token 绑定非会话 Cookie / 双重提交：借 Set-Cookie 注入写入攻击者 Cookie 后提交匹配 Token](web-generic-csrf-token-non-session-cookie-set-cookie-injection.md) | verified | high | 2026-11-12 |
| [CSRF 打本机 rclone RC API：config/create 的 sftp ssh / webdav bearer_token_command 执行命令，配合 sleep 时间盲注外带](web-generic-csrf-rclone-rc-config-create-command-exec.md) | verified | high | 2026-11-08 |
| [IceCMS 广场内容删除 CSRF（CVE-2023-42188）：无 CSRF Token 的跨站表单借管理员会话删帖](web-generic-csrf-icecms-square-delete-form.md) | verified | high | 2026-11-09 |
| [JSON 接口 CSRF：enctype=text/plain 表单直发 JSON 并利用 Referer 校验失效](web-generic-csrf-json-text-plain-form-enctype.md) | verified | high | 2026-11-05 |
| [Referer 弱校验绕过：攻击者子域或 URL query 携带目标域名 + unsafe-url 策略](web-generic-csrf-referer-weak-validation-subdomain-query-unsafe-url.md) | verified | high | 2026-11-12 |
| [Referer 校验依赖请求头存在：用 meta referrer=no-referrer 丢弃 Referer 绕过](web-generic-csrf-referer-header-presence-meta-referrer.md) | verified | high | 2026-11-12 |
| [SameSite=Lax 绕过：Chrome 顶级 POST 前 120 秒豁免窗口（登录后立即投递）](web-generic-csrf-samesite-lax-120s-cookie-refresh-post-window.md) | verified | high | 2026-11-12 |
| [SameSite=Lax 绕过：顶级 GET 导航 + _method 方法重写执行状态变更](web-generic-csrf-samesite-lax-bypass-method-override.md) | verified | high | 2026-11-12 |
| [SameSite=Strict 绕过：兄弟子域同站 + 跨站 WebSocket 劫持（CSWSH）窃取会话数据](web-generic-csrf-samesite-strict-bypass-sibling-domain-cswsh.md) | verified | high | 2026-11-12 |
| [SameSite=Strict 绕过：用同站客户端重定向 gadget 制造站内第二跳](web-generic-csrf-samesite-strict-bypass-client-side-redirect.md) | verified | high | 2026-11-12 |
| [Stock Management System 1.0 Users.php?f=save/delete 无 CSRF Token：管理员访问恶意页即被增删用户（CVE-2025-4282）](web-generic-csrf-sourcecodester-stock-users-save-delete.md) | verified | high | 2026-11-05 |
| [ZrLog 2.1.11 后台 JSON API 全站无 CSRF 校验：text/plain 表单跨站改邮箱（可接管）与改文章内容](web-generic-csrf-zrlog-admin-json-api-text-plain-all-endpoints.md) | verified | high | 2026-11-07 |
| [状态变更接口无 CSRF Token：跨站自动提交表单以受害者身份添加/删除数据](web-generic-csrf-missing-token-state-changing-endpoint.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
