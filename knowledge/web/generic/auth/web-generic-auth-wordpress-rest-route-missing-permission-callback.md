---
id: web-generic-auth-wordpress-rest-route-missing-permission-callback
title: WordPress 插件 register_rest_route 省略 permission_callback：Brevo Sendinblue 订阅接口未授权可调（CVE-2025-66128）
type: scenario
domain: web
path: web/generic/auth
technique: wordpress-rest-missing-permission-callback
aliases:
- CVE-2025-66128
- Brevo Sendinblue 授权缺失
- WooCommerce Sendinblue 未授权
- WordPress REST 权限回调缺失
- subscription/update-status 未授权
tags:
- web
- wordpress
- rest-api
- authorization
- missing-permission-callback
- plugin
- php
- cve-2025-66128
cve:
- CVE-2025-66128
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: <= 4.0.49（原文标记）
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:01:28+08:00'
  notes: 已对照原文与6张图核对：POST /wp-json/sendinblue/v1/subscription/update-status 在 {}、非法参数、伪造 Referer、batch_data、直接路由、X-Forwarded-For 场景均返回200 success:true，与图01-06一致；ApiManager::add_rest_endpoints 的 /configs、/disconnect、/emailsettings 路由缺 permission_callback，save_settings/email_settings/get_file_contents/delete_attachment 无权限校验，与原文代码分析一致；CVE-2025-66128、<=4.0.49 与原文一致。核心 PoC 为订阅状态接口；配置/文件接口为代码层结论，卡内已作变体标注。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

WooCommerce Brevo Sendinblue 插件在 `ApiManager::add_rest_endpoints()` 中用 `register_rest_route()` 注册 REST 路由时没有提供 `permission_callback`，回调函数内部也没有补充权限判断，导致未登录攻击者可直接调用 `/wp-json/sendinblue/v1/subscription/update-status` 等接口，篡改订阅状态、改插件配置或操作插件上传目录文件。

## 原理

- WordPress REST API 的 `register_rest_route($namespace, $route, $args)` 通过 `$args['permission_callback']` 决定谁能调用该路由；省略该参数时，路由默认对所有访问者开放（包括未认证游客），WordPress 仅可能给出开发提示，不会自动拒绝请求。
- 插件把所有路由定义成数组（`method`、`callback`），循环注册时只传了 `methods` 和 `callback`，注释明确写着“核心漏洞：未添加 permission_callback 参数”。
- 回调函数如 `save_settings()` 直接 `update_option(SENDINBLUE_WC_SETTINGS, $request->get_body())`、`email_settings()` 直接改邮件配置、`disconnect_connection()` 直接断开连接；`get_file_contents()` / `delete_attachment()` 只对文件名做 `basename` 和字符过滤，没有校验调用者身份或角色，即可读取/删除插件上传目录中的文件。
- 文件中虽然存在 `validate_api_key()`，但它没有被任何路由的 `permission_callback` 复用，仅校验 API key 且未覆盖所有敏感接口，权限校验形同虚设。
- 根因是“把路由是否公开交给框架默认值”，而不是显式声明权限；只要插件作者漏写 `permission_callback`，所有回调就暴露在未认证攻击面。

## 触发条件

- 目标安装 WooCommerce Brevo Sendinblue 插件 <= 4.0.49（原文标记）。
- WordPress 启用了 REST API（默认 `/wp-json/` 可访问），插件已初始化并注册路由。
- 目标路由未被 WAF/安全插件额外拦截，或攻击者能绕过其规则。
- 攻击者无需任何账号或 API key。

## 利用步骤

1. 探测 `/wp-json/` 与 `/wp-json/sendinblue/v1/`，确认插件 REST 命名空间存在。
2. 向 `/wp-json/sendinblue/v1/subscription/update-status` 发送 POST JSON，`email`、`list_id`、`status` 任意填写，观察是否返回 200 与 `success: true`。
3. 尝试无参数、非法参数格式、伪造 `Referer`、不同来源 IP，确认无参数/格式/Referer/IP 限制（原文逐项验证均返回 200）。
4. 进一步调用 `/configs`（PUT）、`/emailsettings`（PUT）、`/disconnect`（GET）等路由，验证配置修改/断开连接；如存在文件操作路由，可读取或删除插件上传目录文件。
5. 记录未认证请求与响应作为证据；避免对生产站点做破坏性配置修改。

## PoC

未认证篡改订阅状态：

```http
POST /wp-json/sendinblue/v1/subscription/update-status HTTP/1.1
Host: target
Content-Type: application/json

{"email":"test@example.com","list_id":1,"status":"unsubscribed"}
```

```text
HTTP/1.1 200 OK
{"success":true,"message":"Route registered and triggered successfully",
 "data":{"email":"test@example.com","list_id":1,"status":"unsubscribed"}}
```

无参数请求（`{}`）同样返回 `success:true`，`data` 中字段为 `none`，说明参数校验与权限校验均缺失。批量数组 `{"batch_data":[{...},{...}]}` 也返回 200。

## 变体与关联

- 变体：`/configs` 与 `/emailsettings` 直接写入 `update_option`，可篡改插件配置/邮件设置，进一步钓鱼或中断营销邮件。
- 变体：`get_file_contents` 读取插件上传目录文件（Base64 返回），`delete_attachment` 删除文件；虽做了文件名过滤，但无权限校验，仍可未授权操作。
- 变体：其他 WordPress 插件同样常因漏写 `permission_callback` 暴露 REST 接口；可用 `/wp-json/` 索引批量枚举命名空间与路由。
- 关联：[[web-generic-auth-wordpress-rest-header-password-check-missing]]（WordPress REST 回调鉴权逻辑缺陷的另一形态）。
- 关联：[[web-generic-auth-unauth-user-create-admin-takeover]]（未授权接口直接执行敏感操作导致接管）。

## 检测与防御

- 防御：每个 `register_rest_route()` 都必须显式提供 `permission_callback`；默认返回 `WP_Error('rest_forbidden', ..., 403)`，敏感接口叠加 `current_user_can('manage_options')` 或现有 `validate_api_key()`。
- 防御：不要信任 Referer/IP 作为唯一防护；对配置修改、文件操作接口要求 nonce + 管理员能力校验。
- 防御：升级插件到修复版本；若暂无补丁，可在 WAF/反向代理层阻断 `/wp-json/sendinblue/v1/` 的未认证访问。
- 检测：审计插件源码中 `register_rest_route` 是否缺少 `permission_callback`；监控未认证请求命中插件 REST 命名空间；同一 IP 批量调用订阅状态/配置接口；`update_option` 后配置异常变化。
- 检测：WordPress 调试日志中的 `_doing_it_wrong`（REST route missing permission_callback）提示；异常 Base64 文件内容响应。
