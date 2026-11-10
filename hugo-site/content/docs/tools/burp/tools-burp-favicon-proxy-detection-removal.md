---
id: tools-burp-favicon-proxy-detection-removal
title: Burp 代理检测与指纹消除：http://burp/favicon.ico 跨域 img onload 探测，及删 favicon/代理例外/关闭 Web 接口三种规避
type: scenario
domain: tools
path: tools/burp
technique: burp-proxy-favicon-detection-removal
tags:
- burp
- proxy-detection
- favicon
- anti-detection
- javascript
- img-onload
- testing-environment
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V441
  verified_at: '2026-11-09T22:18:22+08:00'
  notes: 已对照幻灯片逐图核对：图05 http://burp/favicon.ico 跨域 img+onload 检测与 alert('found burp') 实测截图、图06 zip -d burpsuite_pro.jar resources/Media/favicon.ico / 不代理列表 burp+127.0.0.1+localhost / Disable web interface at http://burpsuite 三种规避与幻灯片一致；文章为会议幻灯片无版本/CVE；未实测。
url: /docs/tools/burp/tools-burp-favicon-proxy-detection-removal/
draft: false
kb_aliases:
- Burp 检测
- http://burp/favicon.ico
- found burp
- 删除 burpsuite favicon
- 代理指纹消除
- Disable web interface at http://burpsuite
---

## 一句话结论

Burp 在代理端口上同时提供 `http://burp/`（以及 `http://burpsuite`）的本地 Web 接口用于分发 CA 证书；目标站点可以在页面里放一个 `<img src="http://burp/favicon.ico" onload=...>`，利用图片跨域加载成功与否判断浏览器是否走了 Burp，从而弹窗、阻断或返回假数据。把 favicon 从 Burp jar 中删除、把 `burp/127.0.0.1/localhost` 设为不代理、并关闭 Burp 的 Web 接口，即可消除该指纹继续测试。

## 原理

- Burp 的代理监听器不只是 HTTP 代理：访问 `http://burp/` 或 `http://burpsuite` 时，Burp 会返回自己的欢迎页/CA 证书下载页，页面里带有 favicon（`resources/Media/favicon.ico`）。
- 浏览器端的 `<img>` 加载不受同源策略限制（图片可以跨域加载，CORS 只限制读取内容），且 `onload` 事件在图片成功解码时触发。因此目标页面无需读取响应内容，只要观察 onload/onerror 就能判断 `http://burp/favicon.ico` 是否可达。
- 当浏览器配置 Burp 代理时，`http://burp` 被代理到 Burp 自己的本地接口，favicon 加载成功 → `onload` 触发；不使用 Burp 或已屏蔽该地址时加载失败 → `onerror`。这就成了一个零交互的代理检测侧信道。
- 检测到之后，站点可以弹窗提示、拒绝继续操作，或对返回数据做混淆/假数据，干扰安全测试；这也是一种简单的防自动化/反测试手段。
- 规避的关键是让浏览器对 `http://burp` 的请求不经过 Burp、且 Burp 不再提供该页面：三者组合后图片必然加载失败，检测逻辑失效。

## 触发条件

- 目标页面/APP 内嵌 WebView 包含类似的代理检测 JS（常见于金融、电商等对抓包敏感的业务）。
- 测试者浏览器通过 Burp 代理访问目标，且 Burp 默认 Web 接口未被关闭。
- 页面允许执行内联/外部 JS 并加载图片（CSP 未禁止 `img-src http://burp`）。

## 利用步骤

1. 复现检测：在浏览器控制台或页面中运行 `<img src="http://burp/favicon.ico" onload="alert('found burp')">`；走 Burp 代理时会弹出 `found burp`，不走则无反应。
2. 定位检测代码：在页面 JS 中搜索 `burp`、`favicon.ico`、`new Image()`、`onload` 等关键字，确认检测点与后续阻断逻辑。
3. 删除指纹：从 Burp 安装目录的 `burpsuite_pro.jar` 中删除 favicon：
   ```bash
   zip -d burpsuite_pro.jar "resources/Media/favicon.ico"
   ```
4. 设置代理例外：在 Burp/浏览器代理设置的“不代理的地址列表”加入 `burp`、`127.0.0.1`、`localhost`（支持通配符），使对 `http://burp` 的请求不进入 Burp。
5. 关闭 Web 接口：Burp → Proxy → Options → Miscellaneous → 勾选 `Disable web interface at http://burpsuite`（图中选项）。
6. 重新加载页面验证不再触发检测；如仍被识别，检查是否还有其他指纹（`http://burpsuite` 页面特征、CA 证书端点、代理响应头等）。

## PoC

```html
<!-- 检测逻辑（页面侧） -->
<img src="http://burp/favicon.ico" onload="alert('found burp')" onerror="console.log('no burp')">
```

```bash
# 去除 Burp 自带 favicon 指纹
zip -d burpsuite_pro.jar "resources/Media/favicon.ico"
# 代理例外列表（Burp 或系统代理设置）：burp / 127.0.0.1 / localhost
# Burp: Proxy -> Options -> Miscellaneous -> Disable web interface at http://burpsuite
```

## 变体与关联

- 变体：检测 `http://burpsuite` 的页面标题/内容、CA 证书下载页、`/cert` 等 Burp 特有路径，或利用响应时间差异；删除 favicon 后这些端点仍可能存在，需要一并关闭 Web 接口。
- 变体：其他抓包工具（mitmproxy、Charles、Fiddler）也有各自的本地端点/证书指纹，可被同样方式探测；透明代理/上游代理可减少浏览器侧特征。
- 关联：[[mobile-android-anti-detection-root-emulator-proxy]]（移动端代理/root/模拟器检测与规避）、[[mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection]]（绕过系统代理检测）、[[tools-burp-encrypted-api-proxy-decrypt-resign]]（代理链测试环境）。
- 边界：检测依赖浏览器能访问 `http://burp`；已使用上游代理、透明代理或非浏览器客户端时该方法可能失效；站点若用服务端指纹则不适用。

## 检测与防御

- 防守视角：页面级代理检测只能提高测试成本，不能作为安全边界；不要据此放行/拒绝业务请求，真正的防护应放在服务端鉴权、风控与数据加密上。
- 若确实要检测自动化/代理环境，应结合服务端信号（TLS/JA3、IP 信誉、行为序列、请求头一致性）综合判断，而不是单一 `http://burp` 图片探测。
- 监测：页面出现大量对 `http://burp/favicon.ico` 的请求（来自正常用户浏览器）本身说明站点在探测客户端环境，可在前端代码审计时记录该行为。
