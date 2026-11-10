---
id: web-generic-auth-captcha-double-md5-jsrpc-yakit-login-bruteforce
title: 挑战码+双重 MD5 登录加密的 JSRPC 爆破：Sekiro action 内先取 captcha 再算 hex_md5(captcha+hex_md5(pwd))，Yakit 双请求序列提取密文批量登录
type: scenario
domain: web
path: web/generic/auth
technique: captcha-double-md5-jsrpc-yakit-login-bruteforce
aliases:
- jsrpc 登录爆破
- Sekiro 加密登录爆破
- 挑战码双重 MD5
- hex_md5(captcha+hex_md5(password))
- Yakit fuzz sequence 提取密文
- 前端加密口令爆破
- 油猴 XHR hook 定位登录加密
tags:
- web
- auth
- brute-force
- js-reverse
- jsrpc
- sekiro
- yakit
- md5
- captcha
- login
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V463-fix
  verified_at: '2026-11-10T15:11:51+08:00'
  notes: V463 指出步骤5/PoC 对 captcha 多算一次 MD5：图05/08 实际为 hex_md5(captcha + hex_md5(password))，captcha 原样拼接、仅口令内层 MD5。已修正步骤5 与 PoC 的 cipher 计算（captcha + hex_md5(pwd)）。
---

## 一句话结论

登录密码在前端被 `hex_md5(captcha + hex_md5(password))` 处理，且 `captcha` 是服务端按会话下发、需要每次重新获取的挑战码；不必还原或复刻算法，把页面里的取码 XHR 与 MD5 函数一起注册成 Sekiro 的 JSRPC action（一次调用完成“取挑战码 + 算密文”），再在 Yakit 里用双请求 fuzz 序列——请求 1 带明文口令调 invoke 拿密文、提取 `data`，请求 2 用该密文作 `password` 发送登录包——即可对字典中的每个口令自动生成合法密文并批量登录。

## 原理

- **定位加密点**：用油猴 HookScript 之类的脚本 hook `XMLHttpRequest.prototype.send`（或 `open`、`JSON.parse`、`document.cookie` setter），在请求发出前 `debugger` 断下；从调用栈（`send → ajax → nfn → showLogin.html`）回跳，就能在登录函数里看到明文变量 `data` 与随后的赋值 `data.password = hex_md5(captcha + hex_md5(data.password))`。同一口令多次登录得到的密文不同，说明有随机量/挑战码参与——本例中该变量来自 `GET /index.php/Admin/Login/getcaptcha` 返回的 `captcha`。
- **为什么不能离线复刻一次**：captcha 由服务端按会话生成，每次登录（或每次取码）都可能变化；只抓一次密文重放或只算一次 `hex_md5(hex_md5(pwd))` 都不对。必须在同一个会话里“先取当前挑战码，再算双重 MD5”。
- **JSRPC 复用页面函数**：Sekiro 是一个 JSRPC 框架，浏览器页面注入客户端后通过 WebSocket 连到本地服务端（默认 `127.0.0.1:5612`）；页面里把原函数提到全局（如 `window._hex_md5 = hex_md5`、`window._xhr = xhr`），再 `client.registerAction("login", ...)`，action 内部执行 `xhr("GET", getcaptcha)` 拿挑战码并计算密文返回。这样即使 `hex_md5`/`xhr` 位于闭包或混淆代码中，也能被远程调用。
- **Yakit 双请求序列**：序列模式下 Step0 是 `GET http://127.0.0.1:5612/business-demo/invoke?group=<组>&action=login&pwd={{payload(字典)}}`，响应中的 `data` 即密文；用数据提取器存为 `data_0`，Step1 的登录包写 `username=admin&password={{p(data_0)}}`；Fuzzer 对字典每个口令跑一遍序列，服务端看到的是每口令对应、带当前挑战码的合法密文。
- **为什么成立**：前端加密与挑战码对任何持页面会话的用户可见；JSRPC 把“浏览器里跑真函数”变成可编程接口；服务端只校验最终密文，无法区分人工登录与自动化序列。前提是挑战码获取无真实人机验证/限次、登录接口缺少频率限制或设备指纹风控。
- **响应判别**：本例登录成功返回 302（跳转），失败返回 200/错误 JSON，可用状态码或响应关键字筛选命中。

## 触发条件

- 登录接口的 `password` 等字段由前端 JS 生成密文，且依赖服务端下发的挑战码/captcha（不是固定 key 的纯函数）。
- 挑战码接口可直接按会话获取（无图形验证码识别、无一次性强绑定或可绕过），登录接口无验证码/频控/设备指纹。
- 能保持有效会话 Cookie，并能向页面注入油猴脚本或在 Console 执行 Sekiro 客户端代码。
- 浏览器与本地 Sekiro 服务端互通（默认 5612 端口），未被 CSP/企业策略阻断 WebSocket。

## 利用步骤

1. 抓包观察登录请求；用 HookScript 选“发送 POST 请求时断点”（第 4 项）或“XMLHttpRequest 调用断点”（第 3 项），提交一次登录命中断点。
2. 沿调用栈向上回跳（`send → ajax → nfn → 登录函数`），确认此时 `data` 仍是明文、随后被 `hex_md5(captcha + hex_md5(password))` 赋值覆盖；记录 captcha 的获取方式与接口。
3. 同一口令重复登录，确认密文每次不同（挑战码在变）；在 Console 里手工调用一次原函数验证算式。
4. 把页面里的 `hex_md5`、`xhr` 等函数提升到 `window` 全局，或直接写等价包装。
5. 启动本地 Sekiro 服务端（`bin/sekiro.bat` / `sekiro.sh`），加载改过 match 域名的 jsrpc 油猴脚本：`registerAction("login")` 内先 `xhr("GET", getcaptcha)` 取挑战码，再返回 `hex_md5(captcha + hex_md5(pwd))`（captcha 原样拼接，仅口令做内层 MD5）。
6. 用浏览器会话打开 invoke 验证：`GET http://127.0.0.1:5612/business-demo/invoke?group=<组>&action=login&pwd=123`，响应 `data` 为密文。
7. 在 Yakit Web Fuzzer 配置序列：Step0 用明文口令字典作为 `pwd` 调 invoke，数据提取器 `data_0 = $.data`；Step1 `POST /login` 带 `username=admin&password={{p(data_0)}}` 与同会话 Cookie；执行并按 302/成功标识筛结果。
8. 命中后复核登录状态与账号权限，记录速率与影响，停止测试。

## PoC

```javascript
// 页面侧：把原函数提升全局后注册 JSRPC action（函数名以目标页面为准）
window._hex_md5 = hex_md5;   // 页面里实际的 MD5 函数
window._xhr = xhr;           // 页面里实际封装过的 XHR 函数
const client = new SekiroClient(
  "ws://127.0.0.1:5612/business-demo/register?group=test_cha11&clientId=" + Math.random()
);
client.registerAction("login", function (request, resolve, reject) {
  try {
    const captcha = window._xhr("GET", "/index.php/Admin/Login/getcaptcha"); // 每次取新挑战码
    const cipher = window._hex_md5(
      captcha + window._hex_md5(request["pwd"])   // captcha 原样拼接，仅口令做内层 MD5
    );
    resolve(cipher);
  } catch (e) { reject(e); }
});
```

```text
# Yakit Web Fuzzer 序列（示意）
Step 0: GET http://127.0.0.1:5612/business-demo/invoke?group=admin_01y_com&action=login&pwd={{payload(常用弱口令)}}
        -> 提取器 data_0 = $.data
Step 1: POST /index.php/Admin/Login/login HTTP/1.1
        Content-Type: application/x-www-form-urlencoded
        Cookie: <与浏览器相同的会话>

        username=admin&password={{p(data_0)}}
# 响应 302 视为登录成功跳转，按此筛选命中
```

## 变体与关联

- **同类运行时复用**：签名接口可用同一套 Sekiro/JSRPC 思路批量代签，见 [[web-generic-auth-sekiro-jsrpc-yakit-hotload-rensign-batch]]；该卡是纯函数签名，本卡是在 action 内带状态地“取挑战码再算密文”，Yakit 侧需要双请求序列与数据提取器。
- **定位手段**：Hook `JSON.stringify`/`atob` 等明文点定位加密函数见 [[code-analysis-reverse-obfuscation-vjstools-plaintext-hook-encryption-locate]]；本卡的 HookScript 属于 XHR/POST 断点变体。
- **无限 debugger**：页面带反调试时先按 [[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]、[[code-analysis-reverse-anti-debug-js-dynamic-debugger-hook]] 处理。
- **纯算法复刻路线**：固定 key/iv 或 RSA+AES 的场景可离线复刻，见 [[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]；本卡适用于依赖挑战码、无法离线复算的场景。
- **变体**：挑战码可来自接口返回、页面隐藏字段或 Cookie；哈希可换 SHA1/SHA256 或多层盐；也可用 Burp+JSRPC/autoDecoder 替代 Sekiro+Yakit，链路本质相同。

## 检测与防御

- **检测**：同一账号/会话在短时间内大量登录请求且每次密文均不同（每请求都取了新挑战码）；`getcaptcha` 接口被高频调用且无页面渲染/人工交互；本机存在 `127.0.0.1:5612` 等 JSRPC 端口 WebSocket 长连接。
- **防御**：挑战码应与人机验证绑定（图形/滑块/行为验证），限制获取频率与有效期；登录接口按账号/IP/设备做频控、失败锁定与告警。
- **防御**：前端加密/哈希不能作为安全边界；口令校验、验证码与风控必须在服务端完成，敏感接口加一次性 nonce 与严格时间窗。
- **加固**：前端反调试只能提高分析成本；发现批量登录时封禁会话并排查同源 JSRPC 脚本痕迹。
