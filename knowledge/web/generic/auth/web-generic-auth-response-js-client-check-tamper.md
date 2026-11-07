---
id: web-generic-auth-response-js-client-check-tamper
title: 响应包 JS 客户端鉴权可篡改：延长 getUserInfo 定时器绕过登出进入后台
type: scenario
domain: web
path: web/generic/auth
technique: response-js-client-check-tamper
aliases:
- 拦截响应
- getUserInfo 定时器
- Mini2.setTimer
- 前端鉴权
- 响应包修改
tags:
- web
- auth
- client-side
- response-tampering
- burp
- javascript
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:22:37+08:00'
  notes: 已对照原文与图29-34核对：响应 JS 中 setTimeout(getUserInfo,1000) 与 Mini2.setTimer(...,10*1000)，图33 改为 10000000*1000 后进入管理后台；卡内代码与篡改点一致。未复跑 PoC；是否能取到数据仍取决于服务端接口鉴权，卡内已注明。
---

## 一句话结论

登录后的页面在响应体 JS 中用 `setTimeout(getUserInfo, 1000)` 与 `Mini2.setTimer(function(){ getUserInfo(); }, 10*1000)` 周期性检查身份，检查失败就登出/跳转；用 Burp 拦截响应，把定时器改成 `10000000*1000`（或删掉调用）再放行，客户端不再执行登出检查，配合仍然有效的服务端 Session 即可进入后台管理界面。

## 原理

- 身份校验逻辑被放在后端返回的 JS 里：页面加载 1 秒后调用 `getUserInfo()`，并每 10 秒再调用一次；`getUserInfo` 内部用 `$.ajax` 请求用户信息，失败时显示离线提示/跳转登录。
- 浏览器执行的是响应中的 JS 文本；攻击者作为中间人（Burp 代理）可以修改响应体，把 `10*1000` 改成 `10000000*1000`，或删除 `setTimeout`/`setInterval` 调用，让检查永不触发。
- 页面能否真正访问后台，取决于服务端 Session/接口鉴权：如果服务端已经下发有效 Session 且后台接口没有独立授权校验，客户端检查就是唯一门槛，篡改后即可访问；如果服务端每个接口都校验权限，则只能绕过页面跳转、无法获得数据。
- 本题在篡改响应后进入管理员后台，能够对数据增删查改、查看多年订单，说明服务端接口也缺少/弱化了权限校验。
- 这不是“破解 JS 加密”，而是“客户端安全控制不可信”：任何只存在于浏览器的鉴权/登出/隐藏逻辑都可以被代理或 DevTools 修改。

## 触发条件

- 目标需要登录，但攻击者没有可用账号（或只有低权限账号）。
- 登录/进入页面后的响应体包含前端鉴权 JS（定时器、`eval`、`getUserInfo`、跳转逻辑）。
- 攻击者能拦截并修改响应（Burp/中间代理/本地 DevTools）。
- 服务端 Session 或接口权限没有独立、完整地校验（否则只能绕过 UI，拿不到数据）。

## 利用步骤

1. 正常访问登录页/目标页，抓包观察响应体中的 JS，定位 `getUserInfo`、`setTimeout`、`Mini2.setTimer`、登出/跳转逻辑。
2. 在 Burp 中开启“拦截 → 响应此请求”，或使用 Repeater/响应修改规则。
3. 把周期从 `10 * 1000` 改为 `10000000 * 1000`，或删除 `getUserInfo()` 调用/`setTimeout`。
4. 放行响应，浏览器加载修改后的 JS；确认不再跳转登录。
5. 访问后台功能（用户管理、订单、数据增删查改），用接口返回验证权限。
6. 若只是 UI 绕过，继续测试后台 API 是否缺少服务端鉴权；必要时枚举接口。

## PoC

原始响应 JS（示意）：

```javascript
$(document).ready(function () {
    setTimeout(function () {
        AddTab("...", "用户桌面", false, false);
    }, 500);

    setTimeout(getUserInfo, 1000);
    Mini2.setTimer(function () {
        getUserInfo();
    }, 10 * 1000);
});
```

篡改后：

```javascript
    Mini2.setTimer(function () {
        getUserInfo();
    }, 10000000 * 1000);
```

Burp 操作：`Proxy → Intercept → 响应此请求`（或 `Options → Match and Replace` 对响应体做正则替换）。

## 变体与关联

- **响应字段篡改**：把 `success:false`/`statusCode:500` 改为 `true`/`200` 跳过短信验证；见 [[web-generic-auth-password-reset-response-tampering-sms-bypass]]。
- **前端路由守卫**：Vue Router `beforeEach` 只检查 localStorage token，可伪造/清空；见 [[web-generic-auth-vue-router-frontend-guard-bypass]]。
- **隐藏字段/前端权限**：只在前端隐藏管理菜单，接口未鉴权；直接请求 API。
- **JS 加密/签名**：前端加密不等于安全，算法和密钥都可提取；见 [[web-generic-auth-miniprogram-digest-md5-path-timestamp]]。

## 检测与防御

- 所有权限判断必须在服务端每个接口执行；前端只做展示与交互，不作为安全边界。
- 登出/会话过期由服务端 Session/JWT 失效控制，不能依赖页面定时器。
- 对后台接口做统一鉴权中间件与对象级授权；对未授权访问返回 401/403 并记录。
- 检测：客户端出现周期性 `getUserInfo` 调用、响应 JS 包含权限判断；服务端日志中同一 Session 访问大量管理接口但未经过登录/授权流程。
