---
id: web-generic-auth-login-page-prefilled-password-type-unmask
title: 登录页预填管理员口令：把 password 输入框改成 text 或读 value 直接取明文
type: scenario
domain: web
path: web/generic/auth
technique: login-page-prefilled-password-unmask
aliases:
- 登录页密码回显
- input type password 改 text
- 预填口令泄露
- 管理员口令明文
- 前端自动填充密码
- 密码框改 text
tags:
- web
- auth
- frontend
- credential-leak
- password
- dom
- admin-panel
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V298
  verified_at: '2026-11-08T08:00:01+08:00'
  notes: 已对照原文与28张图核对：原文“页面自动显示账号密码、密码加密了、把password改掉即可回显”，图20为预填口令登录页、图21为devtools中type=password、图22改type=TEXT后显示admin123、图23登录后台，卡片描述与截图行为一致；编码值/解码函数作为变体给出且明确为条件式。原文无版本，未设versions。未对真实站点操作。
---

## 一句话结论

部分后台登录页为了演示或“方便”，把管理员账号和口令直接预填在表单的 `value` 里；`type="password"` 只是视觉遮罩，不改变 DOM 中的值。把输入框改成 `type="text"`（或直接读 `input.value`）即可得到明文口令，随后直接用该账号登录后台；若口令经过可逆编码，则需要同时找到页面里的解码函数。

## 原理

- **password 类型只负责遮罩**：`<input type="password" value="...">` 在页面上显示为圆点，但 `value` 属性/属性值仍在 DOM 中，任何能打开开发者工具的人都能读取；改 `type` 为 `text` 只是让浏览器把同一字符串按明文渲染。
- **口令为何会出现在前端**：开发/演示环境为了免输入，把 admin 账号与口令写进模板或由接口下发后填表；上线时未删除。另一种是“记住密码”功能把口令编码后存入 localStorage/Cookie，页面加载时回填到 password 框。
- **编码不等于加密**：若回填值是一串 Base64/十六进制/自定义字符表编码，页面必然带有对应的解码函数（或服务端在登录时接收编码值），攻击者可复用该函数还原；真正的服务端加密不应把可解密材料下发给未认证用户。
- **为什么能直接登录**：口令就是管理员真实口令（或可直接提交的等价凭证），登录接口按正常流程校验通过；这不是绕过认证，而是凭证泄露。
- **与前端硬编码闸门的区别**：本场景泄露的是登录凭证，危害是直接进入后台；前端硬编码编辑口令卡（[[web-generic-auth-frontend-hardcoded-edit-password-gate]]）泄露的是客户端写权限开关，二者利用点不同。

## 触发条件

- 目标登录页在未认证状态下预填了账号和口令（模板写死、演示数据、记住密码回填）。
- 输入框的 `value` 是明文口令，或页面 JS 中存在可复用的解码函数。
- 登录接口接受该口令，且未启用 MFA/设备绑定/验证码（或有验证码但可正常识别）。
- 已获得授权；不要用泄露凭证做未授权访问。

## 利用步骤

1. **查看登录页源码/DOM**：搜索 `type="password"`、`value=`、`autocomplete`、`localStorage`、`remember` 等关键字，确认是否存在预填值。
2. **改类型或读值**：在开发者工具中把 `type` 改为 `text`，或执行 `document.querySelector('input[type=password]').value`；若显示明文，直接得到口令。
3. **处理编码值**：若 value 是 Base64/十六进制/自定义编码，搜索页面 JS 中的 `atob`、`decrypt`、`decode`、字符表等函数，或抓取登录请求看提交的是否就是该编码值；必要时在控制台调用页面自带函数还原。
4. **登录验证**：用泄露的账号口令走正常登录流程；若需要验证码，先获取并识别。
5. **确认权限**：登录后确认是否为管理员、可访问哪些模块；记录证据与时间。
6. **扩大同类资产**：用登录页固定文案/图片/JS 文件名做 body 检索，查找使用同一模板的其他站点；若同样预填，则可能批量命中（原文用鹰图检索到同模板站点并用相同口令登录成功）。
7. **留证与整改**：截图 DOM、登录成功页与请求；测试后通知移除预填值、修改口令。

## PoC

```javascript
// 在登录页控制台执行
document.querySelector('input[type="password"]').type = 'text';
document.querySelector('input[type="password"]').value;  // 或改类型前直接读取
```

```html
<!-- 典型的预填形态：value 就是真实口令，password 只是遮罩 -->
<input class="el-input__inner" type="password" value="admin123" autocomplete="off">
```

```text
若 value 为编码串：
1) 在 Sources/JS 中搜索 atob / decrypt / decode / 字符表；
2) 或在控制台调用页面暴露的解码函数；
3) 或抓登录请求，确认提交值是否可直接复用。
```

## 变体与关联

- **记住密码回填**：口令存在 localStorage/Cookie（常为 Base64/简单 XOR），页面加载时回填；读取存储或复用解码函数即可。
- **隐藏字段/注释**：口令写在隐藏 input、HTML 注释、JS 变量或 source map 中；结合 [[pentest-recon-sourcemap-leak-frontend-source-restore-api-discovery]]。
- **前端硬编码编辑口令**：不是登录凭证而是客户端写权限闸门，见 [[web-generic-auth-frontend-hardcoded-edit-password-gate]]。
- **默认/弱口令**：若页面未预填，仍可尝试产品默认口令，见 [[pentest-initial-access-ruoyi-default-weak-credentials]]。
- **边界**：若 value 只是占位符/提示文本、口令由服务端在登录时一次性下发且绑定会话，或页面仅回填用户名，则本场景不成立。

## 检测与防御

- **修复**：登录页绝不预填真实口令；演示数据上线前清理；不要在 HTML/JS/localStorage 中存放可解密的管理员凭证。
- **加固**：服务端认证 + MFA；对管理员账号启用 IP 白名单/设备绑定；口令定期轮换；前端只做展示，不作为凭证来源。
- **检测**：扫描登录页 HTML/JS 中的 `type="password" value=`、`localStorage` 口令字段、Base64 长串；监控同一口令在多个来源 IP 的登录；对管理员登录做异常告警。
- **认知**：password 类型不是安全边界；只要凭证到达浏览器，就必须视为已泄露。
