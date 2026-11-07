---
id: web-generic-auth-frontend-hardcoded-edit-password-gate
title: 前端硬编码编辑/发布口令：查看 JS 即绕过客户端写权限闸门
type: scenario
domain: web
path: web/generic/auth
technique: frontend-hardcoded-password-gate-bypass
aliases:
- 前端硬编码密码校验绕过
- 客户端写权限闸门绕过
- 报告平台编辑口令
- pso_report 口令
- 前端鉴权绕过
tags:
- web
- auth
- frontend
- hardcoded-secret
- client-side-auth
- authorization-bypass
- javascript
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:51:06+08:00'
  notes: 已对照图05/06核对；LOGIC_BYPASS命中password!=='pso_report'(Line775)与password!=='pso_publish'(Line894)，报告页面写入hacked by标记成功，与卡片一致；PoC未复跑
---

## 一句话结论

数据展示/报告平台把“编辑”和“发布”的授权实现为前端 JS 中的硬编码口令比较（如 `if (password !== '<EDIT_PASS>')`），攻击者查看打包产物即可获得口令，在界面输入后解锁编辑、修改报告内容并推送到后端，绕过正常的服务端鉴权。

## 原理

- 前端代码对所有访问者可见。若授权判断发生在浏览器：用户输入一个口令，JS 与硬编码常量比较，相等则把页面切换为可编辑/可发布状态，那么该口令不是秘密，只是混淆过的常量。
- 这类实现通常只控制 UI 状态：比较通过后，前端调用保存/发布接口；如果后端信任这些请求、没有基于服务端会话/角色的权限校验，攻击者无需真正“破解”任何认证就能写入或发布。
- 静态分析工具可以把 `password !== '...'` 识别为 `LOGIC_BYPASS (AST/CFG)` 硬编码比较，说明该模式在代码审计中很容易被自动发现；即使没有工具，搜索 `password`、`publish`、`edit`、`admin` 等关键字也能定位。
- 与正常登录的区别：正常认证应由服务端校验凭证并签发会话/角色；本例中服务端只接收前端“已解锁”后的写请求，授权边界被下放到客户端。
- 影响取决于写接口的权限：修改展示数据可造成内容篡改/信誉损失；若发布接口对接下游系统，还可能把恶意内容推送到生产。

## 触发条件

- 编辑/发布权限由前端口令或隐藏开关控制；
- 对应的保存/发布接口没有独立的服务端权限校验，或只校验弱会话；
- 前端打包产物可访问，未做服务端渲染隔离；
- 攻击者可访问目标页面并能触发保存/发布请求。

## 利用步骤

1. 打开目标页面，抓取加载的 JS bundle，搜索 `password`、`passwd`、`publish`、`edit`、`admin`、`mode` 等关键字。
2. 定位硬编码比较，例如 `if (password !== '<常量>')`；记录常量及比较后调用的函数/接口。
3. 在页面提示处输入该口令，或直接在控制台调用解锁函数/设置对应的全局状态，使 UI 进入编辑模式。
4. 修改一条测试数据并保存，抓包确认保存请求；再触发发布，确认后端接受了来自普通访问者的写操作。
5. 在授权范围内用无害内容验证（如写入可识别的测试标记），截图记录修改前后的页面与请求；测试后恢复数据。
6. 若前端只隐藏按钮但接口可直接调用，可跳过 UI，直接重放保存/发布请求。

## PoC

前端硬编码比较（示意，实际值应从目标 bundle 提取）：

```javascript
// 打包产物中的典型形态
if (password !== EDIT_PASS) {
    alert('口令错误');
    return;
}
enableEditMode();          // 仅切换前端状态
// 随后调用保存/发布接口
await fetch('/api/report/save', { method: 'POST', body: JSON.stringify(data) });
```

验证思路：

```text
1. 在 JS 中搜索 password !== 或硬编码字符串，得到 EDIT_PASS / PUBLISH_PASS。
2. 页面输入口令进入编辑模式，修改一条测试记录并保存。
3. 抓包确认 /api/report/save 或 /api/report/publish 返回成功。
4. 刷新页面/下游系统确认修改已生效。
```

原文中静态分析结果将两处比较标记为 `LOGIC_BYPASS (AST/CFG)`，并在报告页面写入测试标记，证明修改成功。

## 变体与关联

- 变体：前端隐藏管理员按钮、`window.isAdmin=true`、路由守卫、feature flag、`localStorage.role='admin'` 等客户端授权；共同点是服务端未复核。
- 变体：口令经过简单编码/拼接（Base64、字符数组）仍可从 JS 还原，见前端凭证提取卡。
- 关联：[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]（从混淆 JS 提取硬编码凭证）、[[web-generic-auth-vue-router-frontend-guard-bypass]]（前端路由守卫绕过）。
- 边界：后端对保存/发布接口做了服务端角色校验、口令由服务端下发且绑定会话、或写接口本身需要独立认证时，仅拿到前端口令无法完成写入。

## 检测与防御

- 检测：JS 中出现 `password !==`、`password ===` 与硬编码字符串比较；保存/发布接口被无相应角色的会话调用；同一账号/匿名来源短时间内修改大量展示数据。
- 修复：所有写操作在服务端做权限校验，基于会话/角色/资源归属，不信任前端“已解锁”状态；编辑与发布使用不同权限并记录审计。
- 修复：不要把口令、密钥或管理员开关写入前端；需要前端控制的仅限展示逻辑，不能作为授权依据。
- 加固：保存/发布接口增加 CSRF 防护、速率限制与内容审核；对关键数据保留版本与回滚能力。
