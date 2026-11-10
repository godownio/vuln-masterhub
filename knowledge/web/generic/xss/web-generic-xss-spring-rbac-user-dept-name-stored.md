---
id: web-generic-xss-spring-rbac-user-dept-name-stored
title: Spring Boot RBAC 后台用户/部门名称存储型 XSS：低权用户写入，管理员列表查看时触发
type: scenario
domain: web
path: web/generic/xss
technique: spring-rbac-user-dept-name-stored-xss
aliases:
- 后台用户姓名 XSS
- 部门名称 XSS
- 存储型 XSS 后台
- Layui 表格 XSS
- 管理员列表 XSS
- my-springsecurity-plus XSS
tags:
- web
- xss
- stored-xss
- java
- spring-boot
- rbac
- admin-panel
- layui
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:31:39+08:00'
  notes: 已对照原文与全部61张图核对：用户管理新增 caigo888 姓名填 <script>alert('菜狗安全')</script>（图29 表单）、创建即弹窗（图30）、管理员查看用户列表再次触发；部门管理新增部门名称同 payload（图31 表单）并在部门管理页弹窗（图32）；低权账号 caigo8 可见并操作用户/部门管理（图30）；原文明确最新版仍未校验（正文『这个最新的也有，没对参数做校验』）。卡内触发条件/防御与原文一致。原子性：同一存储型 XSS 技术在用户姓名/部门名称两个字段的实例，属单卡可接受的同技术多入口，不标 split。未验证点：未复跑环境；无版本号，未设 affected_versions；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，admin-blind-registration 等仅同 sink 不同入口/语言；dup-scan 中本卡与同篇 IDOR 卡 pair 判定 related（不同技术），两张均保留。
---

## 一句话结论

Spring Boot + SpringSecurity 的 RBAC 后台若对用户姓名、部门名称等字段不做输入校验/输出编码，低权用户可以在新增用户或部门时写入 `<script>alert(...)</script>` 等 payload，payload 原样入库并在管理员查看用户列表/部门列表时被浏览器执行，形成存储型 XSS，可用于窃取管理员会话或代替管理员执行后台操作。

## 原理

- 后台的“新增用户”“新增部门”表单把姓名/部门名称等字段原样提交到服务端；服务端直接写入数据库，没有做 HTML 转义、长度/字符白名单或富文本过滤。
- 管理员打开用户管理/部门管理列表时，前端（如 Layui 表格）把这些字段作为单元格内容拼接/渲染到 DOM；如果使用 `innerHTML`/模板字符串拼接而未做 HTML 编码，浏览器会把 `<script>` 或事件属性当作 HTML 执行。
- 文章实测两处：
  - 用户管理：新增用户 `caigo888`，姓名填 `<script>alert('菜狗安全')</script>`；创建完成即弹窗，管理员查看用户列表时再次触发。
  - 部门管理：新增部门，部门名称填 `<script>alert('菜狗安全')</script>`；管理员查看部门列表/部门树时触发。
- 这是典型的“低权写入、高权触发”存储型 XSS：payload 持久化在数据库，触发面是管理员高频访问的列表页；即使后台只有管理员使用，低权账号（或越权/共享账号）也能投递。
- 最新版本仍未对这两处参数做校验（原文：“这个最新的也有，没对参数做校验”），说明漏洞不随版本自动修复。

## 触发条件

- 目标为前后端不分离或使用 Layui 等表格组件渲染的后台管理系统；用户姓名/部门名称等字段在列表中未做 HTML 编码。
- 攻击者拥有可新增用户/部门的低权账号（或能调用对应新增接口）。
- 管理员会查看受影响的用户列表/部门列表（或这些字段出现在其他管理页面）。
- 浏览器未启用可阻断内联脚本的 CSP（或 CSP 允许 `unsafe-inline`），且会话 Cookie 未设置 HttpOnly（否则只能执行操作，不能直接读 Cookie）。

## 利用步骤

1. 用低权账号登录后台，找到“用户管理/部门管理”的新增功能，确认姓名、部门名称等字段可自由输入。
2. 提交探测 payload（如 `<script>alert(1)</script>`、`<img src=x onerror=alert(1)>`），观察创建响应和列表页是否弹窗/触发。
3. 若 `<script>` 被过滤，尝试事件属性、`<svg/onload=...>`、大小写/编码变形、`javascript:` 链接等绕过。
4. 用管理员账号（或让管理员）访问用户列表/部门列表，确认 payload 在管理员上下文执行。
5. 将 payload 替换为实际利用代码：读取 `document.cookie`（若未 HttpOnly）、调用后台接口（如新增管理员/修改配置）、发起 CSRF 式请求或加载外部 JS。
6. 若后台有审批/导出等会再次渲染这些字段的功能，扩大触发面。

## PoC

```text
# 用户管理 -> 新增用户
用户名: caigo888
姓名: <script>alert('菜狗安全')</script>
手机/邮箱/角色/部门: 任意合法值
```

```text
# 部门管理 -> 新增部门
部门名称: <script>alert('菜狗安全')</script>
排序/状态/上级菜单: 任意合法值
```

创建成功后，管理员访问“用户管理”或“部门管理”列表时触发弹窗：

```text
127.0.0.1:8088 显示
菜狗安全
[确定]
```

（原文截图为 `alert('菜狗安全')` 的实际弹窗；实际利用可替换为读取 Cookie 或调用后台接口的 JS。）

## 变体与关联

- 变体：`<img src=x onerror=...>`、`<svg/onload=...>`、`<details open ontoggle=...>`、事件属性与 HTML 实体/Unicode 编码变形；若前端对 `<script>` 有黑名单，优先尝试事件属性。
- 关联：Spring Security 后台的存储型 XSS 可与 CSRF/越权组合（管理员上下文执行请求）；同项目的垂直越权见 [[web-generic-auth-spring-rbac-delete-user-idor]]。
- 通用 XSS 卡：[[web-generic-xss-h3blog-username-xff-log-stored-xss]]（XFF 写入日志的存储型 XSS，触发面不同）。

## 检测与防御

- 输入侧：对姓名/部门名称等字段做长度、字符白名单（如只允许中文/字母/数字/常见符号）；拒绝 `<`、`>`、引号、`javascript:` 等；不要依赖前端校验。
- 输出侧：列表渲染时统一 HTML 编码（Layui 表格可用 `escape`/`templet` 转义；Thymeleaf 默认转义，避免 `th:utext`）；富文本使用白名单 sanitizer（DOMPurify 等）。
- 会话与浏览器：Cookie 设置 `HttpOnly`、`SameSite`；部署 CSP（禁止 `unsafe-inline`，限制脚本源）；后台启用点击劫持防护。
- 检测：后台新增/编辑接口出现 `<script`、`onerror=`、`onload=`、`javascript:` 等特征；数据库中姓名/部门名称字段含 HTML 标签；管理员列表页出现非预期脚本/外链。
