---
id: web-generic-auth-type-dispatch-unauth-data-exposure
title: 未授权 type 分发 Servlet 按参数返回全量用户表与明文口令
type: scenario
domain: web
path: web/generic/auth
technique: type-dispatch-missing-auth-data-exposure
aliases:
- type 分发接口
- ImportItemServlet 未授权
- 未授权数据接口
- 明文密码泄露
- 一接口多 type
tags:
- access-control
- unauth
- java
- servlet
- data-exposure
- type-dispatch
- pii
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:42:47+08:00'
  notes: 已对照原文核对：ImportItemServlet无session校验，type=2返回select * from user含明文password，type=3返回含IDCard全量学生数据；截图3(523KB)/4(URL编码JSON含admin密码)佐证。原文脱敏，未设versions；未执行PoC
---

## 一句话结论

一个映射为 `/****oid/ImportItemServlet` 的 Servlet 在 `doGet/doPost` 中完全没有 session 校验，只按 `type` 参数分发业务：`type=2` 执行 `select * from user` 并把 `passWord` 明文塞进 JSON，`type=3` 返回含身份证号的全量学生数据，未登录即可批量拉取。

## 原理

开发者用 `type` 参数实现“一个接口多种业务”：

```java
} else if (type.equals("2")) {
    sql = "select * from user";
    String passWord = h.get("passWord") == null ? "" : (String)h.get("passWord");
    obj.put("password", passWord);
} else if (type.equals("3")) {
    sql = "select st.studentNo,st.name,st.sex,st.gradeNo,st.cardNo,st.IDCard,st.classNo,...";
}
```

漏洞不在 SQL 拼接（这里的 SQL 是固定字符串），而在于：

- **认证与业务分发是两个独立维度**：`type` 只决定走哪个分支，分支前没有任何 `Login_User`/session 判断；
- 反编译全文只有 `doGet/doPost`，没有登录检查或角色校验；
- 返回体直接序列化数据库行，包含 `user_name`、`password`（明文）、`IDCard` 等敏感字段；
- 接口路径属于“移动端/导入端”接口，常被安全设备与开发人员忽略。

因此攻击者不需要注入，也不需要登录，只要请求正确的 `type`，就能拿到全量用户凭据与个人信息。

## 触发条件

- Servlet/接口暴露在可访问路径（示例为 `/****oid/ImportItemServlet`）；
- 类中没有认证/授权检查，或前置过滤器未覆盖该路径；
- `type` 分支执行固定查询并返回敏感字段；
- 响应为 JSON（可能 URL 编码）且直接包含数据库列。

## 利用步骤

1. 从 JS/APK/接口文档/目录扫描中发现 `ImportItemServlet` 一类“导入端”接口。
2. 试探 `type` 值：`1`、`2`、`3`……观察响应长度与内容变化。
3. `type=3` 获取学生全量数据（学号、姓名、身份证、班级等）。
4. `type=2` 获取用户表，重点看 `user_name`、`password` 是否明文。
5. 用泄露的凭据登录后台或横向到其他系统；结合身份证等信息评估合规影响。

## PoC

```http
GET /****oid/ImportItemServlet?type=3 HTTP/1.1
Host: target
```

响应为 JSON 数组，含 `studentNo`、`name`、`sex`、`gradeNo`、`cardNo`、`IDCard`、`classNo` 等字段。

```http
GET /****oid/ImportItemServlet?type=2 HTTP/1.1
Host: target
```

响应为 URL 编码的 JSON（形如 `%5B%7B%22user_no...`），解码后可见 `user_no`、`user_name`、`password` 等字段；文章截图中 `password` 为明文。

## 变体与关联

- 变体：其他 `type`/`action`/`method` 分发接口；同一 Servlet 的 `type=1` 可能是写入/导入，需谨慎测试以免改数据。
- 变体：响应经过 URL 编码、Base64 或分页，需要先解码/翻页再判断是否全量。
- 关联：[[web-generic-auth-servlet-null-role-fail-open]]（同系统的鉴权短路）；[[web-java-framework-do-filter-reflection-dispatch]]（反射分发未授权入口）；[[pentest-recon-web-config-robots-credential-leak]]（凭据泄露后的利用）。
- 不确定点：文章对接口路径前缀做了脱敏；`type` 的取值范围与各分支行为需按目标枚举确认，避免触发写操作。

## 检测与防御

- **认证前置**：所有业务分支执行前统一校验登录与角色；不要因为“移动端/导入端”就豁免。
- **最小返回**：查询结果按需选列，禁止 `select *`；密码字段永远不返回，存储使用强哈希而非明文。
- **接口收敛**：为每个业务动作使用独立路由与权限注解；`type` 分发接口建立白名单并记录审计日志。
- **日志检测**：未认证请求访问 `ImportItemServlet` 等内部接口；同一 IP 遍历 `type` 值；响应体包含 `IDCard`、`password` 等敏感字段关键字。
- **数据面**：数据库账户最小权限；对敏感字段做脱敏/加密；定期扫描暴露的“导入/导出/同步”接口。
