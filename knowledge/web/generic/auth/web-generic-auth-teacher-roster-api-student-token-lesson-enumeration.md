---
id: web-generic-auth-teacher-roster-api-student-token-lesson-enumeration
title: 学生 Token 调用教师课程名单接口：lesson_id 自增遍历批量泄露学籍
type: scenario
domain: web
path: web/generic/auth
technique: teacher-roster-api-missing-role-check-id-enumeration
aliases:
- 学生越权调用教师接口
- get-students 越权
- lesson_id 遍历
- 课程名单接口数据泄露
- 接口层角色校验缺失
tags:
- web
- auth
- authz
- vertical-privilege-escalation
- idor
- enumeration
- data-leak
- education
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:04:16+08:00'
  notes: 已对照原文核对：普通学生 Token 可调 course/schedule/lesson/get-students；lesson_id=1/4/65000 样例各返回 92/218/162 条（图05），字段为学号/姓名/性别/院系/专业/班级/方向；文中称 1-10万+ 有效 ID、约500个有效 lesson、去重约16815条、2009-2025共17级，图05仅示测试范围472条样本，全量统计未独立复核；PoC 的 /student 前缀按文中 getWholeUrl 规则还原（原文未给该接口完整 URL）；未在本机复现。
---

## 一句话结论

当移动端 API 只在 Service 层按 Token 身份过滤数据、Controller 层不做角色校验时，普通学生 Token 可以调用教师端的课程成员接口 `course/schedule/lesson/get-students`；`lesson_id` 是自增序列，遍历 1 到 10 万+ 的有效 ID 即可批量拉取全校学生名单，测试范围内去重后泄露约 16815 条学号、姓名、性别、院系、专业、班级等学籍信息。

## 原理

- 该系统的 URL 使用 `/student`、`/teacher`、`/admin` 前缀，但这些前缀只决定返回字段的视图，不是权限控制；Controller 按前缀分发后不做角色判断。
- 真正的过滤发生在 Service/SQL 层：从 Token 中取 identity/roleId，拼进 WHERE 条件。它只回答“你是谁”，不回答“你能不能调用这个接口”。
- 教师端接口 `get-students` 按 `lesson_id` 返回选课学生名单；接口没有校验调用者是否为教师、是否教授该课程，也没有校验 lesson 的归属。
- `lesson_id` 是数据库自增主键，天然可枚举；每个有效 ID 返回几十到两百多条学生记录，遍历即可拼出全校名册。
- 学号本身是密码重置、教务操作的重要标识；拿到完整名册后，攻击者可以精准选择目标，再结合邮箱修改/密码重置链完成账号接管。
- 这类缺陷自动化扫描器很难发现：接口 URL 藏在 webpack 的 `apiUrlKey` 中，没有 Swagger；`lesson_id` 无注入点、无报错回显，泄露源于权限控制缺失而不是技术漏洞。

## 触发条件

- 攻击者持有任意低权限有效 Token（如学生账号）；
- 教师/管理员专属接口在 API 列表中可发现（webpack 打包产物、前端路由、抓包）；
- Controller/路由层没有角色校验，或只校验“已登录”；
- 业务对象 ID（lesson_id、course_id、class_id 等）为自增序列或可预测，且接口按 ID 返回批量数据；
- 接口响应包含姓名、学号、院系等可识别个人身份的信息。

## 利用步骤

1. 从移动端 `main.js` 的 `apiUrlKey` 提取全部端点，筛出 `get-students`、`get-student-list`、`class/student` 等教师/管理端接口。
2. 用学生 Token 直接请求目标接口，先传 `lesson_id=1`，确认是否返回学生名单而不是 403/空。
3. 遍历 `lesson_id`（1 到业务上限，或先小范围采样确认有效区间），记录每个 ID 返回的记录数与字段。
4. 按学号去重，统计唯一学生数、年级分布、院系分布；抽样验证数据真实性（不要全量下载/长期保存）。
5. 用泄露的名册选择目标，结合邮箱修改/密码重置链进行定向账号接管测试。
6. 在授权范围内停止扩大，保留最小复现证据（请求、响应样本、去重统计）。

## PoC

```http
POST /app-ws/ws/app-service/student/course/schedule/lesson/get-students HTTP/1.1
Host: target-app.edu.cn
Content-Type: application/x-www-form-urlencoded

token=<student-token>&lesson_id=1
```

```json
[{
  "code": "201700120101",
  "name": "白xx",
  "gender": "女",
  "depart_name": "经济管理学院",
  "major_name": "酒店管理",
  "adminclass_name": "17酒店1班",
  "direction_name": ""
}]
```

```python
# 结构示意：遍历 lesson_id 并按学号去重
import requests

seen = {}
for lesson_id in range(1, 1000):
    r = requests.post(URL, data={"token": TOKEN, "lesson_id": lesson_id}, timeout=10)
    for stu in r.json() or []:
        seen[stu["code"]] = stu
print("unique students:", len(seen))
```

## 变体与关联

- 变体：其他教师/管理端接口（班级名单、成绩、考勤、宿舍、缴费）可能同样只验登录不验角色；用学生 Token 批量替换 Cookie/Token 即可测试。
- 变体：`lesson_id` 之外，`course_id`、`class_id`、`student_id` 等自增参数也可能可遍历；结合分页参数可扩大数据量。
- 变体：路径前缀 `/student`、`/teacher`、`/admin` 返回字段不同但都能被同一 Token 访问时，说明前缀只是视图层，不是权限层。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（拦截器只验登录不验角色；本卡补充教师名单接口与自增 ID 批量遍历的数据泄露场景）。
- 关联：[[pentest-recon-webpack-apiurlkey-endpoint-extraction]]（从 webpack `apiUrlKey` 提取隐藏 API 端点）。
- 关联：[[web-generic-auth-email-change-no-verification-password-reset-takeover]]（拿到名册后的定向账号接管链）。
- 影响边界：接口若在 Controller 层校验教师角色、校验课程归属，或 lesson_id 使用不可预测的 UUID，本路径失效；仅返回公开信息时危害降低。

## 检测与防御

- 检测：同一学生 Token 对教师/管理端接口的调用；同一 Token 在短时间内遍历大量自增 ID；响应中批量返回学生姓名/学号等字段；单账号请求量异常。
- 检测：对比 `/student`、`/teacher`、`/admin` 前缀的响应，确认是否存在“同一 Token 可访问所有前缀”的权限模型缺陷。
- 防御：在 Controller/方法级做 RBAC（`@PreAuthorize`、Shiro 注解或策略引擎），默认拒绝；不要依赖 URL 前缀或前端菜单做权限。
- 防御：对业务对象做归属校验（教师只能看自己课程的名单）；批量接口加分页、速率限制与审计；敏感字段按角色最小化返回。
- 防御：把自增 ID 换成不可预测的 UUID 只能提高枚举成本，不能替代授权校验；核心仍是接口层角色与对象级授权。
