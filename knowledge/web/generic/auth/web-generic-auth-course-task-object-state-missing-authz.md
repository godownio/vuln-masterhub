---
id: web-generic-auth-course-task-object-state-missing-authz
title: 课程详情/评论接口只凭 ID 返回内容：未校验报名与教师审批状态导致未授权访问与评论
type: scenario
domain: web
path: web/generic/auth
technique: business-state-object-authz-missing
aliases:
- 课程未授权访问
- 章节越权
- 评论越权
- 报名审批状态绕过
- 在线教育越权
tags:
- authz
- idor
- business-logic
- object-level-authorization
- spring-mvc
- course
- comment
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:02:30+08:00'
  notes: 已对照原文与34张图核对：getApeTaskById 仅按 id 查库直接返回、saveApeTaskComment 无资格校验、未报名/未审批提示仅前端展示，test3 用 test2 链接访问章节与重放评论的请求/响应/页面截图均一致；未在本机复现。
---

## 一句话结论

在线教育系统把“报名并通过教师审批才能看课程/评论”的限制只做在前端和页面跳转上，后端 `getApeTaskById(id)` 与评论保存接口没有校验当前用户是否已报名、是否通过审批，任何已登录用户只要拿到课程 ID（或另一个已授权用户分享的链接）就能直接读取课程详情并提交评论。

## 原理

- 前端流程：学生报名 → 教师审批 → 页面才展示章节内容；未报名/未通过时页面提示“请先报名课程”或“报名课程通过后才能发表评论”。
- 后端 `TaskController.getApeTaskById(@RequestParam("id") String id)` 的实现是 `ApeTask apeTask = apeTaskService.getById(id); return Result.success(apeTask);`，没有任何当前用户、报名记录、审批状态或角色判断。
- 评论接口 `saveApeTaskComment` 同样直接接收 `content`、`taskId` 并保存，未校验用户是否具备评论资格。
- 因此前端的隐藏只是 UI 层的“展示控制”，不是授权；攻击者用浏览器直接请求 API，或把已授权用户页面 URL 中的 `id` 换成目标课程 ID，就能绕过业务状态。
- 该问题与“角色越权”不同：攻击者不需要教师/管理员角色，只需要一个合法学生账号和课程 ID；属于对象级授权（object-level authorization）与业务状态校验缺失。
- 课程 ID 常出现在 URL（`/taskInfo?id=...`、`/rateOfLearning?id=...`）和报名/评论请求中，容易枚举或从他人分享链接获得。

## 触发条件

- 目标课程/章节/评论接口以对象 ID 为唯一参数，后端未校验当前用户与对象的业务关系。
- 攻击者可注册或拥有任意低权限账号，并能获得至少一个课程 ID。
- 前端仅在页面渲染时隐藏内容，API 仍返回完整数据。
- 评论/评分等写接口同样缺少资格校验。

## 利用步骤

1. 用低权限学生账号注册/登录，进入课程页，确认未报名时前端提示无法查看。
2. 从已授权用户分享的链接或课程列表获取目标课程 ID（如 `/taskInfo?id=1729767297673674754`）。
3. 直接请求 `GET /task/getApeTaskById?id=<课程ID>`，观察是否返回课程名称、描述、教师、章节等完整字段。
4. 若前端按 `rateOfLearning` 等页面加载数据，直接访问该页面 URL 也可看到内容。
5. 用同一账号直接请求 `POST /comment/saveApeTaskComment`，提交 `content` 与 `taskId`，确认评论成功落库。
6. 回到前台确认评论已展示；授权测试中只提交无害内容并清理。

## PoC

```http
GET /task/getApeTaskById?random=0.6477049626710879&id=1729767297673674754 HTTP/1.1
Host: target:8080
x_access_token: <低权限学生 token>
Accept: application/json
```

响应包含完整课程对象：

```json
{
  "success": true,
  "message": "操作成功!",
  "code": 1000,
  "data": {
    "id": "1729767297673674754",
    "name": "Mybatis详细教程入门",
    "taskDescribe": "...",
    "teacherId": "...",
    "teacherName": "白易"
  }
}
```

未授权评论：

```http
POST /comment/saveApeTaskComment HTTP/1.1
Host: target:8080
x_access_token: <低权限学生 token>
Content-Type: application/json

{"content":"aaa","taskId":"1729767297673674754"}
```

响应 `{"success":true,"message":"操作成功!","code":1000}`，前台评论列表出现该内容。

## 变体与关联

- 对象变体：课程/章节/作业/考试/资料下载/订单，凡是“有业务状态门槛”的对象都可能只在前端判断。
- 写操作变体：评论、评分、收藏、报名、提交作业，缺少资格校验时可批量刷数据或覆盖状态。
- ID 获取：URL 参数、列表接口、分享链接、连续/雪花 ID；也可从教师主页的课程列表枚举。
- 关联卡片：[[web-generic-auth-missing-function-level-role-check]]（只验登录不验角色的垂直越权）、[[web-generic-auth-mall-pay-success-idor-zero-cost-order]]（业务状态/订单越权）。
- 关联：通用 IDOR、水平越权与业务逻辑漏洞。

## 检测与防御

- 检测：同一低权限账号访问大量未报名课程 ID；`getApeTaskById`/`saveApeTaskComment` 的请求中 `id`/`taskId` 与用户报名记录不匹配；评论接口在未报名状态下返回成功。
- 检测：前端提示“请先报名”但同页 API 已返回课程详情；接口响应包含未授权对象字段。
- 防御：在每个对象级接口内校验“当前用户 → 报名记录 → 审批状态 → 对象归属”，不能只依赖前端隐藏或页面跳转。
- 防御：使用服务端会话中的用户 ID 查询关联表，禁止客户端传入 userId/状态；对写接口做资格与频率校验。
- 加固：统一授权中间件/注解（如 `@PreAuthorize` + 业务校验服务）；课程 ID 使用不可预测值只是辅助，不替代授权。
- 响应：排查未授权访问/评论记录，清理异常评论，修复后回归测试未报名、待审批、已拒绝三种状态。
