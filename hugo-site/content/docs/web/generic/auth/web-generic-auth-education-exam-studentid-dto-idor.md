---
id: web-generic-auth-education-exam-studentid-dto-idor
title: 智慧云教育平台 /student/exam 考试记录查询：DTO 的 studentId 由客户端传入且未与会话绑定
type: scenario
domain: web
path: web/generic/auth
technique: query-dto-studentid-not-bound-to-session
tags:
- web
- authz
- idor
- broken-access-control
- horizontal-privilege-escalation
- spring-boot
- spring-mvc
- mybatis
- education
- enumeration
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V226
  verified_at: '2026-11-07T06:56:36+08:00'
  notes: 已对照原文与38张图核对：ExamInfoController.selectExamInfoList 直接绑定 StudentExamInfoDto、MyBatis selectStudentExamList 的 studentExamInfoDto.studentId/subjectId 条件、WrongBookController 第38行用会话 studentId 覆盖，均与图30/32/36一致；原文截图仅遍历 subjectId（响应示例 studentId=145），未演示把 studentId 改成他人，卡内已注明 confidence medium；未复跑。
url: /docs/web/generic/auth/web-generic-auth-education-exam-studentid-dto-idor/
draft: false
kb_aliases:
- StudentExamInfoDto 越权
- /student/exam studentId 遍历
- 学生考试记录水平越权
- 教育平台 DTO 参数越权
- MyBatis 查询条件身份字段可控
---

## 一句话结论

智慧云教育平台的 `ExamInfoController.selectExamInfoList` 直接接收 Spring MVC 自动绑定的 `StudentExamInfoDto` 作为查询条件，`studentId` 没有像同项目 `WrongBookController` 那样被 `UserSessionContext.getStudentId()` 覆盖；MyBatis 在 `studentId != null` 时把它拼进 `exam.student_id = #{studentExamInfoDto.studentId}`，因此任意登录学生只要替换请求里的 `studentId`，就能读取其他学生的考试记录（成绩、试卷、学科、考试时间等），也可用 `subjectId` 遍历批量拉取。

## 原理

- 控制器签名 `@GetMapping public Result selectExamInfoList(PageParam pageParam, StudentExamInfoDto studentExamInfoDto)`：`StudentExamInfoDto` 是普通查询 DTO，Spring MVC 会把 URL 查询参数（如 `studentId`、`subjectId`）自动绑定到它的字段上，攻击者完全控制。
- 业务层直接调用 `examInfoService.selectStudentExamInfoList(pageParam, studentExamInfoDto)`，没有用会话中的当前学生 ID 覆盖 `studentId`，也没有校验“该 studentId 是否等于当前登录学生”。
- 映射语句 `selectStudentExamList` 的 `<where>` 中有两个条件：`<if test="studentExamInfoDto.studentId != null"> and exam.student_id = #{studentExamInfoDto.studentId}</if>` 与 `<if test="studentExamInfoDto.subjectId != null"> and paper.subject_id = #{studentExamInfoDto.subjectId}</if>`。前者正是身份字段，后者是可枚举的业务字段；两者都来自客户端。
- 鉴权层面 `StudentAuthInterceptor` 只验证请求携带的 Authorization token 是否对应一个有效学生会话，不校验请求体/参数里的 studentId 是否属于该会话；所以“已登录”不等于“只能看自己的数据”。
- 对比同项目 `WrongBookController.list`：其第 38 行显式执行 `wrongBookQuery.setStudentId(UserSessionContext.getStudentId())`，把客户端传入的 studentId 覆盖掉；`ExamInfoController` 缺少这一行，是两类接口安全差异的直接根因。
- 响应字段包含 `studentId`、`testPaperInfoId`、`subjectId`、`subjectName`、`examTime`、`mark`、`correctWrongNumber`、`testPaperInfoName`、`schoolType` 等，足以还原他人考试与成绩画像；`studentId` 为可预测数字（原文示例 145），便于枚举。

## 触发条件

- 目标为使用该代码的智慧云智能教育平台，`/student/exam` 可达。
- 攻击者持有任意有效学生 token（注册/登录即可）。
- 知道或能枚举目标学生的数字 studentId（列表/响应字段、注册顺序、其它接口泄露均可）。
- 服务器未对同一 token 查询大量不同 studentId 做审计/限速。

## 利用步骤

1. 登录普通学生账号，抓取 `GET /student/exam?pageNumber=1&pageSize=9&subjectId=<n>` 请求，确认返回本人考试记录。
2. 在查询串中加入 `studentId=<目标学生ID>`（保留或去掉 subjectId），重放请求。
3. 对比响应中的 `studentId` 字段是否变为目标值、`total`/`dataList` 是否返回目标学生的考试记录；若为空可换 subjectId 再试。
4. 将 `studentId`/`subjectId` 放入 Burp Intruder 递增遍历，按响应长度/记录数筛选有数据的组合，批量导出成绩与试卷信息。
5. 用泄露的 testPaperInfoId、subjectId 继续测试试卷详情、成绩详情等接口，确认是否存在同源的二次越权。

## PoC

```http
GET /student/exam?pageNumber=1&pageSize=9&studentId=<victim-student-id>&subjectId=<subject-id> HTTP/1.1
Host: target
Platform: educationStudent
Accept: application/json, text/plain, */*
Authorization: <登录后的学生 token>
User-Agent: Mozilla/5.0
```

响应中的记录形如：

```json
{
  "total": 10,
  "pageNumber": 1,
  "dataList": [
    {
      "id": 1575,
      "studentId": "<victim-student-id>",
      "subjectId": "<subject-id>",
      "testPaperInfoId": 35,
      "testPaperInfoName": "试卷名称",
      "examTime": "0秒",
      "mark": 0,
      "correctWrongNumber": 1,
      "correctFlag": 0,
      "schoolType": "Windows"
    }
  ]
}
```

说明：原文截图主要展示 `subjectId={int(1-200)}` 遍历并返回考试记录，未在同一张截图中演示把 `studentId` 改成他人；`studentId` 可控这一结论来自控制器与 MyBatis 映射的代码路径，故置信度标为 medium，需在目标上按上述步骤二次确认。

## 变体与关联

- 参数变体：`subjectId` 可直接枚举全部学科；`pageNumber`/`pageSize` 可调大以一次拉取更多记录。
- 接口变体：同一平台学生端其它列表接口若同样使用客户端 DTO 作查询条件，需逐个检查是否有 `setStudentId(会话值)` 覆盖。
- 同文第二处 `/student/wrongBook`：控制器用 `UserSessionContext.getStudentId()` 覆盖了 studentId，仅 `subjectId` 可控；其响应是当前学生自己的错题记录，未能在原文中证明跨用户数据泄露，因此不作为本卡的同等结论，仅提示审计时检查学科范围授权。
- 关联：[[web-generic-auth-mobile-person-permission-userid-idor-pii]]（userId 参数越权查他人资料）、[[web-generic-auth-course-task-object-state-missing-authz]]（教育平台对象级授权缺失）、[[web-generic-auth-form-field-id-idor-pii-enumeration]]（教育系统 ID 遍历）。
- 边界：若服务端在进入业务层前强制用会话身份覆盖 studentId、或对查询字段做白名单/归属校验，则本路径失效；studentId 为不可预测值只能提高枚举成本，不能替代授权。

## 检测与防御

- 检测：同一学生 token 在短时间内请求大量不同 `studentId`/`subjectId`；响应 `studentId` 与会话主体不一致；考试记录接口返回的 `studentId` 分布跨越多个账号。
- 检测：审计所有 `@GetMapping`/`@PostMapping` 接收 DTO 的列表接口，搜索是否有 `setStudentId`/`setUserId` 用会话值覆盖的分支；缺失即为高风险点。
- 防御：所有“我的数据”类查询强制使用服务端会话中的学生 ID，忽略客户端传入的身份字段；对 subjectId 等业务筛选做授权范围校验（是否选课/是否属于本年级）。
- 防御：使用 MyBatis 参数绑定（已有 `#{}`，无 SQL 注入）不等于授权；在 Service 层增加对象级授权（当前用户 → 资源归属）与分页上限。
- 加固：对身份/范围字段做服务端重建（DTO 白名单只保留排序、分页等非敏感字段）；对批量查询做速率限制与越权告警；定期用双账号矩阵回归测试。
