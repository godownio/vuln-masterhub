---
id: web-generic-auth-cmsv6-xzcenter-list-unauth
title: 通天星 CMSV6 /xz_center/list 未授权分页查询：sessionUserId 为空时跳过 create_id 归属过滤，返回全量 XzCenter 记录
type: scenario
domain: web
path: web/generic/auth
technique: unauth-list-conditional-owner-filter-null
aliases:
- 通天星 CMSV6 xz_center 信息泄露
- XzCenterController 未授权
- xz_center/list 未授权查询
- CMSV6 列表接口信息泄露
tags:
- cmsv6
- java
- spring-mvc
- unauth
- access-control
- data-exposure
- idor
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:03:18+08:00'
  notes: 已对照原文与全部18张图核对：XzCenterController#loadPage绑定XzCenterVo并setSessionUserId(SessionParamFilter.getSessionUserId())（图11-12）、DAO仅在sessionUserId!=null时追加create_id过滤并按6天时间窗查询（图13）、POST /xz_center/list page=1未带Cookie返回200分页数据（图11/12）均一致。未验证点：未实际请求。
---

## 一句话结论

`POST /xz_center/list` 不要求登录即可分页查询 XzCenter 记录：`SessionParamFilter.getSessionUserId()` 在未登录时返回 `null`，而 DAO 只在 `sessionUserId != null` 时才追加 `AND a.create_id = :createId` 归属过滤，于是无会话请求反而拿到最近 6 天内所有用户的记录。

## 原理

- 控制器 `com.gps808.operationManagement.service.XzCenterController#loadPage`（`@PostMapping("/list")`）从请求绑定 `XzCenterVo`，然后执行：

  ```java
  XzCenterVo params = (XzCenterVo) RequestUtil.getRequestParams(XzCenterVo.class);
  params.setSessionUserId(SessionParamFilter.getSessionUserId());
  AjaxDto<XzCenterVo> ajaxDto = this.xzCenterService.loadPage(params, this.getPaginationEx());
  return AjaxResult.getSuccess(ajaxDto);
  ```

  控制器本身没有登录/角色注解，文章 PoC 也未携带 Cookie 或 token，直接 `POST /xz_center/list` 加 `page=1` 即可得到 200 与数据。
- Service 层 `loadPage` 先设置默认时间窗（起始为 6 天前的 0 点、结束为当天 23:59:59），再调用 `XzCenterDao#LoadPage`。
- DAO 用 `StringBuilder` 动态拼查询条件，每个条件都依赖参数是否为 `null`：

  ```java
  if (params.getSessionUserId() != null) {
      sb.append(" AND a.create_id = :createId ");
      queryParams.add(new QueryParam("createId", params.getSessionUserId(), INTEGER));
  }
  if (params.getStartTime() != null) { sb.append(" AND a.create_time >= :startTime "); ... }
  if (params.getEndTime() != null) { sb.append(" AND a.create_time <= :endTime "); ... }
  if (StringUtils.isNotBlank(params.getFileName())) {
      sb.append(" AND a.file_name LIKE :fileName ");
      queryParams.add(new QueryParam("fileName", "%" + params.getFileName() + "%", ...));
  }
  sb.append(" ORDER BY a.create_time DESC ");
  ```

  未登录时 `sessionUserId` 为 `null`，`create_id` 归属过滤被整段跳过；时间窗和文件名过滤仍生效，但攻击者可以用 `fileName` 通配或翻页遍历最近 6 天的全部记录。
- 这类问题的根因是「按会话可选地加归属过滤」：把 `null` 当作「不过滤」而不是「拒绝请求」，导致鉴权缺失时数据范围反而扩大。`SessionParamFilter` 负责从会话取用户 ID，但控制器没有在 `null` 时中断请求。
- 返回字段来自 `XzCenterVo`（分页数据、文件/创建者/时间等业务字段）；文章截图为 200 与 JSON 分页结构，未展示具体敏感字段，但接口与 DAO 的条件逻辑足以确认未授权读取路径。

## 触发条件

- 目标暴露 `/xz_center/list`，且该接口没有独立的登录拦截/权限注解（文章 PoC 未带会话）。
- `SessionParamFilter.getSessionUserId()` 在无会话时返回 `null`（而不是抛异常/返回 0），使 DAO 跳过 `create_id` 过滤。
- 数据库中存在最近 6 天内的 XzCenter 记录；超过时间窗的数据不会被默认查询带出，但攻击者可利用 `fileName` 通配或改时间参数（若可绑定）扩大范围。
- 请求以 `application/x-www-form-urlencoded` 或表单方式提交 `page=1`，分页参数由 `getPaginationEx()` 解析。

## 利用步骤

1. 直接发送 `POST /xz_center/list`，正文 `page=1`，不带 Cookie；确认返回 `result:0` 且 `data` 中含分页记录。
2. 递增 `page` 遍历所有页；用 `fileName` 参数（若 VO 可绑定）传 `%` 或业务关键字缩小/扩大结果，枚举文件名等字段。
3. 记录返回中的创建者 ID、文件名、时间等字段，用于后续针对具体用户/资源的越权或社会工程。
4. 若接口同时支持时间参数，尝试改 `startTime`/`endTime` 扩大时间窗，读取 6 天之外的历史记录（以实际参数绑定为准）。

## PoC

```http
POST /xz_center/list HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0
Accept: */*
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: application/x-www-form-urlencoded

page=1
```

响应为 `AjaxResult` 包装的 `AjaxDto<XzCenterVo>` 分页数据；文章截图显示 HTTP 200，`data` 内含分页结构。翻页时改 `page=2`、`page=3` 即可。

## 变体与关联

- 同产品的 `StandardLoginAction_getAllUser.action` 也是未授权账号信息泄露，见 CMSV6 getAllUser 卡；两者一个泄露业务记录、一个泄露账号列表，可组合做用户枚举。
- 通用手法：`web/generic/auth` 下已有「只校验登录不校验角色」「未授权 user/all 全量泄露」等卡；本卡差异是「归属过滤按 session 是否为 null 条件拼接」这一具体缺陷模式，可作为代码审计特征复用。
- 若响应中带文件路径/下载 ID，可衔接 CMSV6 的任意文件读取接口进一步取文件内容。

## 检测与防御

- 修复：控制器入口强制登录，未认证直接 401；DAO 的归属过滤改为无条件生效（`create_id = 当前用户`），管理员列表才允许全量并单独做角色校验；不要把 `null` 解释为「不过滤」。
- 参数：分页、时间、文件名参数做白名单/长度校验，限制单页大小与时间窗；返回字段最小化，去除不必要的创建者/路径信息。
- 检测：监控未携带会话访问 `/xz_center/list` 的请求与高频翻页；对单 IP 遍历多页、`fileName=%` 的查询告警；审计该接口的响应条数与来源。
- 排查：核对 Web 访问日志中该接口的未认证调用、返回记录数与涉及的创建者范围。
