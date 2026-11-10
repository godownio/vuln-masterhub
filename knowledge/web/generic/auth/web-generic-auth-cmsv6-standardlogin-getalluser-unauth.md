---
id: web-generic-auth-cmsv6-standardlogin-getalluser-unauth
title: 通天星 CMSV6 StandardLoginAction_getAllUser 未授权账号枚举：json=null 直接返回全部用户
type: scenario
domain: web
path: web/generic/auth
technique: struts-action-unauth-user-enumeration
aliases:
- 通天星 CMSV6 用户信息泄露
- StandardLoginAction_getAllUser
- getAllUser 未授权
- CMSV6 账号枚举
tags:
- cmsv6
- java
- struts2
- unauth
- user-enumeration
- information-disclosure
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:03:21+08:00'
  notes: 已对照原文与全部18张图核对：POST /808gps/StandardLoginAction_getAllUser.action、Content-Type表单、正文json=null与类名StandardLoginAction均与原文PoC一致。但原文仅给请求与类名，未给响应/返回字段，未证明未授权返回全部用户；json=null语义为按接口名推断。卡内confidence=low并已注明，保留供后续补证。未验证点：未实际请求目标。
---

## 一句话结论

`/808gps/StandardLoginAction_getAllUser.action` 无需登录即可调用，POST 体只传 `json=null` 就会走「无过滤」分支返回全部用户账号信息；文章仅给出 PoC 与类名、未贴响应，危害按接口语义判定为账号枚举与用户信息泄露。

## 原理

- CMSV6 的 Struts2 路由规则是「任意路径 + 类名_method.action」，因此 `StandardLoginAction_getAllUser.action` 对应 `com.gps808.operationManagement.action.StandardLoginAction#getAllUser` 方法。该类属于登录相关 Action，但 `getAllUser` 方法本身没有做会话/角色校验（文章 PoC 未携带 Cookie，直接 POST 即可）。
- 请求体 `json=null` 是该接口的参数形态：方法接收一个 `json` 参数（可能是 JSON 过滤条件），传 `null` 时不做用户过滤，直接查询并返回全部用户；若传具体条件则按条件查询。文章未贴出该方法的源码与响应，以上按 PoC 与动作语义推断，具体返回字段（账号、姓名、角色、联系方式等）需以目标实际响应为准。
- 这类问题的根因是「Action 方法级鉴权缺失」：Struts2 的 Action 可能整体挂了登录拦截器，但登录相关 Action 常被加入白名单（如登录、验证码、找回密码），`getAllUser` 若与这些方法同属 `StandardLoginAction`，就会随白名单一起被放行；同时方法内部没有二次校验当前会话。
- 账号列表本身可用于后续攻击：枚举用户名做口令喷洒/弱口令尝试、结合默认口令登录后台、配合日志 session 泄露定位管理员账号，或用于社会工程。

## 触发条件

- 目标暴露 `/808gps/StandardLoginAction_getAllUser.action`，且该 Action 未被登录拦截器拦截（文章 PoC 无 Cookie）。
- 方法接受 `json` 参数，`null` 会跳过过滤；若目标版本对 `json` 做了非空校验，需要按实际参数结构构造。
- 数据库中存在用户记录；返回内容与权限取决于实现，文章未展示响应细节。
- 该接口与登录流程同属 `StandardLoginAction`，登录白名单配置是能否未授权访问的关键。

## 利用步骤

1. 发送 `POST /808gps/StandardLoginAction_getAllUser.action`，`Content-Type: application/x-www-form-urlencoded`，正文 `json=null`，不带 Cookie。
2. 观察响应是否为用户列表/JSON 数组；若返回登录页或 302，说明该版本已加拦截，改用其他白名单 Action 或先获取低权限会话。
3. 若返回数据，记录账号、姓名、角色、联系方式等字段，枚举管理员账号；结合默认口令、弱口令或日志泄露的 session 尝试登录。
4. 若 `json` 支持过滤条件，尝试传空对象/通配条件扩大返回范围；以实际接口行为为准。

## PoC

```http
POST /808gps/StandardLoginAction_getAllUser.action HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36
Connection: close
Content-Length: 9
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate

json=null
```

文章未给出该请求的响应截图或返回字段，因此本卡不声称已在本机复现；`json=null` 的实际效果需以目标版本为准。

## 变体与关联

- 同产品的 `/xz_center/list` 未授权列表泄露见 CMSV6 xz_center 卡；两者可组合做「账号 + 业务记录」枚举。
- 通用手法：`web/generic/auth` 下已有「未授权用户列表」「只校验登录不校验角色」等卡；本卡差异是 Struts2 登录 Action 的 `getAllUser` 方法级鉴权缺失与 `json=null` 参数形态。
- 枚举到的账号可衔接弱口令/默认口令登录、日志 session 劫持（见 CMSV6 downLoad 卡）或后台功能滥用。

## 检测与防御

- 修复：`getAllUser` 增加登录与管理员角色校验；登录白名单只放行登录/验证码等必要方法，不能按整个 Action 放行；`json` 为空时返回空结果或拒绝，而不是全量查询。
- 返回最小化：只返回必要字段，敏感联系方式/角色按权限裁剪；分页与查询条件做白名单。
- 检测：监控未携带会话调用 `StandardLoginAction_*` 的请求，尤其是 `getAllUser`；对返回大量用户记录的响应、单 IP 高频枚举告警。
- 排查：审计 Struts 登录白名单与 `StandardLoginAction` 的方法映射，核对访问日志中该 Action 的未认证调用。
