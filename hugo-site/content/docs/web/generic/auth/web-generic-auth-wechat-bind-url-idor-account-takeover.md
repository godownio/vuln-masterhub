---
id: web-generic-auth-wechat-bind-url-idor-account-takeover
title: 微信绑定 getBingUrl?id 不校验归属：换目标教师 ID 取绑定二维码，扫码接管他人账号
type: scenario
domain: web
path: web/generic/auth
technique: wechat-bind-url-idor-account-takeover
tags:
- web
- auth
- idor
- account-takeover
- wechat
- oauth
- access-control
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:04+08:00'
  notes: 已对照原文与图18-27核对：getBingUrl?id=...&fromType=1 返回 dingTalkWebBingUrl；tcadmList 返回 teacherId/teacherName；替换 id 后扫码提示“微信号绑定成功”，清缓存微信登录接管教师账号。未在真实目标复测；原文未给域名/账号，属授权 SRC 测试。
url: /docs/web/generic/auth/web-generic-auth-wechat-bind-url-idor-account-takeover/
draft: false
kb_aliases:
- 微信绑定越权
- getBingUrl id 替换
- 绑定微信接管账号
- 教师账号接管
- WeChat bind IDOR
---

## 一句话结论

个人设置里的“绑定微信”功能调用 `getBingUrl?id=<userId>&fromType=1`，服务端只按传入 `id` 生成微信 OAuth 绑定二维码 URL，不校验该 `id` 是否属于当前登录用户；攻击者从教师列表、课程信息、作业/公告/考试等接口拿到目标教师的 `id`，替换后获取绑定链接，用自己的微信扫码完成绑定，清除浏览器缓存后用微信登录，即接管目标教师账号。

## 原理

- 绑定流程：前端在“个人设置 → 账号绑定 → 微信”处请求 `getBingUrl`，服务端按 `id` 生成一个微信开放平台 `qrconnect` URL（响应字段 `dingTalkWebBingUrl`），用户扫码后微信 `openid` 与该 `id` 对应的账号建立绑定关系；之后微信扫码登录即可通过 `openid` 找到该账号。
- 缺陷：`getBingUrl` 只用 `id` 查账号并生成绑定 state，没有把 `id` 与当前会话用户做归属校验（也没有一次性绑定 token/CSRF 防护），因此任何能调用该接口的登录用户都可以为任意 `id` 生成绑定链接。
- `id` 不是自增可遍历，但泄露面很广：新建题库/选择教学负责人接口 `tcadmList?bankId=` 的响应会返回 `teacherId`/`teacherName`/`teacherNum`；课程信息接口 `courseInfo` 的 `teacherInfos[].teacherId`；教师发布的作业、公告、考试等页面也会带教师 id。攻击者只要拿到一个教师 id 即可发起绑定。
- 绑定成功后，微信登录链路按 `openid` 找到被绑定的账号，攻击者清缓存/换浏览器用同一微信扫码登录，即获得目标教师的会话与权限。
- 条件是目标账号尚未绑定微信（或绑定可被覆盖）；原文用爆破得到的测试教师账号完成操作，并验证“微信号绑定成功”，随后用微信登录接管。

## 触发条件

- 目标系统支持微信扫码登录，并提供“绑定微信”功能；`getBingUrl` 可被登录用户调用（原文称绑定动作需教师权限，但可用爆破得到的测试教师账号，或学生账号从其他接口获取教师 id）。
- `getBingUrl` 不校验 `id` 归属，也不要求当前会话二次确认/绑定令牌。
- 攻击者能通过其他业务接口获得目标账号的 `id`（教师列表、课程信息、作业/公告/考试等）。
- 目标账号未绑定微信或绑定可被覆盖；微信扫码绑定/登录链路可用。

## 利用步骤

1. 登录一个可用账号（教师测试账号，或能调用相关接口的账号），进入个人设置确认“绑定微信”功能。
2. 在新建题库/选择教学负责人等功能中勾选“显示全部教学负责人”，抓包获取响应的 `teacherId` 列表（示例字段 `teacherId`、`teacherName`、`teacherNum`）。
3. 调用 `getBingUrl?id=<目标teacherId>&fromType=1`，从响应 `data.dingTalkWebBingUrl` 取微信绑定二维码 URL。
4. 用攻击者自己的微信扫码；页面提示“微信号绑定成功”。
5. 清除浏览器缓存/换无痕窗口，使用该微信扫码登录；系统按 openid 找到被绑定账号，攻击者以目标教师身份进入。
6. 若目标已有绑定，尝试其他未绑定教师或先确认绑定是否可覆盖；仅在授权测试中验证，不对真实用户操作。

## PoC

```http
GET /iplat/bp/<path>/getBingUrl?id=<victimTeacherId>&fromType=1 HTTP/1.1
Host: <target>
Cookie: <attacker-or-test-teacher-session>

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "dingTalkWebBingUrl": "https://open.weixin.qq.com/connect/qrconnect?appid=...&redirect_uri=...&state=<state>&scope=snsapi_login#wechat_redirect"
  }
}
```

```text
1) 用攻击者微信扫码上述 URL → 页面提示“微信号绑定成功”
2) 清除浏览器缓存 → 微信扫码登录 → 进入目标教师账号
```

原文实测截图：`tcadmList?bankId=` 返回 `teacherId` 列表；替换 id 后 `getBingUrl` 返回 `dingTalkWebBingUrl`；扫码提示“微信号绑定成功”；微信登录后以教师身份进入首页。

## 变体与关联

- 变体（id 来源）：教师列表、课程信息 `teacherInfos[].teacherId`、作业/公告/考试发布者、导出接口等；任何返回用户 id 的接口都可作为前置。
- 变体（绑定方式）：除微信外，手机号/QQ/钉钉等第三方绑定若同样只按 id 生成绑定链接，也可能存在归属校验缺失。
- 关联：[[web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover]]（微信小程序 session_key 解密接管，不同链路）、[[web-generic-auth-unauth-idor-account-agent-contact-role-chain]]（IDOR 多端点画像）、[[web-generic-auth-missing-function-level-role-check]]（功能级授权缺失）。
- 边界：`getBingUrl` 校验会话归属、绑定需短信/密码二次确认、目标已绑定且不可覆盖时，链路不成立；原文仅验证测试账号，未对真实用户操作。

## 检测与防御

- 修复：`getBingUrl` 从会话取当前用户 id，禁止客户端传入任意 `id`；如必须传 id，校验其属于当前用户；绑定操作增加一次性 token、短信/密码二次确认与 CSRF 防护；已绑定账号需先解绑并验证。
- 加固：第三方绑定/登录的 state 与用户 id 绑定并设置短 TTL；绑定成功/失败均审计；限制同一账号/微信的绑定频率与异地操作。
- 检测：同一会话对多个不同 `id` 调用 `getBingUrl`；同一微信 openid 短时间内绑定多个账号；绑定后立即异地登录；教师账号在非工作时间被新微信绑定/登录。
- 响应：发现异常绑定立即解绑、强制重新认证、通知账号持有人并排查是否已发生数据访问。
