---
id: web-generic-auth-vip-course-direct-media-url-leak
title: VIP 课程接口直接返回付费音频 CDN 直链：未开通会员也能下载播放
type: scenario
domain: web
path: web/generic/auth
technique: vip-content-direct-url-leak-paywall-bypass
tags:
- web
- auth
- business-logic
- paywall
- content-leak
- vip
- cdn
- object-storage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:36+08:00'
  notes: 已对照原文与 img16-18 核对：POST /course/getGoodsCourseInfo?goodsId=512&appVersion=1.9.1&timestamp=...&sign=... 响应 sourceInfo 返回 OSS mp3 直链，浏览器可直接播放；未复跑。
url: /docs/web/generic/auth/web-generic-auth-vip-course-direct-media-url-leak/
draft: false
kb_aliases:
- VIP 课程直链泄露
- 付费音频 URL 外泄
- 会员内容越权访问
- 前端门禁后端放行
- paywall bypass CDN
---

## 一句话结论

课程详情接口 `POST /course/getGoodsCourseInfo` 在未校验会员资格的情况下，直接返回 VIP 课程音视频文件的对象存储直链（`sourceInfo` 中的 mp3 URL）；攻击者不需要开通 VIP，访问该直链即可下载/播放付费内容。

## 原理

- 付费内容的鉴权只做在客户端 UI 层（按钮显示“VIP 免费用”/前端拦截），服务端在返回课程详情时没有校验当前用户是否为 VIP、是否购买该课程。
- 课程详情响应中包含 `sourceInfo` 字段，直接给出对象存储（如阿里云 OSS）上的 mp3/视频地址；该地址未与用户会话绑定，也没有短期签名或防盗链，任何拿到 URL 的人都能直接访问。
- 由于 URL 是完整可访问的 CDN 地址，攻击者可以绕过 APP/小程序播放器，直接在浏览器或下载工具中获取原始文件，形成完整的付费内容泄露。
- 本质是“前端门禁 + 后端直出资源地址”：服务端把资源定位符当作普通字段返回，而没有把资源访问权限与用户权益绑定。

## 触发条件

- 攻击者拥有可登录的普通账号（甚至可能无需登录，取决于接口鉴权）。
- 课程详情/播放信息接口在响应中返回媒体文件地址，且只校验登录态不校验会员/购买状态。
- 媒体 URL 为可直接访问的对象存储/CDN 地址，未绑定用户、未使用短期签名或防盗链。
- 接口参数（goodsId/courseId）可枚举或可从列表页获得。

## 利用步骤

1. 登录普通账号，打开一个 VIP 课程页面，抓取课程详情请求：`POST /course/getGoodsCourseInfo?goodsId=512&appVersion=1.9.1&timestamp=...&sign=...`。
2. 检查响应 JSON 中的 `sourceInfo`/`url`/`mediaUrl` 等字段，提取 mp3/mp4/pdf 直链。
3. 在未开通 VIP 的浏览器/下载工具中直接访问该 URL，确认可正常播放/下载。
4. 遍历 `goodsId`/`courseId` 获取更多付费课程直链，批量验证；注意控制下载量。
5. 记录请求、响应字段与直链访问结果作为证据；测试后删除本地文件。

## PoC

```http
POST /course/getGoodsCourseInfo?goodsId=512&appVersion=1.9.1&timestamp=1728035898995&sign=<valid_sign> HTTP/1.1
Host: target
Content-Type: application/json
Cookie: <普通用户会话>
```

响应中的关键字段（原文）：

```json
{
  "sourceInfo": "https://<bucket>.oss-cn-....com/psy/1718351294543_....mp3",
  "sourceTime": 524,
  "studyStatus": 0,
  "auditionStatus": 0,
  "releaseStatus": 1
}
```

直接在浏览器打开该 mp3 地址即可播放（原文在未开通 VIP 的浏览器中播放成功）。

## 变体与关联

- 变体：视频、PDF、课件、直播回放等资源同样可能在详情/播放接口中直出 URL；检查 `sourceInfo`、`playUrl`、`downloadUrl`、`filePath` 等字段。
- 变体：对象存储签名 URL 若有效期长且不绑定用户，可被转发复用；可测试去掉签名参数、替换路径、目录遍历。
- 关联：[[web-generic-auth-course-id-enumeration-courseware-url]]（课程/课件 URL 越权泄露，侧重 courseId 遍历；本卡侧重 VIP 权益校验缺失与 CDN 直链）、[[web-generic-auth-course-task-object-state-missing-authz]]（课程详情只凭 ID 返回）。
- 边界：服务端在返回 URL 前校验会员/购买状态、使用短有效期且绑定用户的签名 URL、或通过鉴权代理转发媒体流时，直链泄露不成立。

## 检测与防御

- 修复：课程详情/播放接口先校验当前用户的会员资格或购买记录，再返回资源；未授权时只返回试听片段或不返回 URL。
- 加固：媒体 URL 使用短有效期、绑定用户/会话的签名（如 OSS 私有 bucket + STS 临时凭证）；通过带鉴权的代理/CDN token 播放；禁止在列表/详情接口返回永久直链。
- 检测：非 VIP 用户请求 VIP 课程详情/播放接口；同一账号/IP 批量枚举 goodsId；对象存储出现大量非 APP 来源的直接下载；Referer/UA 缺失的批量请求。
- 响应：轮换对象存储密钥/签名密钥，将 bucket 改为私有并开启防盗链，审计已泄露资源的访问日志。
