---
id: web-generic-auth-course-id-enumeration-courseware-url
title: 培训平台 courseId 遍历：低权账号枚举课程并获取课件下载地址
type: scenario
domain: web
path: web/generic/auth
technique: course-id-enumeration-courseware-url
tags:
- auth
- idor
- object-level-authorization
- enumeration
- courseware
- education
- data-leak
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T18:09:02+08:00'
  notes: 已对照原文与 img08/09/11/13：img08 GET ...?courseId=40&languageType=1 响应含 coursewareDetail.cover/url 与文件路径，img09 Intruder 遍历 courseId（3/4/31/33/34/38/40/47 等）均 200 且长度不同，img11 批量提取 pdf/mp4 URL，img13 SRC 审核为中危。卡片与原文一致；接口路径部分打码，卡片以参数与响应结构描述通用模式；未实测。
url: /docs/web/generic/auth/web-generic-auth-course-id-enumeration-courseware-url/
draft: false
kb_aliases:
- courseId 遍历
- 课程课件未授权访问
- 课件下载地址泄露
- 在线教育 IDOR
- coursewareDetail url
---

## 一句话结论

登录后的课程查询接口仅按 `courseId` 返回课程详情与 `coursewareDetail` 中的课件地址（PDF/MP4 等），未校验当前用户是否报名、购买或属于该课程；遍历自增 `courseId` 即可批量获取其他课程的课件 URL/路径并直接下载。

## 原理

- 课程详情接口把 `courseId` 作为唯一对象标识，从数据库/对象存储返回课程名称、封面、课件列表与下载地址；后端只校验“已登录”，不校验“当前用户是否有权访问该课程”。
- `courseId` 通常是自增主键，可从当前账号可见的课程 ID 推断范围，或用 Intruder/脚本遍历；每个有效 ID 返回一组 `coursewareDetail`，其中 `url` 直接指向 PDF/MP4（可能是对象存储签名 URL 或绝对路径）。
- 前端只展示已报名/已购买课程，隐藏其他课程入口；但 API 仍返回完整数据，属于对象级授权缺失（IDOR）。
- 原文的响应中还暴露了文件绝对路径/对象存储 URL，攻击者无需再猜文件名即可下载课件；签名 URL 若未与用户绑定或有效期较长，可直接被未授权用户复用。
- 影响主要是未授权访问内部/付费课程资料，属于数据泄露；若课件 URL 指向内网对象存储，还可能进一步探测存储权限。

## 触发条件

- 拥有任意低权限登录账号（如通过弱口令/注册获得）；
- 课程详情/课件接口以 `courseId` 为参数且只校验登录态；
- `courseId` 可枚举（自增或可预测）；
- 响应中包含可访问的课件 URL/绝对路径，且未与当前用户/会话绑定。

## 利用步骤

1. 登录低权账号，打开一门课程，抓取课程详情请求（原文形如 `GET ...?courseId=40&languageType=1`）。
2. 观察响应中的 `coursewareDetail`/`url`/`cover` 字段，确认是否直接返回课件地址或绝对路径。
3. 用 Burp Intruder 或脚本遍历 `courseId` 范围（如 1–200），按响应长度/是否包含 `url` 过滤有效课程。
4. 提取所有 `.pdf`/`.mp4` 等课件 URL，逐一访问验证是否可下载；记录课程名、courseId 与文件地址。
5. 对签名 URL 检查有效期与是否绑定用户；若可复用，批量下载；测试结束后清理本地数据。

## PoC

```http
GET /api/course/detail?courseId=40&languageType=1 HTTP/1.1
Host: target
Cookie: <低权账号会话>
Accept: application/json
```

```json
{
  "courseId": 40,
  "courseName": "Thermal Management System",
  "coursewareDetail": {
    "courseName": "Thermal Management System troubleshoot",
    "cover": "https://<storage>/cover/....png",
    "url": "https://<storage>/course/20240726/....pdf"
  }
}
```

```bash
# 遍历 courseId，提取课件 URL（示意）
for id in $(seq 1 200); do
  curl -s -b "<cookie>" "https://target/api/course/detail?courseId=$id&languageType=1" \
    | jq -r '.coursewareDetail.url // empty'
done
```

## 变体与关联

- 变体：其他以 `courseId`/`lessonId`/`wareId` 为参数的详情、下载、播放接口可能存在同样的对象级授权缺失，需逐个验证。
- 变体：签名 URL 若与用户绑定，可尝试从响应中获取新的签名 URL，或通过播放接口代理下载。
- 关联：课程详情/评论越权 [[web-generic-auth-course-task-object-state-missing-authz]]、lesson_id 名单遍历 [[web-generic-auth-teacher-roster-api-student-token-lesson-enumeration]]、弱口令入口 [[web-generic-auth-captcha-ocr-username-enumeration-same-password]]。

## 检测与防御

- 检测：同一账号短时间遍历大量 `courseId`；访问未报名/未购买课程详情；课件 URL 被非授权会话直接请求；对象存储访问日志中出现异常批量下载。
- 防御：在服务端做对象级授权（校验报名/购买/租户/角色）；课程 ID 使用不可预测的 UUID；课件 URL 使用短有效期且绑定用户的签名；对枚举行为限速与告警；不要把绝对路径/永久 URL 返回给客户端。
- 注意：原文接口路径被部分打码，卡片以 `courseId` 参数与响应结构描述通用模式；实际测试需按目标路由调整。
