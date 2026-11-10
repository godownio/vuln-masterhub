---
id: web-generic-auth-frontend-media-direct-url-plain-download
title: 前端源码里的 mp4/pdf 直链未做鉴权：未登录直接下载付费/受限视频与文档
type: scenario
domain: web
path: web/generic/auth
technique: static-media-direct-url-missing-authz
aliases:
- 视频直链绕过登录下载
- 文档直链未授权下载
- 静态资源完整性缺失鉴权
- F12 拿到 mp4 地址绕过权限
tags:
- web
- auth
- broken-access-control
- static-resource
- direct-link
- media
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:25:56+08:00'
  notes: 已对照原文核对；原文为未登录状态点击视频/文档提示无权限，F12 在 li onclick 与 a download 中得到 mp4/pdf 完整路径并用下载工具下载成功，与卡片一致；未验证点：文件服务器是否另有防盗链/签名机制（原文未提）
---

## 一句话结论

站点把视频与文档的完整访问地址（`..._1_850.mp4`、`...书_720.pdf`）直接写在 HTML 的 `onclick`/`<a download>` 属性和前端 JS 里，而真正的文件由 Web 服务器按静态资源放行；未登录用户点页面只看到「没有权限」提示，但只要从源码里取出该 URL，用下载工具直接请求就能拿到原始文件——鉴权只做在页面点击链路，没有做在文件访问链路。

## 原理

- 内容型站点常见的「伪鉴权」：列表/详情页判断登录与会员资格，命中后才把资源地址渲染到 DOM；但资源本身以静态文件形式存放在可公开访问的目录（或对象存储公共读桶），服务器对 `/video/xxx.mp4`、`/doc/xxx.pdf` 并不校验会话。
- 前端为了「点一下就能播放/下载」，必然要把真实 URL 交给浏览器；只要 URL 出现在 HTML/JS 里（`onclick="location.href='...'"`、`<a href="..." download>`、`video.src`），就绕不过「可见即可取」：攻击者不需要会播放器，复制 URL 用 `curl`/迅雷即可。
- 因此权限判断位置错误是根因：把「是否展示入口」当成了「是否能访问资源」。一旦 URL 被枚举或从源码读到，鉴权完全失效。
- 危害取决于内容：付费课程视频、内部培训资料、收费文档被批量下载，直接造成内容资产泄露；若文件名含规律（`1_850.mp4`、`720.pdf` 之类编号），还能按编号遍历扩面。
- 与「接口返回直链」的区别：本场景不经过任何业务接口，URL 是静态拼接/预置的，绕过接口鉴权直接命中文件服务器，日志里表现为「无 Referer 的静态文件 GET」。

## 触发条件

- 资源以静态文件/公共读对象存储形式提供，文件服务器不校验会话与权益。
- 页面源码（HTML、前端 JS）里能看到完整资源 URL 或可推导的 URL 规则。
- 目标未对资源目录做 Referer 防盗链、签名 URL 或短期 token。
- URL 具有可枚举规律（编号、日期、文件名与 ID 对应）。

## 利用步骤

1. 未登录访问资源详情页，确认页面提示「没有权限操作此软件/没有权限」且不渲染播放器。
2. 打开 F12 或直接请求页面 HTML，在 `onclick`、`<a>`、`<video>`、`<script>` 里搜索 `.mp4`、`.pdf`、`.m3u8`、`/upload/`、`/files/` 等特征。
3. 取出完整 URL（可能是相对路径，补全为绝对地址），用 `curl -I` 或下载工具直接请求。
4. 观察响应：`200` 且 `Content-Type: video/mp4`/`application/pdf`、`Content-Length` 与文件大小匹配，即确认未授权可取。
5. 按文件名规律（递增编号、日期目录）小范围遍历验证是否可批量获取，记录样例即可，不要全量拖取。
6. 对文档同样处理：`<a ... download>` 的 href 就是直链。

## PoC

```http
GET /upload/video/xxx_1_850.mp4 HTTP/1.1
Host: target
```

```http
GET /upload/doc/xxx书_720.pdf HTTP/1.1
Host: target
```

（不带 Cookie 即可；响应 200 且返回完整媒体/文档流说明未授权。原文用下载工具直接粘贴 URL 下载成功。）

## 变体与关联

- 变体：`m3u8` 切片地址同样可直取，拿到切片后可离线合并；`Referer` 防盗链可用目标站点域名伪造。
- 变体：对象存储公共读桶时，URL 形如 `https://<bucket>.oss-....com/...`，可直接列举或按目录遍历。
- 变体：URL 做了 base64/十六进制混淆仍属「客户端可得」，解码即可；签名 URL 若过期时间很长同样可长期复用。
- 关联：[[web-generic-auth-vip-course-direct-media-url-leak]]（业务接口直接返回付费媒体直链，属同一根因的接口侧形态）。
- 关联：[[pentest-initial-access-zlmediakit-file-index-camera-stream-unauth]]（静态资源/流媒体目录不鉴权的极端形态）。

## 检测与防御

- 防御：资源访问必须经过服务端鉴权：下载/播放接口校验会话与权益后，用短期签名 URL（OSS/STS）或反向代理校验 Cookie 后 `X-Accel-Redirect`，文件服务器不直接对外。
- 防御：不要在前端拼接真实文件路径；用资源 ID 换取一次性地址。
- 防御：对静态目录设置防盗链与权限（Nginx `auth_request`），并按目录隔离付费/免费内容。
- 检测：监控静态资源目录的无 Referer、无 Cookie 请求；对同一 IP 短时间内大量编号连续的 mp4/pdf 请求告警。
- 检测：把「页面源码中出现完整资源路径」纳入发布前检查（尤其付费内容站点）。
