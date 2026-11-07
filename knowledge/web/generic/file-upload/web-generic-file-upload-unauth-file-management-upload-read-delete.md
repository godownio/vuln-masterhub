---
id: web-generic-file-upload-unauth-file-management-upload-read-delete
title: 未授权文件管理接口：上传/读取/删除三权裸奔
type: scenario
domain: web
path: web/generic/file-upload
technique: unauth-file-management-upload-read-delete
aliases:
- 未授权文件上传读取删除
- 文件管理接口缺认证
- /file/Files 未授权
- 文件接口三权裸奔
- 未授权文件删除
tags:
- web
- file-upload
- unauthorized
- file-read
- file-delete
- spring-boot
- missing-auth
- integrity
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:05:03+08:00'
  notes: 已对照原文第四.4节核对：POST /file/Files 返回 cloudcard-file_CY8a4t9G12.jpg；GET /file/Files/{id} 返回 Base64 fileContent 与元信息；POST /file/Files/delete 返回 0000；扩展名矩阵（jpg/png/svg 成功，html/jsp/php/双重扩展名/../ 路径/伪造 Content-Type 均 1210）与原文一致。文章无图片，无法用截图二次核对。未验证点：目标已脱敏、PoC 未本机复跑、测试矩阵为作者自述；SVG 存储型 XSS 链原文明确未打通，卡内也已标为潜在变体而非已证明危害。
---

## 一句话结论

当文件服务的上传、读取、删除接口整体遗漏认证时，任何人无需 Token 即可上传文件、按 ID 读取文件内容、按 ID 删除文件，形成对文件存储层的完整未授权控制。

## 原理

- 案例为 Spring Boot 单模块应用：`POST /file/Files` 上传、`GET /file/Files/{id}` 读取、`POST /file/Files/delete` 删除。三个接口都不校验 `Authorization` 头，也不依赖 Session。
- 根因是权限配置只覆盖了认证模块（如 `/auth/**`），漏掉了文件模块（`/file/**`）；开发可能在 Controller 上写了 `@PreAuthorize`，但 Spring Security 的拦截规则没有覆盖该路径，注解未生效。
- 上传接口按扩展名白名单（jpg/png/svg）校验，服务端生成随机 ID（如 `cloudcard-file_<random>.jpg`）并保存文件元信息；读取接口按 ID 返回 Base64 内容与文件名/大小/扩展名；删除接口按 ID 删除。
- 未授权上传意味着攻击者可把目标当免费文件存储/图床，托管钓鱼图片、恶意 SVG、社工素材；未授权读取意味着只要知道/枚举到 ID，就能下载其他用户上传的学生照片、学校 Logo、卡面设计等文件；未授权删除意味着可按 ID 破坏文件完整性。
- 上传接口的扩展名白名单能阻止 JSP/PHP/HTML 直接落地，但 SVG 本身可携带脚本；是否能形成存储型 XSS 取决于前端如何渲染（`<img>` 加载不会执行 SVG 脚本，`innerHTML`/`embed`/`object` 才可能执行），原文未完成该链，属于潜在变体而非已证明危害。

## 触发条件

- 目标暴露文件管理接口（上传/读取/删除），且未配置认证或对象级授权。
- 攻击者知道接口路径与参数格式（可从 SPA JS、前端上传组件或路由枚举获得）。
- 上传接口的扩展名白名单允许 svg 等可被浏览器解释的类型（用于存储型 XSS 变体）。
- 读取/删除接口使用可枚举或可预测的文件 ID（用于越权读取/删除他人文件）。

## 利用步骤

1. 从前端 JS、上传组件或接口枚举中找到 `/file/Files`、`/file/Files/{id}`、`/file/Files/delete`。
2. 不带任何认证头上传测试文件，确认返回 `respCode=0000` 与文件 ID。
3. 用返回的 ID 读取文件，确认接口返回 Base64 内容与元信息。
4. 测试扩展名边界：jpg/png/svg 是否允许，jsp/php/html/双重扩展名/路径遍历文件名是否被拒。
5. 用 ID 调用删除接口，确认未授权删除成功。
6. 评估 ID 可枚举性；若 ID 随机但可预测/泄露（列表接口、页面引用），可越权读取或删除他人文件。

## PoC

```bash
# 1. 未授权上传
curl -sk -X POST "https://target/file/Files" \
  -F "file=@test.jpg;filename=test.jpg"
# {"respCode":"0000","respInfo":"处理成功","obj":"cloudcard-file_CY8a4t9G12.jpg"}

# 2. 未授权读取（Base64 内容 + 元信息）
curl -sk "https://target/file/Files/cloudcard-file_CY8a4t9G12.jpg"
# {"respCode":"0000","obj":{"id":"...","fileName":"test.jpg","fileExt":"jpg","fileSize":12345,"fileContent":"/9j/4AAQ..."}}

# 3. 未授权删除
curl -sk -X POST "https://target/file/Files/delete" \
  -H "Content-Type: application/json" \
  -d '{"id":"cloudcard-file_CY8a4t9G12.jpg"}'
# {"respCode":"0000","respInfo":"处理成功"}
```

```text
# 扩展名测试结果（原文）：
# jpg/png/svg -> 0000 成功
# html/jsp/php、双重扩展名、../../etc/passwd.jpg、伪造 Content-Type -> 1210 文件格式不对
```

## 变体与关联

- 变体：SVG 存储型 XSS——上传带 `<script>` 的 SVG，若前端把 Base64 内容 `innerHTML`/`embed`/`object` 渲染，脚本可窃取 localStorage 中的 Token；原文未完成该链（读取返回 Base64，`<img>` 不执行脚本），仅作为潜在组合。
- 变体：文件 ID 枚举/列表接口泄露导致越权读取他人上传的学生照片、证件、卡面等 PII。
- 变体：批量删除/遍历删除造成文件完整性破坏与业务中断。
- 变体：上传接口若使用原始文件名或可预测 Key，可转向对象存储同名覆盖，见关联卡。
- 关联：[[web-generic-file-upload-unauth-object-storage-overwrite]]（未授权上传 + 同名覆盖）、[[web-generic-file-upload-content-type-trust-bypass]]、[[web-generic-xss-unauth-stored-xss-hot-question]]（存储型 XSS 链）。
- 边界：文件接口已加认证/对象级授权、上传白名单严格且重编码、文件 ID 不可枚举、读取接口只返回本人文件时，本场景降级或失效。

## 检测与防御

- 检测：访问日志中出现无 `Authorization` 头的 `/file/Files`、`/file/Files/{id}`、`/file/Files/delete` 请求；同一 IP 高频上传/读取/删除；上传文件扩展名分布异常（大量 svg）；删除操作集中在业务关键文件。
- 修复：对 `/file/**` 统一加认证与对象级授权；上传接口校验文件内容/魔数并重编码图片；服务端生成不可预测 ID；读取/删除校验文件所有者或业务权限；禁止或净化 SVG。
- 加固：文件服务独立域名/独立存储，禁止匿名读写；上传限速与配额；对文件操作做审计与告警；前端渲染上传文件时使用 `Content-Disposition: attachment` 或隔离域，避免 SVG/HTML 脚本执行。
