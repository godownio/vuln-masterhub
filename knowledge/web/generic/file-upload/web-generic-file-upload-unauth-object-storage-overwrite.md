---
id: web-generic-file-upload-unauth-object-storage-overwrite
title: 未授权文件上传接口导致对象存储同名对象覆盖
type: scenario
domain: web
path: web/generic/file-upload
technique: unauth-upload-object-storage-overwrite
aliases:
- OSS 同名覆盖
- 对象存储文件覆盖
- 未授权上传
- 上传接口覆盖
- 云桶对象覆盖
tags:
- web
- file-upload
- unauthorized
- object-storage
- oss
- overwrite
- integrity
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:33:02+08:00'
  notes: 已对照原文与图24/29/30核对：POST /api/common/upload 未鉴权返回 OSS URL，重复以同名 2.txt 上传不同内容后，访问对象看到内容被覆盖；.html 与 ?response-content-type=text/html 被桶策略拒绝，卡中边界描述准确。危害为对象完整性破坏，severity=medium 合理。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

当文件上传接口未鉴权且直接使用原始文件名作为对象存储的 Key 时，攻击者可重复上传同名文件覆盖桶中已有对象，造成图片/文档/静态资源被替换的完整性破坏；若桶允许控制 Content-Type 且对外提供内容，还可能升级为存储型 XSS。

## 原理

- 上传接口通常接收 multipart 文件，服务端把文件写入本地目录或对象存储（如 OSS/S3/COS），并把对象 URL 返回给前端。
- 如果接口没有认证/授权，任何人只要知道路径和字段名就能上传。
- 对象存储的 `PutObject` 对同一个 Key 默认是覆盖语义：上传同名对象会替换已有内容（除非开启版本控制或对象锁）。若服务端保留原始文件名（而不是生成随机 UUID），攻击者就能精确覆盖已知对象。
- 覆盖的后果取决于对象用途：替换网站图片可造成篡改；替换 JS/CSS 可影响页面行为；若桶对外提供且允许 `text/html`，可植入钓鱼页或 XSS。案例中桶对 Content-Type 修改和匿名访问做了严格限制，因此只证明了覆盖。
- 尝试通过 `.html` 后缀或 `?response-content-type=text/html` 改变响应类型时，服务端/CDN 可能仍按 `Content-Disposition: attachment` 或固定 Content-Type 返回，阻止脚本执行。

## 触发条件

- 存在未鉴权的文件上传接口（前端上传组件对应的 `/api/common/upload` 等）。
- 对象存储使用原始文件名/可预测 Key，且未开启版本控制/对象锁。
- 攻击者知道或能枚举目标对象 Key（图片路径、附件名、静态资源名）。
- 覆盖后的对象会被站点或其他用户访问，才能产生实际影响。

## 利用步骤

1. 从前端 JS、上传组件、抓包或路由枚举中找到上传接口及表单字段名。
2. 上传一个测试文件，记录返回的对象 URL 与 Key（案例中 Key 就是原文件名）。
3. 确认目标 Key 对应的现有对象可被公开访问，并记录其内容。
4. 用相同文件名、不同内容再次上传。
5. 访问对象 URL，确认内容已被替换。
6. 评估影响：替换的是图片、文档、JS/CSS 还是可执行 HTML；据此判断是篡改、钓鱼还是 XSS。

## PoC

```bash
# 1. 上传测试文件，观察返回的 URL/Key
curl -i -X POST 'https://target.example/api/common/upload' \
  -F 'file=@2.txt;type=image/jpeg'

# 返回示例：
# {"msg":"上传成功","code":200,"url":"https://bucket.example/2.txt"}

# 2. 用同名文件覆盖
printf 'overwritten-content' > 2.txt
curl -i -X POST 'https://target.example/api/common/upload' \
  -F 'file=@2.txt;type=image/jpeg'

# 3. 访问确认
curl -s 'https://bucket.example/2.txt'
```

```text
# 预期：返回的 URL 内容从原内容变为 overwritten-content
```

## 变体与关联

- 变体：上传 `.html`/`.svg` 并尝试 `?response-content-type=text/html` 或对象元数据覆盖，若桶/CDN 允许则转为存储型 XSS；案例中被桶策略拒绝。
- 变体：覆盖站点引用的 JS/CSS/图片，造成页面篡改或供应链式影响。
- 变体：若 Key 可由路径穿越/目录遍历控制，可覆盖桶内其他目录对象；案例中桶限制严格，未发现遍历、AK/SK 泄露、临时 token 或桶接管。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]、[[web-generic-file-upload-clientside-js-whitelist-bypass]]（上传校验绕过）；[[web-generic-xss-unauth-stored-xss-hot-question]]（另一条存储型 XSS 路径）。
- 边界：仅覆盖对象不等于 RCE；需要目标对象被访问且用途敏感。对象存储开启版本控制、随机 Key、禁止覆盖或独立静态域名时，影响显著降低。

## 检测与防御

- 检测：审计上传接口的认证与授权；监控同一 Key 的高频覆盖写；对桶内对象做完整性/哈希基线；告警上传后 Content-Type 或对象元数据异常变更。
- 修复：上传接口要求认证与配额；服务端生成随机对象 Key，禁止客户端指定文件名；桶策略禁止覆盖或开启版本控制/对象锁。
- 加固：上传内容做类型/魔数校验并重编码图片；静态资源使用独立域名与 `Content-Disposition: attachment`；限制桶的匿名读写与 Content-Type 修改权限；对关键静态资源做 CDN 缓存与完整性校验。
