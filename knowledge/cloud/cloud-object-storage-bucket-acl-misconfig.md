---
id: cloud-object-storage-bucket-acl-misconfig
title: 对象存储 Bucket ACL 配置错误：公共读 ListObject 目录遍历与公共读写 PUT 上传
type: scenario
domain: cloud
path: cloud
technique: object-storage-bucket-acl-misconfig
aliases:
- OSS Bucket 公共读
- OSS 公共读写
- ListObject 目录遍历
- Bucket ACL 配置错误
- 对象存储任意上传
- 公共读写 PUT
tags:
- cloud
- object-storage
- oss
- cos
- s3
- acl
- information-disclosure
- file-upload
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:10:26+08:00'
  notes: 已对照原文与图片02/04/06/08核对：公共读+ListObjects 通过目录URL列出对象；公共读写可PUT。图04 ACL为公共读写、图08为只读(含ListObject)。卡内已纠正原文“上传PHP/JSP即可执行”的错误：对象存储仅静态托管，脚本执行需前置CDN/反向代理/应用服务器，实际危害是数据泄露/篡改/钓鱼/XSS。原文未给受影响版本；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

对象存储 Bucket 被设为“公共读”且授权策略包含 `ListObjects` 时，匿名访问对象 URL 的上一级目录会返回该前缀下的对象列表，导致批量目录遍历与敏感文件下载；被设为“公共读写”时，匿名用户可用 HTTP PUT 上传/覆盖对象，造成数据篡改、恶意内容托管与钓鱼，若前置 CDN/反向代理/应用服务器错误地把对象当脚本解析，才可能进一步执行代码。

## 原理

- 对象存储（阿里云 OSS、腾讯云 COS、AWS S3 等）用 Bucket 作为顶层容器，对象的访问权限由 Bucket ACL 与 Bucket 授权策略共同决定。
- “公共读”允许匿名 `GetObject`；如果授权策略还包含 `ListObjects`/`ListObjectsV2`，匿名请求目录前缀（如 `https://bucket.oss-cn-shanghai.aliyuncs.com/docs/`）会返回 `ListBucketResult`，列出该前缀下的所有对象 Key，形成目录遍历。
- “公共读写”允许匿名 `PutObject`/`DeleteObject`；攻击者可直接 PUT 任意对象（如 HTML、JS、SVG、压缩包），覆盖业务文件或投放恶意内容。
- 对象存储本身通常只做静态托管，不解析 PHP/JSP；上传 `.php`/`.jsp` 一般只会被当作静态文件下载/返回。只有当 Bucket 绑定自定义域名并由 CDN、反向代理或应用服务器错误地转发/解析脚本时，才可能升级为代码执行；否则主要危害是数据泄露、篡改、钓鱼、存储型 XSS（HTML/SVG）与恶意软件分发。
- Bucket 名称在同厂商内全局唯一；公共读/读写是常见的历史配置错误，尤其在静态资源、日志、备份、前端直传场景。

## 触发条件

- Bucket ACL 为公共读或公共读写，且匿名访问可到达。
- 公共读场景：授权策略包含 `ListObjects`/`ListObjectsV2`；对象 Key 可猜测或目录列表可枚举。
- 公共读写场景：允许匿名 `PutObject`；Bucket 绑定自定义域名或 CDN，可能被用于内容托管/钓鱼。
- 目标未启用“阻止公共访问”、未限制 Referer/IP、未开启版本控制/合规保留。

## 利用步骤

1. 从页面源码、JS、APP 抓包或 DNS 记录中找到对象存储域名（`*.oss-cn-*.aliyuncs.com`、`*.cos.*.myqcloud.com`、`*.s3.*.amazonaws.com` 等）。
2. 访问一个已知对象 URL，再把路径截断到上一级目录（如 `/docs/1.pdf` → `/docs/`），观察是否返回 XML 对象列表。
3. 若返回列表，解析 `<Key>`/`<Contents>` 批量下载；优先找备份、日志、配置、用户数据、前端 source map。
4. 测试写权限：对随机 Key 发送 `PUT`，内容为无害字符串；若返回 200/204，说明公共读写。
5. 若可写，评估影响：覆盖业务静态资源、上传钓鱼 HTML、上传恶意 SVG/JS；不要上传 webshell 并假定会被执行，先确认前置是否有脚本解析。
6. 记录 Bucket、权限、可读/可写对象范围；避免批量下载/覆盖真实业务数据。

## PoC

目录遍历探测：

```http
GET /docs/ HTTP/1.1
Host: bucket.oss-cn-shanghai.aliyuncs.com
```

若返回：

```xml
<ListBucketResult>
  <Contents><Key>docs/1.pdf</Key></Contents>
  <Contents><Key>docs/2.pdf</Key></Contents>
</ListBucketResult>
```

匿名 PUT 测试：

```http
PUT /test-write-check.txt HTTP/1.1
Host: bucket.oss-cn-shanghai.aliyuncs.com
Content-Type: text/plain
Content-Length: 5

hello
```

返回 `200 OK` 或 `204 No Content` 表示可匿名写入；随后 `GET /test-write-check.txt` 验证。

恶意内容托管（仅用于授权测试）：

```http
PUT /phish.html HTTP/1.1
Host: bucket.oss-cn-shanghai.aliyuncs.com
Content-Type: text/html
Content-Length: ...

<html><body>...</body></html>
```

## 变体与关联

- 变体：仅公共读但无 ListObjects 时，只能下载已知 Key；可通过 JS/source map/备份命名规则猜 Key。
- 变体：公共读写可覆盖已有对象（如 JS/CSS），造成供应链/前端劫持；版本控制可缓解但不会阻止写入。
- 变体：Bucket 绑定 CDN/自定义域名时，缓存可能继续提供旧内容或被投毒。
- 变体：部分厂商有“公共读（包含 ListObject）”与“公共读（不包含 ListObject）”两个预设，需区分。
- 关联：[[cloud-object-storage-dangling-cname-bucket-takeover]]（Bucket 删除后的 CNAME 接管）。
- 关联：[[web-generic-file-upload]] 下的上传/解析卡（对象存储本身通常不解析脚本，需确认前置解析）。
- 注意：不要把“PUT 成功”直接等同于 RCE；对象存储的静态托管与脚本解析是两件事。

## 检测与防御

- 防御：默认私有；关闭“阻止公共访问”例外；公共读 Bucket 移除 `ListObjects`，只暴露必要对象；禁止公共读写。
- 防御：前端直传使用 STS 临时凭证 + 最小权限 + 对象前缀限制；开启版本控制与访问日志；绑定 CDN 时限制回源与内容类型。
- 检测：Bucket 策略/ACL 变更为 `public-read`/`public-read-write`；匿名 `ListObjects`/`PutObject` 成功日志；大量目录前缀 GET；异常对象上传（HTML/SVG/JS/压缩包）；CDN 回源异常。
- 响应：发现公共读写立即回滚 ACL、删除恶意对象、轮换可能泄露的凭证、检查 CDN 缓存与前端引用。
