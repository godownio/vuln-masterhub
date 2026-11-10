---
id: web-generic-file-upload-signed-visit-302-path-disclosure
title: 上传文件的签名访问接口 302 Location 泄露真实存储路径：以 ShowDoc visitFile 为例
type: scenario
domain: web
path: web/generic/file-upload
technique: signed-visit-302-path-disclosure
tags:
- web
- file-upload
- info-disclosure
- path-disclosure
- showdoc
- http-redirect
- phar
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:09:44+08:00'
  notes: 已对照原文图14核对 visitFile&sign 返回 302 且 Location 为 Public/Uploads/2024-06-05/665f63851018d.jpg；卡内示例已占位化；与既有 ShowDoc phar 卡为前置路径泄露关系而非重复；原文未声明该行为的版本区间。
url: /docs/web/generic/file-upload/web-generic-file-upload-signed-visit-302-path-disclosure/
draft: false
kb_aliases:
- visitFile 路径泄露
- sign 访问接口 302
- 上传真实路径暴露
- attachment visitFile
- 附件访问跳转泄露路径
---

## 一句话结论

ShowDoc 上传文件后返回的是带 `sign` 的不透明访问链接（`/server/index.php?s=/api/attachment/visitFile&sign=...`），但请求该链接时服务端返回 302，`Location` 直接给出真实静态文件路径（如 `http://host/Public/Uploads/2024-06-05/<hash>.jpg`）；原本用来隐藏存储位置的签名机制因此失效，攻击者拿到真实路径后可直连文件，也可将其作为 `phar://` 路径触发反序列化。

## 原理

- **签名链接的意图**：上传接口不直接返回物理路径，而是返回 `sign`，客户端用 `visitFile&sign=<sign>` 间接访问，表面上隐藏了文件名/目录。
- **302 暴露真实路径**：`visitFile` 的处理逻辑根据 `sign` 查到文件后，用 302 重定向到静态资源 URL，`Location` 头就是真实存储路径（含日期目录与哈希文件名）。重定向头对客户端完全可见，签名只保护了「入口」，没有保护「出口」。
- **为什么这很重要**：很多后续利用需要知道上传文件的文件系统路径——例如 PHAR 反序列化必须用 `phar://<真实路径>` 才能让 PHP 解析归档 metadata；只用 HTTP URL 或 `sign` 不能触发。302 泄露把「盲上传」变成「路径可知」。
- **路径结构可预测**：示例路径为 `Public/Uploads/<YYYY-MM-DD>/<hash>.<ext>`，日期目录 + 哈希文件名；即使不依赖 302，知道日期和上传响应也能推测，但 302 直接给出精确值。
- **边界**：若服务端改为流式输出文件、返回 CDN 签名 URL（仍可能泄露 bucket/key）、或对 `visitFile` 强制鉴权，则泄露面变化；Location 可能是相对路径，需要拼接 Host。

## 触发条件

- 目标应用提供「上传 → 返回 sign → 通过访问接口取文件」的间接访问模式。
- 访问接口使用 HTTP 302/301 跳转到真实静态文件，且 `Location` 未脱敏。
- 攻击者已能上传文件（任意账号或结合其他漏洞获得登录态），并需要真实路径进行后续利用（如 phar://）。
- 上传目录位于 Web 根内或可被 PHP 流包装器访问。

## 利用步骤

1. 登录/获得上传权限后，向文件上传接口提交文件（如 PHAR 改名的 `.jpg`），从响应或文件库取得 `sign`。
2. 请求 `GET /server/index.php?s=/api/attachment/visitFile&sign=<sign>`，禁止自动跟随重定向，读取响应头。
3. 从 `Location` 解析真实 URL/路径（示例 `http://host/Public/Uploads/2024-06-05/<hash>.jpg`），去掉 scheme/host 得到 Web 根相对路径。
4. 直接访问该路径确认文件可读；若目标是 PHAR，构造 `phar://<相对或绝对路径>` 传给文件操作 sink。
5. 结合上传内容与路径，完成 phar 反序列化或直接访问敏感上传文件。

## PoC

```http
GET /server/index.php?s=/api/attachment/visitFile&sign=274720cc0ae1fe98fc945877282926b HTTP/1.1
Host: target
Cookie: PHPSESSID=<session>

HTTP/1.1 302 Found
Location: http://target/Public/Uploads/2024-06-05/665f63851018d.jpg
Content-Length: 0
```

```text
# 取到路径后用于 PHAR 触发（示意）
GET /server/index.php?s=/home/index/new_is_writeable&file=phar://../Public/Uploads/2024-06-05/665f63851018d.jpg
```

说明：以上请求/响应来自文中截图（域名与哈希做占位化处理），仅用于说明 302 泄露路径的机制。

## 变体与关联

- [[web-php-deserialization-showdoc-new-is-writeable-phar-guzzle-filecookiejar-webshell]]：利用本卡泄露的路径把上传的 PHAR 送入 `phar://` 触发反序列化并写 WebShell。
- [[web-php-deserialization-phar-upload-jpg-wakeup-eval]]：上传任意后缀文件后经 `phar://` 触发的同类链，同样依赖「知道上传文件路径」这一前提。
- [[web-generic-static-upload-path-join-download-id-photo-bulk]]：上传路径泄露后拼接静态资源路由批量下载，属同一「路径泄露 → 直连文件」模式。
- 变体：302 跳到对象存储/CDN 的预签名 URL 会泄露 bucket 与 object key；`X-Accel-Redirect` 可能泄露内部路径；相对 `Location` 需结合当前目录解析。
- 边界：签名一次性/短时效只限制访问入口，不影响已泄露路径的直连；若静态目录禁止直接访问或文件被移出 Web 根，则路径价值下降。

## 检测与防御

- 防御：访问接口改为由应用流式输出文件或返回短期预签名 URL，避免在 `Location` 中暴露物理路径/对象存储 key；上传文件存到 Web 根之外并使用随机化、不可枚举的存储 key。
- 防御：上传目录禁止脚本执行（Nginx/Apache 关闭 PHP 解析），对图片做真实解码重编码，破坏 PHAR 结构。
- 检测：监控 `visitFile`/附件访问接口返回 302 且 `Location` 指向上传目录的请求；同一 `sign` 被非浏览器客户端请求、随后出现 `phar://` 参数。
- 响应：发现路径泄露后检查上传目录是否可直连、是否存在被写入的脚本；轮换签名密钥/失效旧 sign。
