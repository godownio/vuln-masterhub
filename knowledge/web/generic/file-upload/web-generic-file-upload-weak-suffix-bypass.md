---
id: web-generic-file-upload-weak-suffix-bypass
title: 上传仅按文件名后缀弱校验，改后缀即可落地任意类型文件
type: scenario
domain: web
path: web/generic/file-upload
technique: file-upload-extension-bypass
aliases:
- 后缀校验绕过
- 扩展名弱校验
- 任意文件上传
- 上传类型绕过
- filename 后缀可控
tags:
- web
- file-upload
- extension-bypass
- multipart
- content-type
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:07:43+08:00'
  notes: 已对照原文与5张图核对：hello.html 改后缀上传、响应 code=0/msg=ok、落地文件可访问均与图一致；原文未验证脚本执行，卡片已如实限定影响边界
---

## 一句话结论

上传接口只依据 multipart 文件名中的后缀做限制、且校验不严时，攻击者修改 `filename` 后缀即可让服务端接收并保存原本不允许的文件类型；文件落地后可被 Web 访问，就构成可复用的任意文件上传原语。

## 原理

- 服务端把 `Content-Disposition: form-data; name="file"; filename="..."` 中的文件名当作可信输入，从该字符串截取扩展名做判断。
- 如果只做简单黑名单/白名单比较、大小写或双后缀处理不严、未同时校验 `Content-Type` 与文件魔数，攻击者就能通过改名让扩展名落入允许集合，而文件内容仍由自己控制。
- 文件按原字节写入 Web 可访问目录后，服务端不再关心它“本来应该是什么类型”，访问该 URL 即按实际内容解析，从而形成任意文件落地。

## 触发条件

- 上传接口对未授权或低权限用户开放；
- 扩展名判断取自客户端文件名，且只做弱校验（黑名单、简单后缀匹配、大小写/多点号处理缺陷）；
- 未同时校验 Content-Type、文件头魔数与实际解析类型；
- 上传目录位于 Web 根下或可被外部访问；
- 目标服务器对落地文件的解析行为可知（是否执行脚本、是否按 HTML 渲染）。

## 利用步骤

1. 先用正常图片/文档走通上传，记录请求结构、参数名、返回的落地路径或文件名规则。
2. 观察服务端对后缀的反馈：改大小写、双后缀、加空格/点、换 `Content-Type`，判断校验依据。
3. 构造一个内容可控、后缀在允许范围内的文件（例如 `hello.html` 配合 `Content-Type: text/html`），确认服务端返回成功。
4. 按响应中的路径访问文件，确认内容原样返回、未被重命名或强制下载。
5. 结合目标解析能力评估影响：同源 HTML 可导致存储型 XSS/钓鱼；脚本后缀且目录可解析才可能进一步 RCE；否则按任意文件落地/托管评估。

## PoC

```http
POST /<upload-path> HTTP/1.1
Host: <target-ip>:<port>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX

------WebKitFormBoundaryX
Content-Disposition: form-data; name="file"; filename="hello.html"
Content-Type: text/html

<!DOCTYPE html><html><body>upload-test</body></html>
------WebKitFormBoundaryX--
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"code":"0","msg":"ok","data":"<落地路径或文件名>"}
```

随后请求返回的落地 URL，确认文件可访问且内容未被改写。

## 变体与关联

- 变体：大小写后缀（`.PhP`）、双后缀（`.jpg.php`、`.php.jpg`）、末尾点/空格、`filename*=` 编码、`Content-Type` 伪装、.htaccess/web.config 覆盖、解析漏洞与竞争上传。
- 关联：[[web-generic-file-upload-extension-zero-check]]（完全不做扩展名校验、可直接上传脚本并执行）；[[web-generic-auth-cookie-base64-identity-forgery]]（认证缺陷后到达上传点）；[[pentest-recon-mobile-app-traffic-shadow-asset]]（从客户端流量发现外围上传服务）。
- 影响边界：本文只验证到“非预期后缀文件成功上传并可访问”，未验证脚本执行或同源渲染；若上传目录不解析脚本、文件强制下载或跨域隔离，危害会降级。因此 confidence 定为 low。
- 环境差异：不同框架对 `filename` 的解析（引号、分号、路径分隔符）不同，绕过方式需按目标实测。

## 检测与防御

- 检测：上传目录中新出现的非常规后缀/脚本文件；同一账号短时间多次改后缀上传；Web 访问日志中对刚上传文件的直接访问。
- 防御：服务端用白名单 + 文件头魔数 + 内容解析三重校验；重命名并剥离客户端扩展名；上传目录禁止脚本执行、与 Web 根分离；对可访问文件强制 `Content-Disposition: attachment` 与正确 Content-Type。
