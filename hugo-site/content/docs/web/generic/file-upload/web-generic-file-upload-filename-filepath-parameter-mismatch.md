---
id: web-generic-file-upload-filename-filepath-parameter-mismatch
title: multipart filename 与 filePath 参数文件名不一致：WAF 校验 filename=1.txt，后端按 ?filePath=1.jsp 落盘 JSP
type: scenario
domain: web
path: web/generic/file-upload
technique: filename-filepath-parameter-mismatch
tags:
- web
- file-upload
- waf-bypass
- parser-differential
- multipart
- filename
- jsp
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V486
  verified_at: '2026-11-10T21:44:34+08:00'
  notes: '已对照原文图09核对：POST /upload?filePath=1.jsp HTTP/1.0、boundary=----WebKitFormBoundarycHNJSGBoKxSQ20CA、Content-Length: 136、filename="1.txt"、正文 1 与卡内 PoC 一致（Host 归一为 target）；单动作（filename 与 filePath 文件名来源不一致），非标准上传格式已拆至另一卡且互引；卡内无 sources/source_url/文章ID/URL，path 合法；原文未给受影响版本，已 --clear。注意：本卡对应图09，非图10（图10 为黑名单后缀绕过）。未验证点：原文未给具体后端实现，PoC 未在真实目标执行。'
url: /docs/web/generic/file-upload/web-generic-file-upload-filename-filepath-parameter-mismatch/
draft: false
kb_aliases:
- filePath 参数控制文件名
- 文件名受其他参数控制
- filename 与 filePath 冲突
- 上传参数覆盖文件名
- WAF 文件名来源差异
- 多来源文件名绕过
---

## 一句话结论

multipart part 的 `filename` 保持 `1.txt` 骗过只校验它的 WAF，同时在 URL/表单里另给 `filePath=1.jsp` 这类参数；后端不把 filename 当最终名字，而是用该参数拼接落盘路径/文件名，最终写出 `.jsp`——WAF 检查的名字与真正落盘的名字不是同一个来源。

## 原理

Java 上传流量对抗的通用背景：WAF 用自身解析器从请求中提取“文件名/内容”做后缀黑名单与内容检测，后端则按自己的业务逻辑决定最终落盘路径；安全决策对象与实际写入对象一旦错位，检测就被绕过。

- **multipart 的 filename 只是建议名**：RFC 中 `filename` 是客户端建议的文件名，服务端可以不用。真实上传代码常另有 `filePath`、`fileName`、`savePath`、`name` 等参数参与最终路径/文件名拼接。
- **本手法**：幻灯片请求 `POST /upload?filePath=1.jsp`，body 内 `Content-Disposition: form-data; name="file"; filename="1.txt"`，内容为 1。WAF 从 part 的 filename 提取到 `1.txt`，后缀白名单/黑名单判定安全放行；后端落盘时取 `filePath` 参数（值为 1.jsp）决定最终文件名/路径，于是写出 `1.jsp`。
- **为什么有效**：白名单/黑名单、内容检测、落地路径判断都依赖“解析出的文件名与内容”；当 WAF 只看 `filename` 而后端另有参数来源时，WAF 校验的是安全的名字，后端用的是另一个名字，两侧视图不一致。
- 反向同理：把恶意后缀放在 filename、参数放安全名也能制造两侧不一致，具体以目标实现为准。

## 触发条件

- 后端上传代码存在“文件名/落盘路径可由其它请求参数控制”的逻辑，且未对最终落盘名做统一校验/规范化；
- WAF 仅从 multipart 的 `filename`（或仅从某一来源）取文件名做后缀检测，未与其它参数做一致性校验；
- 上传目录可写且 Web 可访问（或配合解析执行 .jsp）；
- 仅限授权测试；哪个参数真正控制落盘需实测。

## 利用步骤

1. 正常 multipart 上传时，在 URL query、表单字段、Header 中分别加入 `filePath`/`fileName`/`savePath`/`name` 等参数并设值 `1.jsp`，filename 保持 `1.txt`；
2. 对比响应与落盘结果，找出真正生效的参数及其拼接规则（前缀目录、后缀拼接还是完全覆盖）；
3. 用安全 filename 通过 WAF、用生效参数让后端写出可执行文件，访问验证；
4. 若被拦截，换参数名/参数位置或组合目录穿越（见变体）。

## PoC

```http
# 文件名受其它参数控制（幻灯片示例；未对真实目标执行）
POST /upload?filePath=1.jsp HTTP/1.0
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarycHNJSGBoKxSQ20CA
Content-Length: 136

------WebKitFormBoundarycHNJSGBoKxSQ20CA
Content-Disposition: form-data; name="file"; filename="1.txt"

1
------WebKitFormBoundarycHNJSGBoKxSQ20CA--
```

说明：幻灯片演示的是 filePath 参数决定落盘名；参数名与生效条件随目标代码而变，未在真实目标执行。

## 变体与关联

- 变体：`fileName`/`savePath`/`uploadPath`/`name` 等参数控制文件名或目录；参数控制目录 + filename 控制后缀组合目录穿越；参数值经二次解码/拼接后再落盘。
- 关联：[[web-generic-file-upload-jsp-uploadpath-param-any-extension-timestamp-rename]]（uploadPath 参数控制目录的实例）、[[web-generic-file-upload-nonstandard-filename-header-line-parser]]（同一拆分来源的另一张卡：完全不标准的上传格式）、[[web-generic-file-upload-iweboffice-dbstep-custom-protocol-waf-bypass]]、[[web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass]]。
- 边界：后端若只从 filename 取最终名并对参数做严格白名单，手法无效；WAF 若校验“filename 与 filePath 等参数后缀一致性”则被识别。

## 检测与防御

- 检测（WAF）：一并提取并交叉校验 multipart filename 与 filePath/fileName/savePath 等参数，后缀不一致即拒绝；对“参数值含路径分隔符或脚本后缀”的请求重点检测。
- 检测（主机）：同一请求中 filename 与 filePath 等参数后缀不一致；落盘文件后缀与请求声明不符；上传目录出现脚本文件。
- 防御：应用只从单一可信来源取文件名，统一规范化（去路径、取最后一段、后缀白名单）后再落盘；落盘名由服务端生成（随机名+白名单后缀）；上传目录移出 Web 根并禁止脚本执行。
