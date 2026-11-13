---
id: web-generic-file-upload-nonstandard-filename-header-line-parser
title: '非标准上传格式：不写 multipart，自定义 filename: 1.jsp 头行 + 正文当文件，只解析标准 multipart 的 WAF 看不到文件'
type: scenario
domain: web
path: web/generic/file-upload
technique: nonstandard-filename-header-line-upload
tags:
- web
- file-upload
- waf-bypass
- parser-differential
- filename
- jsp
- multipart
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V486
  verified_at: '2026-11-10T21:44:31+08:00'
  notes: '已对照原文图08核对：POST /upload + 裸 filename: 1.jsp 头行 + 正文 JSP 与卡内 PoC 一致（Host 归一为 target）；单动作（非标准上传格式），filePath 参数动作已拆至另一卡且互引；卡内无 sources/source_url/文章ID/URL，path 合法；原文未给受影响版本，已 --clear。注意：filePath 参数卡实际对应图09（图10 为黑名单后缀绕过幻灯片），核验单中的图号需按 09 修正。未验证点：原文未注明具体后端实现，PoC 未在真实目标执行。'
url: /docs/web/generic/file-upload/web-generic-file-upload-nonstandard-filename-header-line-parser/
draft: false
kb_aliases:
- 非标准上传格式
- filename 头上传
- 裸 filename 行
- 自定义上传协议
- WAF 上传协议解析差异
- 规则绕过特殊案例
---

## 一句话结论

完全不用 multipart：请求里直接写一行自定义头 `filename: 1.jsp`、正文放 JSP 代码，只按标准 `multipart/form-data` 解析上传的 WAF 找不到任何文件 part，于是不做文件名/内容检测直接放行；而使用自定义解析的上传后端仍把该头行当文件名、把正文当文件内容落盘。

## 原理

Java 上传流量对抗的通用背景：WAF 与后端是两套解析器，检测规则作用在“WAF 解析出的文件”上，而落盘发生在“后端解析出的文件”上，两者对同一请求的理解可以不同。

- **协议合规性差异**：上传请求的解析在 RFC 中存在模糊地带，不同语言/框架/中间件实现差异很大（幻灯片称其引擎覆盖 PHP/Java/.NET/Python 四种语言、十种主流框架、41 种 multipart 异常点）。WAF 的解码器只认自己实现的标准格式，后端可能认另一种格式。
- **本手法**：请求不是 `multipart/form-data`，没有 boundary、没有 part、没有 `Content-Disposition`，而是普通 POST 加一行自定义头：
  ```http
  POST /upload HTTP/1.1
  Host: target

  filename: 1.jsp

  <% Runtime.getRuntime().exec('xxx');%>
  ```
  WAF 按标准 multipart 解析器找不到文件与边界，将其视作无文件的普通请求放行，内容规则不触发；后端若实现“从 `filename` 头/自定义行取文件名 + 原始正文作文件内容”的逻辑，则照常以 1.jsp 落盘。
- **为什么有效**：安全决策（有没有文件、文件名后缀、内容是否恶意）全部依赖 WAF 的解析视图；WAF 不认识的协议形态下它根本提取不到检测对象，而真实后端按自己的自定义协议处理同一字节流。

## 触发条件

- 后端上传实现使用自定义解析（从自定义头行/原始正文取文件名与内容），而非标准 multipart 容器解析；
- WAF 仅对标准 multipart/urlencoded 做上传解析与检测，且对“非标准格式的上传请求”不拒绝；
- 上传目录可写且 Web 可访问，配合 .jsp 解析执行拿到 webshell；
- 仅限授权测试；目标后端是否接受该格式需实测（原文仅给出请求样例，未标注具体后端实现）。

## 利用步骤

1. 向目标上传接口发送不含 multipart 的请求（`filename: 1.jsp` 自定义头 + JSP 正文），观察响应是否提示上传成功、是否返回路径/文件名；
2. 访问回显/猜测的落盘路径（如 /upload/1.jsp）确认文件写入与脚本执行；
3. 若目标后端不认该格式，遍历其它非标准形态（重复头、自定义分隔/字段名）或改用自定义协议（见关联卡）；
4. 成功后替换正文为参数化 webshell 扩大利用。

## PoC

```http
# 非标准上传格式（幻灯片示例；未对真实目标执行）
POST /upload HTTP/1.1
Host: target

filename: 1.jsp

<% Runtime.getRuntime().exec('xxx');%>
```

说明：幻灯片仅展示请求结构，未说明具体后端/框架；是否接受该格式、落盘路径与后缀均需按目标实测。

## 变体与关联

- 变体：重复/冲突的 `Content-Disposition`、`name`、`filename`、boundary 伪造、chunked 等“畸形 multipart”解析差异；以及产品自定义协议（如 iweboffice DBSTEP）。
- 关联：[[web-generic-file-upload-iweboffice-dbstep-custom-protocol-waf-bypass]]（自定义协议让 WAF 完全不认识，同一“引擎解码差异”大类）、[[web-generic-file-upload-filename-filepath-parameter-mismatch]]（同一拆分来源的另一张卡：标准 multipart 内经参数控制文件名）、[[web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass]]（重复 filename 的畸形 multipart 变体）、[[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]（后端直接信任标准 filename 的简单情形）。
- 边界：后端若严格只接受标准 multipart 并统一从 filename 取名字，非标准格式无效；WAF 若对上传接口的非 multipart 请求直接拒绝或与目标同实现做一致性校验则失效。

## 检测与防御

- 检测（WAF）：对上传接口收到的非 multipart POST、含裸 `filename:` 行、Content-Type 与正文结构不符的请求直接拒绝或提升检测；按目标应用的实际解析器实现上传解析，而不是只实现标准格式。
- 检测（主机）：上传接口收到非 multipart 请求却落盘文件；落盘文件名/后缀来自请求头行而非框架标准字段；上传目录出现脚本文件与访问日志中的脚本请求。
- 防御：后端统一走标准 multipart 解析并只从单一可信来源取文件名；上传目录移出 Web 根、禁止脚本执行、随机重命名；WAF 对歧义请求采取“拒绝优先”策略。
