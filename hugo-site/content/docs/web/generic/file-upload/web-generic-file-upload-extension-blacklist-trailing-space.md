---
id: web-generic-file-upload-extension-blacklist-trailing-space
title: 上传扩展名黑名单精确 equals 未 trim：filename 尾空格绕过并保留 .jsp 落地
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-extension-blacklist-trailing-space
tags:
- web
- java
- jsp
- file-upload
- blacklist
- bypass
- trailing-space
- webshell
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:18:19+08:00'
  notes: 已对照原文与 28 张图核对：UploadServlet.service 的 ssDfctId 会话校验、getUploadFileName 的 hex+原后缀、mimeTypeCheck 的扩展名/Content-Type 双重黑名单 equals、getUploadDir 日期目录、/AddressFileUpload 映射均与图 14-22 一致；filename="example.jsp " 使 ext="jsp " 不等于 "jsp" 的逻辑成立。核实修正：卡内指向已 reject 草稿的 wiki 链接已改为既有同类卡 web-generic-file-inclusion-luckyframeweb-download-filename-traversal。未验证点：原文未展示上传后 JSP 访问成功；尾空格落成 .jsp 依赖 Windows 文件系统；需普通用户会话。
url: /docs/web/generic/file-upload/web-generic-file-upload-extension-blacklist-trailing-space/
draft: false
kb_aliases:
- 尾空格绕过上传黑名单
- 扩展名黑名单未 trim
- filename jsp 空格
- UploadServlet 后缀校验绕过
- 普通用户上传 getshell
---

## 一句话结论

上传 Servlet 的黑名单校验把“最后一个点之后的后缀”转小写后与黑名单逐个 `equals`，但没有做 `trim`/规范化；上传 `filename="example.jsp "`（末尾带空格）时后缀被取成 `jsp `，不等于 `jsp` 从而绕过，随后服务端用“随机 hex + 原后缀”命名并写入 Web 目录，在会去掉文件名尾部空格/点的文件系统（典型为 Windows）上实际落成 `.jsp`，被容器解析执行；接口只要求普通用户会话，因此普通账号即可 getshell。

## 原理

- **文件名生成**：`getUploadFileName` 取 `fileName.lastIndexOf('.')`，返回 `createHaxa16() + fileName.substring(p)`。即随机前缀 + 最后一个点之后的全部字符，尾空格被原样保留。
- **黑名单校验**：`mimeTypeCheck` 计算 `ext = fileName.substring(p + 1).toLowerCase()`，然后遍历扩展名黑名单（`exe`、`asp`、`aspx`、`php`、`jsp`、`cs`、`js`、`bat`、`css`、`htm`、`html`、`eml` 等）做 `fileTypeList[k].equals(ext)`。由于是精确字符串比较，`"jsp "` 与 `"jsp"` 不相等，校验通过。
- **内容类型校验同理**：另一个黑名单按 `Content-Type` 精确比较（`application/octet-stream`、`application/x-javascript`、`text/html`、`text/css` 等）；把 multipart 的 `Content-Type` 改成 `image/jpeg` 等不在黑名单中的值即可通过。
- **落盘**：`ServletFileUpload` + `DiskFileItemFactory` 把文件写入按日期生成的目录，文件名为随机 hex + 后缀；该目录位于 Web 可访问路径下。Windows 的文件系统 API 会去掉文件名末尾的空格和点，因此 `.jsp ` 实际落为 `.jsp`，Tomcat/JSP 引擎按 JSP 解析。
- **权限边界**：`UploadServlet.service` 从 session 取 `ssDfctId`，`sessionRequired()` 为真且该值为空时直接返回错误；因此这不是未授权上传，而是“普通登录用户 → webshell”的权限提升面。

## 触发条件

- 目标存在继承自该 `UploadServlet` 的上传 Servlet（如 `/AddressFileUpload`），且上传目录位于 Web 根/静态映射内，容器正常解析 JSP。
- 攻击者拥有普通用户会话（session 中存在 `ssDfctId` 等身份标识）。
- 应用运行在会去除文件名尾部空格/点的文件系统上（典型为 Windows）；Linux 会保留尾空格，需要改用大小写、双扩展名、其他可解析后缀或 `::$DATA` 等变体。
- 未部署“上传目录禁止脚本执行”或独立文件服务器策略。

## 利用步骤

1. 登录普通账号，获取有效会话。
2. 构造 multipart 上传请求到继承类 Servlet 的路由（如 `/AddressFileUpload`），文件字段名按实现填写。
3. `filename` 使用 `example.jsp `（末尾空格），`Content-Type` 设为 `image/jpeg` 等非黑名单值，内容写 JSP webshell。
4. 服务端校验通过后写入“日期目录/随机 hex.jsp”；从响应、目录规律或错误信息推断访问路径。
5. 访问该 `.jsp` 验证命令执行或连接 WebShell 管理工具。

## PoC

```http
POST /AddressFileUpload HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Cookie: JSESSIONID=<普通用户会话>

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="example.jsp "
Content-Type: image/jpeg

<% out.println(111); %>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="user_id"

testuser
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

随后访问生成的 `<随机hex>.jsp`。原文未给出上传成功后的访问截图，落盘路径与随机名需结合目标目录规则判断。

## 变体与关联

- **尾点/尾空格**：`example.jsp.`、`example.jsp `、`example.jsp::$DATA`（Windows NTFS 备用数据流）都可使精确匹配的后缀黑名单失配，是否最终解析为 JSP 取决于文件系统与容器。
- **大小写与双扩展名**：黑名单只转小写而未覆盖 `.jspx`、`.jspf`、`.js` 等容器可解析后缀时，可直接换后缀。
- **内容类型黑名单**：把 multipart 内容类型改为图片类型即可绕过按 Content-Type 的拒绝逻辑。
- **同类卡**：[[web-generic-file-upload-crm-sendfile-jsp-preserve-suffix]] 同样是“原后缀保留 + 文件名尾空格”的 JSP 落地；本卡的区别是存在显式后缀黑名单，需要 `jsp ` 与 `jsp` 的精确匹配差异来绕过。
- **前置链**：普通用户会话可来自任意文件读取泄露的数据库配置后添加的账号（同类下载接口参数直入文件路径见 [[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]）。

## 检测与防御

- 扩展名白名单而不是黑名单；比较前统一 `trim()`、转小写、去除末尾点/空格与 `::$DATA`，并拒绝多扩展名与空后缀。
- 用服务端生成的固定扩展名（按业务类型映射），不要保留用户提供的后缀；随机文件名不改变“后缀可控”的本质。
- 上传目录移出 Web 根或使用对象存储；若必须落 Web 目录，关闭该目录的脚本解析权限。
- 监控文件名含尾空格/尾点/`::$DATA` 的 multipart 请求，以及上传目录中新出现的可执行脚本文件。
