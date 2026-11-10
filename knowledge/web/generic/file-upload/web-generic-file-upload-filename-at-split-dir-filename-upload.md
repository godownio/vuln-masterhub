---
id: web-generic-file-upload-filename-at-split-dir-filename-upload
title: 某协同办公系统上传接口：filename 必须含 @ 且按 @ 分隔为「上传目录+文件名」两段，filename=@1.jsp 直接落 cms/html 目录 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: filename-at-split-dir-filename-upload
aliases:
- filename @ 分隔上传
- '@1.jsp 上传'
- 协同办公系统文件上传
tags:
- file-upload
- java
- webshell
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:48:16+08:00'
  notes: 已对照原文核对：抽取者注明的远程 URL 图片本次已通过带 Referer 头下载全部 6 张并核对成功——web.xml /cms/upload→com.eway.upload.FileUploadServlet、saveCmsHtml 中 ServletFileUpload.parseRequest+filename 含 @ 硬校验+split("@") 两段拼接、getWebCmsHtmlDirPath()=cms/html、POST /cms/upload filename="@1.jsp" 200、GET /cms/html/1.jsp 返回 1，卡描述与证据完全一致，medium 置信疑虑解除。未验证点：真实环境复现。
---

# 某协同办公系统上传接口：filename 必须含 @ 且按 @ 分隔为「上传目录+文件名」两段，filename=@1.jsp 直接落 cms/html 目录 getshell

## 一句话结论

某 Java 协同办公系统的自定义上传处理对 multipart filename 有硬性要求——filename 必须包含 `@` 否则抛异常中断，随后以 @ 为界把 filename 截成两段：第一段与系统默认上传目录拼接为新目录、第二段作为落盘文件名，因此传入 `filename=@1.jsp` 即把 1.jsp（ServletFileUpload 标准解析）落到默认目录 `cms/html` 下并被 Tomcat 解析执行。

## 原理

- 系统用 commons-fileupload 的 `ServletFileUpload.parseRequest` 标准解析上传请求（第三方库部分无自定义逻辑，普通 multipart 包即可）。
- 业务代码随后对 filename 做 `@` 分隔处理：不含 @ 直接抛异常（这是接口的硬编码约定，正常业务用「子目录@文件名」表达层级）；`@` 前第一段拼接到默认上传目录后、`@` 后第二段与该目录拼接生成最终文件。两段均未见后缀白名单/内容校验，最终 `FileOutputStream` 直接写盘。
- 攻击面：第一段留空（`@` 开头）表示不追加子目录，第二段即最终文件名，可携带 `.jsp` 等可执行后缀；默认上传目录 cms/html 位于 web 应用内可被解析。
- 该设计把「目录结构」塞进客户端可控的 filename，等效于目录穿越+文件名控制两个能力合一。

## 触发条件

- 目标为该协同办公系统（web.xml 中含多个上传 servlet 入口，历史漏洞公开可查得部署包源码）；
- 上传接口前台可达（该篇为红队项目实战案例，原文描述可直接上传成功）；
- 默认上传目录 cms/html 可被容器解析 jsp。

## 利用步骤

1. 从历史漏洞/互联网资产获取该系统部署包，在 web.xml 搜索 upload 定位上传 servlet。
2. 构造标准 multipart 包，`Content-Disposition: form-data; name="file"; filename="@1.jsp"`，文件体为 jsp webshell。
3. 落盘位置为 cms/html/1.jsp，访问对应 URL 验证执行；若需其他目录，在 @ 前填子目录段。

## PoC

```http
POST <上传接口> HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="@1.jsp"
Content-Type: image/jpeg

<%= 1 %>
------WebKitFormBoundary--
```

## 变体与关联

- 变体：@ 前段可携带子目录（甚至 ../ 视实现过滤情况），实现任意目录落盘。
- 关联：[[web-generic-file-upload-empty-filename-path-concat-bypass]]（同为「落盘路径部分来自非 filename 字段/特殊格式」的绕过分支）。
- 关联：[[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]（filename 完全信任的基线上传场景）。
- 审计提示：第三方上传库（commons-fileupload/oreilly）处理部分可略读，只审系统自身对 filename 的后处理逻辑。

## 检测与防御

- 检测：multipart filename 以 @ 开头或含 @ 的上传请求；cms/html 目录新增 jsp。
- 防御：禁止把目录结构编码进 filename；落盘文件名服务端生成并对后缀白名单；上传目录禁脚本解析。
