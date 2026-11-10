---
id: web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload
title: 用友时空 KSOA ImageUpload servlet 任意文件上传：filepath/filename 参数把 JSP 写进 Web 根
type: scenario
domain: web
path: web/java/component
technique: yonyou-ksoa-imageupload-arbitrary-file-upload
tags:
- yonyou
- ksoa
- file-upload
- webshell
- jsp
- unauthenticated
- servlet
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T07:57:05+08:00'
  notes: 已对照原文与6张图核对：原文给出 POST /servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=gmtxj.jsp 与 body <% out.println("hello"); %>，并说明用该上传先传马子再拖源码；卡片 filepath/filename 控制写入路径与文件名、JSP 落 Web 根可直接执行的描述与 POC 一致。未验证点：原文未给出 servlet 服务端代码、上传响应或 webshell 执行截图，机制细节属按 POC 参数推断，卡片已标注 confidence=medium；未实际发包复现；原文未写 KSOA 版本，未设置 affected_versions；frontmatter 无 sources/source_url。dedup 仅命中自身；dup-scan 与同文章 SQLi 卡 related 但机制不同，均保留。
url: /docs/web/java/component/web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload/
draft: false
kb_aliases:
- KSOA 文件上传
- com.sksoft.bill.ImageUpload
- 用友 KSOA webshell
- ImageUpload 任意上传
- filepath filename 上传
---

## 一句话结论

用友时空 KSOA 的 `com.sksoft.bill.ImageUpload` servlet 直接使用请求参数 `filepath` 与 `filename` 决定写入路径与文件名，攻击者 POST `filepath=/&filename=gmtxj.jsp` 并在 body 放 JSP 代码，即可把 webshell 写进 Web 根目录并访问执行；原文用该入口先拿到 webshell，再打包下载源码做审计。

## 原理

- 该 servlet 的用途是图片上传，但未限制扩展名/目录，也未校验目标路径是否位于允许的上传目录；`filepath` 可直接给 `/`（Web 根），`filename` 给 `gmtxj.jsp`。
- 写入内容来自请求 body（原文为 `<% out.println("hello"); %>`），服务端按给定文件名原样落盘；JSP 容器会把 `.jsp` 当脚本编译执行。
- 由于入口是公开 servlet（未授权），攻击者不需要登录即可写入；写入成功后访问 `/gmtxj.jsp` 即执行 JSP。
- 该上传也是后续源码审计的“拿源码”手段：拿下 webshell 后可打包/下载应用源码，寻找更多未授权 JSP 与 SQL 注入。
- 原文未给出服务端返回内容/执行截图，实际利用需目标存在该 servlet 且上传目录可写、未被 WAF 拦截。

## 触发条件

- 目标为用友时空 KSOA，存在 `com.sksoft.bill.ImageUpload` servlet 且可未授权访问。
- Web 根/目标目录对应用进程可写；`filepath` 参数未做目录白名单/规范化限制。
- 上传的 JSP 能被容器解析执行（扩展名/解析配置允许）。
- 请求 body 大小限制允许写入 webshell。

## 利用步骤

1. 确认 servlet 可达：访问/发包 `POST /servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=gmtxj.jsp`。
2. 在 body 中放最小 JSP：`<% out.println("hello"); %>`。
3. 访问 `/gmtxj.jsp`，若返回 `hello` 说明写入并解析成功。
4. 把 body 换成功能 webshell（命令执行/文件管理/打包下载源码），继续审计或横向。
5. 清理/隐藏时删除或改名 webshell；注意日志与文件时间戳。

## PoC

```http
POST /servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=gmtxj.jsp HTTP/1.1
Host: target
Content-Type: application/octet-stream
Content-Length: 30

<% out.println("hello"); %>
```

访问：

```http
GET /gmtxj.jsp HTTP/1.1
Host: target
```

## 变体与关联

- 变体：`filepath` 指向子目录/上级目录、`filename` 使用双扩展名/大小写/`;` 等绕过；body 用冰蝎/哥斯拉等加密 webshell。
- 变体：同类 servlet（图片上传/附件上传）常见 `filepath`+`filename` 任意写，可批量测试其它 KSOA 上传接口。
- 关联：[[web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint]] 是拿到源码后审计出的同产品 SQL 注入族。
- 关联：[[code-analysis-source-audit-jsp-legacy-oa-include-auth-filter]] 是源码到手后的未授权 JSP 审计方法。

## 检测与防御

- 检测：`/servlet/com.sksoft.bill.ImageUpload` 请求带 `filepath`/`filename` 且扩展名为 jsp/jspx；Web 根出现非业务 JSP；上传目录产生脚本文件；WAF 对 `filepath=/` 与 `.jsp` 文件名的告警。
- 防御：上传接口做鉴权、扩展名白名单（仅图片）、路径规范化与目录限制、重命名存储；上传目录禁止脚本执行（IIS/Apache/Tomcat 配置）；及时打厂商补丁；WAF 拦截恶意扩展名。
