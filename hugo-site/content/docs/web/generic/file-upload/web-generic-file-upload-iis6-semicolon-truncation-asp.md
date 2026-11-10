---
id: web-generic-file-upload-iis6-semicolon-truncation-asp
title: IIS6 分号截断解析：test.asa;1.gif 以图片后缀上传后按 ASP 执行
type: scenario
domain: web
path: web/generic/file-upload
technique: iis6-semicolon-truncation-asp-parsing
tags:
- web
- file-upload
- iis6
- semicolon
- truncation
- asp
- webshell
- windows
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-10'
updated: '2026-11-10'
url: /docs/web/generic/file-upload/web-generic-file-upload-iis6-semicolon-truncation-asp/
draft: false
kb_aliases:
- IIS6 分号截断
- test.asa;1.gif
- test.asp;.jpg
- 分号解析漏洞
- 分号后内容被忽略
---

## 一句话结论

在 IIS6 上，上传名为 `test.asa;1.gif` 的文件（内容为 ASP 代码，上传校验只看到 `.gif`），访问时使用带分号的全名 `/upload/test.asa;1.gif`，IIS 会忽略分号及其后内容、按分号前的 `.asa` 交给 ASP 处理程序解析，从而绕过上传后缀限制执行脚本。共享背景：上传点只按最后扩展名/Content-Type 放行图片，文件落在 Web 可访问目录，攻击者再按下面的解析形态访问同一文件，形成“存的是图片、跑的是脚本”的二次解析。

## 原理

- 上传校验与请求解析判断的对象不同：上传代码取文件名最后一个 `.` 之后的后缀（这里是 `.gif`），而 IIS6 在处理请求 URL 时按自己的规则决定把请求交给哪个 ISAPI 处理程序。
- IIS6（Windows Server 2003 时代的默认行为）把 URL 路径中分号 `;` 及其后的内容当作路径参数处理：在确定文件扩展名与脚本映射时只看分号前的部分，因此 `test.asa;1.gif` 被判定为 `.asa` 文件。
- `.asa` 在 IIS 中默认映射到 ASP 处理程序（asp.dll），IIS 便把该文件内容交给 ASP 解析执行；而磁盘上的物理文件确实是名为 `test.asa;1.gif` 的普通文件，上传阶段看到 `.gif` 就放行了。
- 关键点是“访问时要带分号全名”：只有带分号的 URL 才会触发截断后的 `.asa` 映射；不带分号无法定位到该物理文件。
- 为何成立：分号在文件名中是合法字符，上传落盘时未被重命名或过滤；上传目录又允许脚本执行，两个条件同时满足即可执行任意 ASP 代码。

## 触发条件

- 目标为 IIS6 环境（典型为 Windows Server 2003 的默认解析行为）。
- 上传点只按最后扩展名或 Content-Type 校验，允许 `.gif`/`.jpg` 等后缀，且不剥离/拒绝文件名中的分号。
- 上传文件保存在 Web 可访问目录，且该目录未禁止脚本执行。
- 攻击者能获得上传后的访问路径，并能按原文件名（含分号）访问。

## 利用步骤

1. 找到只校验后缀/Content-Type 的上传点，准备内容为 ASP 代码的图片文件（如 `<% Response.Write("parsed") %>`），文件名设为 `test.asa;1.gif`。
2. 若上传组件会改写文件名，先确认分号是否被保留；必要时尝试 `test.asp;.jpg`、`test.asp;1.jpg` 等等价分号形态。
3. 上传成功后，按带分号的全名访问：`http://target/upload/test.asa;1.gif`。
4. 观察响应是否由 ASP 处理（输出标记内容）；成功后按授权范围停止并固定证据。

## PoC

```text
上传文件名：test.asa;1.gif
文件内容：<% Response.Write("parsed") %>
访问：http://target/upload/test.asa;1.gif
成功标志：页面输出 parsed（说明按 .asa/ASP 解析执行）
```

说明：按文章给出的 `test.asa;1.gif` 形态整理；未在真实目标复现，仅在授权环境使用。

## 变体与关联

- 变体：可执行段换成 `.asp`/`.cer` 等 IIS 已映射的脚本后缀，如 `test.asp;.jpg`、`test.asp;1.jpg`。
- 关联：[[web-generic-file-upload-iis6-directory-asp-name-parsing]]（同属 IIS6 解析差异，走目录名而非文件名分号）；[[web-generic-file-upload-php-cgi-pathinfo-jpg-php-parsing]]（PHP 侧的 pathinfo 二次解析）；[[web-generic-file-upload-weak-suffix-bypass]]、[[web-generic-file-upload-blacklist-double-write-bypass]]（先过上传校验的其他手法，可与本卡组合）。
- 边界：IIS7+ 默认不再按分号截断扩展名；文件名被服务端重命名（去掉分号）或上传目录禁止脚本执行时本手法失效。

## 检测与防御

- 检测：上传文件名或 Web 访问日志中出现含分号的脚本文件名（`*.asa;*`、`*.asp;*`）；上传目录出现分号命名文件后紧接脚本执行请求；响应异常出现 ASP 执行输出。
- 防御：升级/淘汰 IIS6；上传文件强制重命名为随机名+固定安全后缀，剥离 `;` 等特殊字符；上传目录移除脚本处理程序映射（禁止执行）；WAF 拦截含分号的可执行扩展名请求。
