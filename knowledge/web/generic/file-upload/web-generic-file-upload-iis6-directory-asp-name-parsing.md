---
id: web-generic-file-upload-iis6-directory-asp-name-parsing
title: IIS6 目录名以 .asp 结尾：123.asp/12.jpg 目录内任意文件按 ASP 解析
type: scenario
domain: web
path: web/generic/file-upload
technique: iis6-directory-asp-name-parsing
aliases:
- 目录名 .asp
- 123.asp/12.jpg
- IIS6 目录解析
- 目录解析漏洞
- .asp 目录内文件执行
tags:
- web
- file-upload
- iis6
- directory-parsing
- asp
- webshell
- windows
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-10'
updated: '2026-11-10'
---

## 一句话结论

在 IIS6 上，只要 URL 路径中某个目录名以 `.asp` 结尾（如 `123.asp`），该目录内的任意文件（如 `123.asp/12.jpg`）都会被当作 ASP 脚本解析执行，攻击者把 ASP 代码写进图片、放进该目录即可获得 WebShell。共享背景：上传点只按扩展名/Content-Type 放行图片并落到 Web 可访问目录；本卡只讨论“目录名决定解析器”这一种二次解析形态。

## 原理

- IIS6 在选择处理程序时检查的是请求 URL 的路径，而不只是最后一个文件扩展名：只要路径中某个目录段以脚本扩展名（`.asp`）结尾，整个请求就被交给 ASP 处理程序（asp.dll）。
- 因此 `/upload/123.asp/12.jpg` 虽然最终文件是 `.jpg`，IIS6 仍按 ASP 解析该文件内容；文件自身的扩展名在这里不参与处理程序选择。
- 攻击者只需两步：得到一个以 `.asp` 结尾的目录（通过可控上传路径、目录创建、压缩包解压或路径穿越等），把含 ASP 代码的文件（图片后缀即可）放进去，再按 `目录名.asp/文件名.jpg` 访问。
- 上传校验看到的仍是 `.jpg`，放行；解析由目录名触发，二者判断不一致即为绕过点。
- 为何成立：IIS6 的路径解析把目录段当作脚本映射的一部分；IIS7+ 的集成管道按最终文件后缀映射处理程序，默认不再复现该行为。

## 触发条件

- 目标为 IIS6 环境。
- 攻击者可创建或控制一个以 `.asp` 结尾的目录（例如上传路径/子目录参数可控、可上传 zip 解压出目录、或存在目录创建功能）。
- 上传点允许把含 ASP 代码的文件以 `.jpg` 等非脚本后缀存入该目录，或能把任意文件放到该目录。
- 上传目录位于 Web 根下、可访问且未禁止脚本执行。
- 攻击者能构造 `http://target/<路径>/<目录>.asp/<文件>.jpg` 形式的访问 URL。

## 利用步骤

1. 寻找可控制上传子目录、目录创建或压缩解压的入口，创建名为 `123.asp` 的目录。
2. 把内容为 ASP 代码的文件（如 `12.jpg`，内容 `<% Response.Write("parsed") %>`）上传/解压到该目录。
3. 访问 `http://target/upload/123.asp/12.jpg`，观察是否按 ASP 执行（返回 parsed）。
4. 成功后按授权范围停止并固定证据。

## PoC

```text
目录：/upload/123.asp/
文件：12.jpg（内容：<% Response.Write("parsed") %>）
访问：http://target/upload/123.asp/12.jpg
成功标志：页面输出 parsed（目录内 .jpg 被当 ASP 解析）
```

说明：按文章给出的 `123.asp/12.jpg` 形态整理；未在真实目标复现，仅在授权环境使用。

## 变体与关联

- 变体：目录名换成 `.asa`、`.cer` 等 IIS 已映射的脚本后缀；也可与文件名分号形态组合。
- 关联：[[web-generic-file-upload-iis6-semicolon-truncation-asp]]（同属 IIS6 解析差异，走文件名分号而非目录名）；[[web-generic-file-upload-php-cgi-pathinfo-jpg-php-parsing]]（PHP 侧的 pathinfo 二次解析）；[[web-generic-file-upload-weak-suffix-bypass]]（先过上传校验的其他手法）。
- 边界：IIS7+ 默认不复现；无法控制目录名、上传目录禁止脚本执行、或文件不在 Web 可访问路径时失效。

## 检测与防御

- 检测：请求 URL 中出现以脚本扩展名结尾的目录段（如 `/xxx.asp/`、`/xxx.asa/`）且访问的是图片/文本文件；上传接口出现 `dir`/`path` 类参数被写入 `.asp` 目录；新建目录名含脚本后缀。
- 防御：升级/淘汰 IIS6；上传目录禁止脚本执行（移除处理程序映射）；上传子目录名由服务端生成并过滤脚本后缀/特殊字符；解压后校验条目路径，拒绝创建脚本后缀目录；WAF 拦截路径中含 `.asp/`、`.asa/` 的请求。
