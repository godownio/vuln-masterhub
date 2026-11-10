---
id: web-generic-ssti-mcms-template-edit-freemarker-rce
title: MCMS 后台模板编辑结合静态化/自定义页面渲染触发 FreeMarker SSTI RCE
type: scenario
domain: web
path: web/generic/ssti
technique: freemarker-template-ssti-rce
aliases:
- MCMS FreeMarker SSTI
- MCMS 模板注入
tags:
- java
- freemarker
- ssti
- mcms
- rce
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T16:57:35+08:00'
  notes: 已对照原文核对：模板编辑插入Execute载荷经静态化生成主页与自定义页面mdiyPage渲染两条路径实测弹计算器，证据图齐全；MCMS 5.2.8为测试环境UI显示版本非原文标注受影响版本，已clear；freemarker 2.3.31为原文依赖列表明确写出
---

## 一句话结论

MCMS 后台「模板管理」允许编辑模板文件且模板内容在静态化生成主页（/generateIndex）与自定义页面（mdiyPage 渲染）时被 FreeMarker 无过滤解析，编辑 index.htm 插入 Execute 载荷后生成主页或访问自定义页面即可命令执行。

## 原理

ms-base/ms-mdiy jar 内的模板工具类（FiUiUtil.rendering、ParserUtil.rendering）直接 new Configuration(VERSION_2_3_0) 后 template.process 解析模板字符串，对模板内容没有任何黑名单/沙箱限制。MCMS 后台「模板管理」功能提供 index.htm 等模板文件的在线编辑，且 CmsParserUtil.generate(templatePath,...) 的模板路径来自 /generateIndex 接口的 url 参数；MCmsAction 的 index.do、search 等动态页面则用后台可编辑的 index.htm 作为模板渲染。因此「编辑模板内容」这一后台功能成为 SSTI 的 payload 注入点，静态化与页面访问成为触发点。

## 触发条件

- 拥有 MCMS 后台权限（能进入模板管理编辑模板、或能新建自定义页面绑定模板）；
- 站点启用静态化（内容管理-静态化-生成主页）或存在可访问的自定义页面路由。

## 利用步骤

1. 登录后台，进入 系统设置-模板管理，编辑 index.htm（或新建 shell.htm），插入载荷 `<#assign value="freemarker.template.utility.Execute"?new()>${value("cmd.exe /c calc")}`；
2. 路径 A（静态化）：进入 内容管理-静态化，主页模板选 index.htm，点击「生成主页」，后台调用 CmsParserUtil.generate 渲染模板触发命令执行（弹计算器）；
3. 路径 B（自定义页面）：自定义页面-新增，标题任意、分类文章、绑定模板选 index.htm、路径关键字如 ssti；保存后访问 /mdiyPage/ssti.do 触发渲染执行命令；
4. 也可上传含恶意载荷的 htm 模板文件（模板上传未拦截 htm）后走静态化触发，本质同上。

## PoC

```ftl
<#assign value="freemarker.template.utility.Execute"?new()>${value("cmd.exe /c calc")}
```

编辑入 index.htm 后通过静态化生成主页或访问绑定的自定义页面（/mdiyPage/ssti.do）触发，原文实测弹出计算器。

## 变体与关联

- 通用 FreeMarker `?new()` Execute / TemplatesImpl / ObjectConstructor 载荷均适用，因为模板引擎未做解析限制；
- MCMS 的文件上传（/ms/file/upload.do、/ms/file/uploadTemplate.do）黑名单仅拦 exe,.jsp,.jspx,.sh，可上传含载荷的 htm 模板再静态化，是该 SSTI 的替代 payload 投递方式；
- 与通用 FreeMarker SSTI 卡的区别在于入口是后台模板管理/自定义页面这一 CMS 功能组合。

## 检测与防御

- 检测：后台操作日志中模板保存后紧跟静态化请求；访问自定义页面时出现 freemarker.template.utility.Execute 等特征。
- 防御：模板编辑权限收敛并审计；渲染端使用 FreeMarker Configuration 设置 TemplateClassResolver.SAFER_RESOLVER 禁止 ?new() 实例化任意类；升级修复版本。
