---
id: web-generic-ssti-fastcms-template-edit-freemarker-rce
title: FastCMS 0.1.5 后台模板编辑 FreeMarker 注入：?new Execute 直接命令执行
type: scenario
domain: web
path: web/generic/ssti
technique: freemarker-editable-template-rce
tags:
- ssti
- freemarker
- java
- rce
- fastcms
- template-edit
- authenticated
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: FastCMS v0.1.5（FreeMarker 2.3.31）
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:51:16+08:00'
  notes: 已对照原文与图22-25核对：后台模板编辑写入 <#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}，RenderUtils new Template+template.process 未限制类解析器，FreeMarker 2.3.31，前台刷新弹出计算器，与图23/24/25一致。未验证点：原文未给 FastCMS 受影响版本区间（仅 v0.1.5 审计版本）；PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssti/web-generic-ssti-fastcms-template-edit-freemarker-rce/
draft: false
kb_aliases:
- FastCMS 模板注入
- FastCMS RCE
- freemarker.template.utility.Execute
- FreeMarker ?new Execute
- 后台模板编辑 RCE
- FastCMS FreeMarker SSTI
---

## 一句话结论

FastCMS 0.1.5 允许后台编辑模板，保存后的模板由 FreeMarker 直接 `template.process()` 解析且未限制 `?new()` 可实例化的类；拥有模板编辑权限的攻击者写入 `<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}`，即可在服务端执行任意命令。

## 原理

- **可控模板进入渲染器**：后台“模板 → 编辑”可修改 `index.html` 等模板文件；渲染时 `RenderUtils` 执行 `new Template(templateName, renderTemplate, getConfiguration())`，再 `template.process(data, stringWriter)`，模板内容被当作 FreeMarker 程序执行。
- **默认类解析器过宽**：`?new` 内建函数是否允许实例化任意类由 `TemplateClassResolver` 决定。应用未显式配置 `ALLOWS_NOTHING_RESOLVER` 时使用默认解析器，`?new()` 可以取出 `freemarker.template.utility.Execute`；该类是 FreeMarker 自带的 `TemplateMethodModel`，其 `exec()` 会对传入参数调用 `Runtime.exec()`。
- **为什么成立**：模板语言本身支持“实例化类并调用方法”，模板编辑权限等价于服务端代码执行权限；漏洞不是模板文件解析器的内存破坏，而是“把攻击者可控文本当模板执行”的设计缺陷。原文使用的 FreeMarker 版本为 2.3.31。
- **与历史 CVE 的关系**：原文在背景中列出 FreeMarker 相关 CVE（如 CVE-2023-26307 等），但本场景的实际利用条件是“后台可编辑模板 + 默认类解析器”，不依赖某个特定 CVE 的触发路径。

## 触发条件

- 目标为 FastCMS 0.1.5，使用 FreeMarker 2.3.31 且未配置 `ALLOWS_NOTHING_RESOLVER`/自定义安全类解析器。
- 攻击者拥有后台模板编辑权限（原文以 admin 登录演示）。
- 被修改的模板会被渲染（如首页 `index.html`），且模板缓存/重启策略允许新内容生效。

## 利用步骤

1. 登录后台，进入“模板 → 编辑”，选择会被访问的模板（原文为 `index.html`）。
2. 在模板开头插入 payload，保存。
3. 访问对应前台页面触发渲染。
4. 观察命令执行结果（原文以 `calc.exe` 弹计算器验证）；可替换为 `whoami`、反弹 shell 或写文件命令。
5. 清理模板修改痕迹时注意：模板内容本身可能被审计/备份记录。

## PoC

```ftl
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```

原文验证：保存后刷新前台页面，目标主机弹出计算器，确认命令在服务端执行。

## 变体与关联

- 变体：把命令替换为 `bash -c ...`、`cmd /c ...`、写入 WebShell 或建立反向连接；若目标配置了 `SAFER_RESOLVER`，`Execute` 会被拦截，可改用第三方 `TemplateMethodModel`、静态初始化块、`ProtectionDomain` 或 `?api` 等绕过方式。
- 关联：`[[web-generic-ssti-freemarker-safer-resolver-bypass]]`（配置了 SAFER_RESOLVER 后的多条绕过链）；`[[web-generic-ssti-freemarker-classpath-resource-read]]`（同环境下的配置读取）；`[[web-generic-ssti-engine-identification-decision-tree-errors]]`（模板引擎识别）。
- 注意：后台模板编辑在 CMS 中常被视为“管理员正常功能”，但从权限边界看，模板编辑者不应获得主机命令执行；多租户/外包运维场景下风险更高。

## 检测与防御

- 检测：模板文件出现 `?new`、`freemarker.template.utility.Execute`、`Runtime`、`getClassLoader` 等特征；后台模板保存操作与前台异常进程（如 `calc.exe`、`bash -c`）的关联；模板文件完整性监控。
- 修复：配置 `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER)`（不需要 `?new` 时）；升级 FreeMarker 到默认策略更安全的版本（原文提及 2.3.32 相关 CVE 背景，需按官方公告确认）；对模板编辑功能做权限隔离与二次确认。
- 缓解：模板编辑仅限可信管理员并开启审计；模板变更走审批/发布流程；应用进程低权限运行；WAF 对模板编辑请求中的 `?new`/`Execute` 关键字告警。
