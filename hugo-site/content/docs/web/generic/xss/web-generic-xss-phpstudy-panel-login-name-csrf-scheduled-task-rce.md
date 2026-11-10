---
id: web-generic-xss-phpstudy-panel-login-name-csrf-scheduled-task-rce
title: phpStudy Windows 面板登录名 XSS + 内置计划任务 CSRF：管理端 1-click 命令执行
type: scenario
domain: web
path: web/generic/xss
technique: phpstudy-panel-login-xss-csrf-scheduled-task-rce
tags:
- phpstudy
- xss
- csrf
- scheduled-task
- rce
- panel
- windows
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T17:06:52+08:00'
  notes: 已对照原文正文（phpStudy v8.1/8.1.1.3、首页未过滤回显登录用户名→存储型XSS、配合面板自带计划任务→1click RCE、www下生成1.txt、登录/取日志/执行计划任务代码截图位置）核对，card的注入点/持久性/CSRF到计划任务/边界（未给完整JS与接口）与原文一致；该段对应后半篇cdn外链图，tmp未提供，未能逐图核对。未验证点：PoC为步骤骨架未复跑（原文亦未给出完整JS/请求体）。无sources/文章ID/长段摘录，path web/generic/xss合法；dedup候选(phpstudy-linux-sqli-taskmng)平台/入口不同非同链；dup-scan早于建卡无pair。XSS+CSRF为一条1click链，无需拆分。
url: /docs/web/generic/xss/web-generic-xss-phpstudy-panel-login-name-csrf-scheduled-task-rce/
draft: false
kb_aliases:
- 小皮面板 XSS
- phpStudy 存储型 XSS
- phpStudy 计划任务 RCE
- 1click RCE
- 面板 XSS 配合 CSRF
---

## 一句话结论

phpStudy Windows 面板（文中 v8.1）会把登录尝试的用户名写入日志并在面板首页回显，且没有做 HTML 过滤，攻击者提交含 JS 的用户名即可形成存储型 XSS；管理员登录后访问首页时脚本在其浏览器执行，借管理员会话 CSRF 调用面板自带的计划任务功能创建一条执行命令的任务，把结果写入网站目录（如 `www/1.txt`），形成“管理员打开面板即被执行命令”的 1-click RCE。

## 原理

- **注入点**：面板登录页把每次登录的用户名记录到日志；首页/登录日志展示时直接输出用户名，未做 HTML 实体转义，用户名中的 `<script>`/事件属性会在管理员浏览器执行。
- **XSS 的持久性**：攻击者无需管理员在线即可先提交恶意用户名；日志保存后，管理员下次登录/访问首页即触发，属于存储型 XSS（也可视为日志注入）。
- **CSRF 到计划任务**：phpStudy 面板内置计划任务功能，可在面板内创建定时执行的命令/脚本。XSS 在面板同源上下文运行，能读取页面 token/直接调用面板接口，以管理员身份创建任务；任务执行后把命令输出写到网站根目录（文中在 `www` 下生成 `1.txt`）。
- **为什么能 RCE**：面板本身拥有管理 Apache/MySQL、执行脚本的高权限；计划任务功能设计用于运行命令，一旦被 CSRF/XSS 调用，等价于以面板服务账户权限执行任意命令。
- **前提**：攻击者能访问面板登录页并提交恶意用户名；管理员会登录并访问会回显日志的页面；面板计划任务功能可用。
- **边界**：文中未给出完整的 JS/接口请求体，复现需按目标面板版本抓取计划任务接口；不同版本页面结构与 CSRF 防护可能不同。

## 触发条件

- 目标为 phpStudy Windows 面板（文中 v8.1.1.3），面板可被攻击者访问。
- 登录日志/首页存在未过滤的用户名回显（存储型 XSS）。
- 管理员会登录面板并触发 XSS；面板计划任务功能未被禁用。
- 面板服务的账户有权限执行目标命令、写网站目录。

## 利用步骤

1. 访问面板登录页，提交用户名为 XSS payload（如 `<script>...</script>` 或事件属性），使登录日志记录该值。
2. 构造 JS：在管理员浏览器中调用面板计划任务创建接口，任务命令为写入文件/反弹 Shell；必要时先读取页面中的 CSRF token。
3. 等待管理员登录并访问首页/日志页，XSS 执行并发起同源请求。
4. 检查网站目录（如 `www/1.txt`）或外带通道确认命令执行。
5. 若计划任务接口有 CSRF 防护，改为读取 token 后再提交；若 XSS 被过滤，尝试编码/事件属性绕过。

## PoC

```text
步骤骨架（原文未给出完整 JS/接口，需按目标版本抓包补全）：
1) 登录页用户名填入：<script>fetch('/计划任务接口', {method:'POST', credentials:'include', body:'...命令...'})</script>
2) 管理员登录并打开首页 -> 浏览器执行脚本
3) 目标网站目录出现 1.txt，内容为命令输出
```

```text
验证：面板首页源码中登录日志处出现未转义的用户名；www 目录新增攻击者预期文件。
```

## 变体与关联

- 若登录日志不回显，可尝试其它把用户名/输入回显到管理端的页面（用户管理、操作日志）。
- 计划任务接口若要求特定 token，可用 XSS 先请求表单页解析 token 再提交；同源 XSS 不受 CORS 限制。
- 关联：[[web-generic-xss-admin-blind-stored-registration]]（管理端盲打存储型 XSS）、[[web-generic-csrf-zrlog-admin-json-api-text-plain-all-endpoints]]（JSON API CSRF）、[[web-generic-sqli-phpstudy-linux-panel-socket-login-taskmng-webshell]]（phpStudy Linux 面板的计划任务写 Webshell，另一版本/另一入口）。

## 检测与防御

- **修复**：登录日志/首页对用户名做 HTML 转义；计划任务接口加 CSRF token 与来源校验；面板仅内网访问并加独立认证。
- **检测**：登录用户名中出现 `<script`、`onerror=`、`fetch(` 等特征；面板日志出现异常 JS；计划任务被创建后立即执行写文件/外联。
- **加固**：面板不要暴露公网；管理员不要在同一浏览器访问不可信页面；限制面板服务账户权限；升级面板版本。
