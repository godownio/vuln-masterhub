---
id: web-generic-auth-zentao-endresponse-exception-deny-continue
title: 禅道 17.0–17.4 EndResponseException 被捕获后继续执行：deny 不退出导致鉴权失效、未授权模块照常运行
type: scenario
domain: web
path: web/generic/auth
technique: zentao-endresponse-exception-deny-continue
aliases:
- 禅道 17.x 鉴权绕过
- Zentao EndResponseException
- 禅道 helper::end 异常不退出
- 禅道 deny 绕过
- ZenTao auth bypass exception
tags:
- php
- zentao
- auth-bypass
- exception
- deny
- access-control
cve: []
severity: high
confidence: high
affected_versions: 17.0–17.4（原文：17.0–17.3 全模块鉴权失效；17.4 仍可经 deny 异常机制绕过）
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:08:24+08:00'
  notes: 已对照原文与 img/12,13,15,16 核对：framework/helper.class.php 的 end() 为 throw EndResponseException；17.0 common/model.php 2316-2325 的 catch 仅 echo getContent() 后继续；17.4 2382 处改 die，但 deny()(410) 仍 helper::end 抛异常并被吞掉，卡片描述与原文一致。PoC 为原文思路重建、未执行。dedup：与 QVD deny 卡机制相邻但不同链（该卡是 deny 写 session user 走 API 建管理员），非重复。
---

## 一句话结论

17.0 起禅道把 `helper::end()` 从 die 改为 `throw EndResponseException`，但 `checkPriv()` 外层 `catch` 只 `echo` 异常内容后继续执行；`deny()` 抛出的“终止”不再中断请求，未登录用户仍会进入 `loadModule()` 执行目标模块动作。17.4 在部分位置改回 die，但 `deny()` 路径仍抛异常并被吞掉，绕过依旧成立。

## 原理

- **end 语义变化**：`framework/helper.class.php` 的 `end($content='')` 实现为 `throw EndResponseException::create($content);`，取代了原来的 `die/exit`。
- **异常被吞**：`module/common/model.php` 的鉴权失败路径（`checkPriv()` → `deny()` → `helper::end()`）外层是 `try { ... } catch(EndResponseException $endResponseException) { echo $endResponseException->getContent(); }`。异常在本函数内被消费，`checkPriv()` 正常返回，入口 `index.php` 继续执行 `$app->loadModule()`，目标控制器/方法照常运行。
- **17.0–17.3**：鉴权不通过直接抛出异常，捕获后程序没有结束，等于整个鉴权失效；所有“只依赖 checkPriv 拦截、方法内部不再校验用户”的模块，未登录即可访问。
- **17.4**：部分位置改为直接 `die()`（原文提到 2382 行），但 `deny()`（410 行）仍用 `helper::end()` 抛异常，捕获后不退出；原文作者据此在 17.4 绕过鉴权后使用文件包含/命令注入。
- **为什么成立**：把“终止请求”实现为可捕获异常，而捕获方只输出不 rethrow，控制流回到框架主流程，安全语义丢失；这不是某个接口写错，而是全局错误处理机制的问题。
- **边界**：只有“模块方法自身不再校验用户/权限”的动作可利用；模块内若有二次 `hasPriv`/对象校验仍会被拦；不同小版本的 try/catch 位置需按代码核对。

## 触发条件

- 17.0–17.4 禅道；目标模块动作依赖框架 `checkPriv` 拦截且内部无二次权限校验。
- 请求路由能到达目标方法（模块/方法存在且未被路由层拦截）。

## 利用步骤

1. 直接以未登录会话请求目标模块方法（不一定需要伪造 session）。
2. 响应可能先输出 deny 的跳转 JS/内容，但随后模块动作仍执行（写操作、文件包含等）。
3. 配合 `api` debug 文件包含或 repo 编辑完成 RCE。

## PoC

```text
原文未给出独立请求样例。验证思路：
- 选择仅靠 checkPriv 保护、内部无 hasPriv 的方法；
- 不带 Cookie 直接请求，与正常未授权行为对比：应出现 deny 内容后动作仍生效
  （如数据被修改、文件被包含执行）。
（该思路按原文代码截图重建，未在真实目标执行。）
```

## 变体与关联

- 另一条同版本段鉴权绕过是 `programPriv->waterfall` 白名单（16.0–17.4）：[[web-generic-auth-zentao-programpriv-waterfall-modules-bypass]]。
- 前置会话伪造（15.0.1+，18.x 仍可用）：[[web-php-rce-zentao-captcha-session-repo-checkconnection-exec]]。
- 绕过后的两个 RCE sink：api debug 文件包含 [[web-php-file-inclusion-zentao-api-debug-getmethod-basename-bypass]]、repo SVN client 命令注入 [[web-php-rce-zentao-repo-svn-client-command-injection]]。
- 16.x 的 `deny()` 还会把 user 写入 session（QVD-2024-15263）：[[web-generic-auth-zentao-qvd-2024-15263-testcase-deny-session-user-bypass]]。

## 检测与防御

- 检测：17.x 出现未登录访问业务模块且响应同时包含 deny 页内容与业务结果；错误日志出现 `EndResponseException` 但同一请求继续执行；同一 IP 连续探测受保护方法。
- 修复：catch 后必须 rethrow/return/exit，恢复终止语义；`end()` 不应被业务代码捕获吞掉；鉴权失败应同时清空 `app->user` 并终止请求。
- 加固：模块内做二次权限校验；WAF 拦截未登录对业务模块的批量探测；升级到修复版本。
