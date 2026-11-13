---
id: web-generic-auth-zentao-programpriv-waterfall-modules-bypass
title: 禅道 16.0–17.4 programPriv waterfall 白名单越权：伪造会话即可无权限操作 project/bug/doc/repo 全部模块
type: scenario
domain: web
path: web/generic/auth
technique: zentao-programpriv-waterfall-authz-bypass
tags:
- php
- zentao
- authz-bypass
- access-control
- session
- repo
cve: []
severity: high
confidence: high
affected_versions: 16.0–17.4（原文：16.0 checkPriv 引入 waterfall 白名单；17.4 仅增加 tab 校验）
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:08:22+08:00'
  notes: 已对照原文全文与 img/01,02,07,08,15 核对：16.0 checkPriv 在 isset(app->user) 分支对 config->programPriv->waterfall 数组直接 return true，数组含 project/bug/doc/repo/meeting/stakeholder；17.4 改为 in_array(...) && app->tab=='project' && method!='browse' 才放行，卡片与版本说明一致（17.4 repo 路径被 tab 校验阻断的边界已写明）。PoC 按原文代码重建、未在真实目标执行。dedup：与 captcha 会话伪造卡、QVD deny 卡、repo 注入卡均非同链；dup-scan 无涉及 pair。27 张图全部读取。
url: /docs/web/generic/auth/web-generic-auth-zentao-programpriv-waterfall-modules-bypass/
draft: false
kb_aliases:
- 禅道 waterfall 越权
- zentao programPriv
- 禅道 checkPriv return true
- 禅道所有模块可操作
---

## 一句话结论

16.0 起禅道 `checkPriv()` 在 `isset($this->app->user)` 分支里对 `config->programPriv->waterfall` 中的模块直接 `return true`，而该数组包含 project/bug/doc/repo/meeting/stakeholder 等项目协作全部业务模块；任何拥有会话 user 的用户（包括 misc/captcha 伪造的会话）无需任何角色或对象权限即可读写这些模块，17.4 只加了 `tab=='project'` 与 `method!='browse'` 条件，分支仍然存在。

## 原理

- **代码路径**：`module/common/model.php checkPriv()` 中 `if(isset($this->app->user)) { if(in_array($module, $this->config->programPriv->waterfall)) return true; $this->app->user = $this->session->user; if(!commonModel::hasPriv($module, $method)) $this->deny($module, $method); }`。
- **数组内容**：`$config->programPriv->waterfall` 由 `array_merge($config->programPriv->scrum, array('workestimation','durationestimation','budget','programplan','review','reviewissue','weekly','cm',...))` 生成，而 scrum 数组里就包含 `projectstory/projectrelease/project/build/bug/testcase/testreport/caselib/doc/repo/meeting/stakeholder`——覆盖项目、需求、任务、bug、用例、文档、仓库等主要业务面。
- **为什么成立**：`return true` 发生在 `hasPriv()` 之前，等于把这些模块整体排除在权限系统之外；它只要求 `$this->app->user` 存在（真实登录或伪造会话均可），不校验角色、项目组成员、对象归属。
- **17.4 变化**：条件改为 `if(in_array($module, waterfall) && $this->app->tab == 'project' && $method != 'browse') return true;`，必须 cookie `tab=project`；对 repo 这类依赖其他 tab 的功能，强行设置 tab 会破坏正常操作流程，所以 17.4 起 repo RCE 不再直接走这条路（但 deny 异常绕过仍可用），其他模块在 tab=project 下仍可绕过。
- **边界**：不同版本 waterfall 数组内容有差异；`app->tab` 来自客户端可控 cookie；模块方法内部若有二次 `hasPriv`/对象校验，仍可能被拦。

## 触发条件

- 16.0–17.4 禅道；已获得任意会话 user（低权限真实账号或 misc/captcha 伪造会话）。
- 目标模块在 `programPriv->waterfall` 数组内。
- 17.4 需附加 `Cookie: tab=project`，且对 repo 等依赖 tab 的功能可能不可用。

## 利用步骤

1. 取得会话（伪造成本最低，见关联卡）。
2. 直接请求 waterfall 模块的业务动作：如 `index.php?m=project&f=create`、`m=bug&f=...`、`m=doc&f=...`、`m=repo&f=create/edit`，无需任何权限分配。
3. 17.4 额外带 `Cookie: tab=project`（`browse` 以外的方法）。
4. 在 repo 模块继续把仓库更新为 `SCM=Subversion` 触发命令注入（见关联卡）。

## PoC

```http
POST /zentao/index.php?m=project&f=create HTTP/1.1
Host: target
Cookie: zentaosid=<会话>; tab=project
Content-Type: application/x-www-form-urlencoded

<按版本表单提交项目字段>
```

```text
预期：未分配任何项目权限的会话/伪造会话直接得到创建表单或创建成功，
而不是 deny 跳转/“无权访问”页面（16.x 不需要 tab=project）。
（原文未给出独立于 RCE 链的请求样例，此验证思路按代码重建，未在真实目标执行。）
```

## 变体与关联

- 16.x–17.4 的 repo SVN client 命令注入依赖本越权进入 repo 模块：[[web-php-rce-zentao-repo-svn-client-command-injection]]。
- 17.4 起另一条鉴权绕过改用 `deny()` 抛异常不退出：[[web-generic-auth-zentao-endresponse-exception-deny-continue]]。
- 前置伪造会话：[[web-php-rce-zentao-captcha-session-repo-checkconnection-exec]]；`deny()` 写 session user 的路径：[[web-generic-auth-zentao-qvd-2024-15263-testcase-deny-session-user-bypass]]。
- 设计共性问题：waterfall 属“配置即白名单”，与 `openMethods` 中按方法名含 `ajax` 放行类似，都是把鉴权交给静态名单。

## 检测与防御

- 检测：同一会话短时间内访问多个属主无关的业务模块；cookie `tab` 被显式设置为 `project` 且伴随 repo/doc/bug 编辑请求；低权限账号创建/修改项目、bug、文档。
- 修复：waterfall 不应等于“免权限”，应在 `hasPriv` 内对模块-动作做细粒度判断，至少要求项目成员/角色；`tab` 不能作为鉴权输入。
- 加固：审计 `config->programPriv` 配置并最小化；对 repo/bug/doc 写操作增加对象级权限校验与二次确认。
