---
id: web-php-rce-php7-backtrace-uaf-disable-functions-bypass
title: PHP 7.0-7.4.3 debug_backtrace UAF 绕过 disable_functions（蚁剑插件）
type: scenario
domain: web
path: web/php/rce
technique: php7-backtrace-uaf-disable-functions-bypass
tags:
- php
- php7
- disable-functions
- uaf
- backtrace
- antsword
- webshell
- bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: PHP 7.0/7.1/7.2 全版本；7.3 < 7.3.15；7.4 < 7.4.3（蚁剑插件适配区间，原文目标 PHP 7.2.33）
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T11:52:51+08:00'
  notes: '已对照原文核对：原文目标 PHP 7.2.33（phpinfo 截图）、disable_functions 列表、蚁剑插件 PHP7 Backtrace UAF 模式及版本区间（7.0/7.1/7.2 全版本、7.3<7.3.15、7.4<7.4.3）均与截图一致；whoami 成功取得 www 命令执行。未验证点：未本地复现 UAF 利用。元数据小瑕疵：aliases 中未加引号的 ''Bug #76047'' 被 YAML 当注释截断为 ''Bug''。'
url: /docs/web/php/rce/web-php-rce-php7-backtrace-uaf-disable-functions-bypass/
draft: false
kb_aliases:
- PHP7 Backtrace UAF
- 蚁剑绕过 disable_functions
- disable_functions-8.137.123.30
- Bug
- PHP 7 disable_functions bypass
---

## 一句话结论

拿到 PHP WebShell 但 `disable_functions` 禁用了 `system`/`exec`/`passthru` 等命令函数时，若目标为 PHP 7.0-7.4.3，可用蚁剑“绕过 disable_functions”插件的 PHP7 Backtrace UAF 模式（Bug #76047）触发内存破坏、取得命令执行原语，从而在禁用函数限制下继续执行系统命令。

## 原理

- `disable_functions` 在 PHP 用户态函数表层面禁用函数，被禁函数不会以可调用形式注册，用户代码调用时返回 disabled；但它不阻止引擎内部的内存破坏利用。
- PHP 7.0-7.4.3 的 `debug_backtrace` 在访问已析构的 backtrace 参数时存在 use-after-free（Bug #76047），攻击者可借此破坏/复用内存中的 zval 或函数结构，构造出可调用的内部函数指针，绕过用户态函数表检查。
- 蚁剑（AntSword）的“绕过 disable_functions”插件把该利用封装为可视化模式：PHP7 Backtrace UAF 针对 PHP 7.0-7.4.3，PHP8 UAF 针对更高版本；插件在 WebShell 内执行利用代码并返回命令结果。
- 利用成功后命令以 Web 服务用户（如 `www-data`）权限执行，不是系统 root；仍受 `open_basedir`、SELinux/AppArmor、seccomp 等限制。

## 触发条件

- 已获得可执行 PHP 代码的 WebShell（上传/文件包含/其他 RCE）。
- 目标 PHP 版本在 7.0-7.4.3 区间，且 `disable_functions` 禁用了命令执行函数。
- 目标未额外启用 seccomp/AppArmor 等阻断内存破坏利用的机制；`open_basedir` 未阻止读取必要路径。
- 攻击者可使用蚁剑或等价 exploit 工具连接 WebShell。

## 利用步骤

1. 上传/连接 WebShell 后执行 `phpinfo()` 或读取 `disable_functions`，确认 `system`、`exec`、`passthru`、`shell_exec`、`popen`、`proc_open` 等被禁用，并记录 PHP 版本。
2. 在蚁剑中右键目标 → 加载插件 → 辅助工具 → 绕过 disable_functions。
3. 选择 PHP7 Backtrace UAF 模式（PHP 7.0-7.4.3）；插件会向 WebShell 发送利用载荷并在服务端执行。
4. 在插件终端执行 `whoami`、`ls` 验证命令执行；成功后按需执行后续命令。
5. 若 PHP7 模式失败，按版本尝试 PHP8 UAF、LD_PRELOAD、`.htaccess` CGI 等等价绕过方式。

## PoC

```text
# 蚁剑操作路径
右键 WebShell → 加载插件 → 辅助工具 → 绕过 disable_functions
选择模式：PHP7 Backtrace UAF（适配 PHP 7.0 - 7.4.3）
执行：whoami / ls / id
```

```php
// 仅用于确认禁用项，不包含 exploit
<?php phpinfo(); ?>
```

## 变体与关联

- **PHP 8 UAF**：PHP 8.4/8.5 使用 zif_system 内存破坏链，见 [[web-php-rce-uaf-memory-corruption-disable-functions-bypass]]。
- **LD_PRELOAD**：通过 `putenv` + 恶意 .so 劫持子进程函数，见 [[web-php-rce-disable-functions-ld-preload]]。
- **.htaccess/CGI**：上传 `.htaccess` 让脚本由 CGI 执行，绕过 PHP 层禁用，见 [[web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions]]。
- **其他**：`ffi`、`imap_open`、`mail`、`putenv`、`pcntl` 等历史绕过；取决于扩展与版本。
- **前置**：上传入口可用 [[web-generic-file-upload-magic-byte-gif-prefix-bypass]] 的 GIF89a 前缀手法 getshell。

## 检测与防御

- 升级 PHP 到 7.3.15/7.4.3 及以上或 PHP 8，修复 backtrace UAF；及时打安全补丁。
- `disable_functions` 只是纵深防御的一层，不能替代上传目录禁止脚本解析、`open_basedir`、最小权限、seccomp/AppArmor。
- 上传目录放在 Web 根之外或禁止 PHP 解析；文件类型白名单 + 完整图片解码校验 + 随机重命名。
- 检测：WebShell 流量中出现蚁剑特征、`disable_functions` 绕过插件请求；PHP 进程异常内存操作/崩溃；上传目录出现脚本文件；`whoami`/`ls` 等命令执行特征。
