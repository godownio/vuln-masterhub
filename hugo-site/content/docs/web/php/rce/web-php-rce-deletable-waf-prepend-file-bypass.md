---
id: web-php-rce-deletable-waf-prepend-file-bypass
title: 过滤逻辑写在同目录可写的 PHP 文件里：先命令执行读出 no.php 确认它是 WAF，再 rm 掉它使限制失效，随后通配符 cat 根目录取 flag
type: scenario
domain: web
path: web/php/rce
technique: deletable-waf-prepend-file-removal-bypass
tags:
- php
- waf-bypass
- file-deletion
- auto-prepend
- command-injection
- glob
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:37:22+08:00'
  notes: x
url: /docs/web/php/rce/web-php-rce-deletable-waf-prepend-file-bypass/
draft: false
kb_aliases:
- 删掉 WAF 文件绕过过滤
- no.php 是 WAF
- 过滤器随文件删除失效
- rm no.php
- 可删除的前置过滤脚本
- 通配符读根目录 flag
---

## 一句话结论

当目标把「命令执行过滤 / `open_basedir` 类限制」实现在**站点目录下一个普通的 PHP 文件**（常通过 `auto_prepend_file`、`.user.ini` 或 `include` 在每个请求前加载）里，而攻击者已经拿到**能执行命令的同一权限**时，限制本身就成了可删除的对象：先用 `cat no.php` 读出过滤逻辑确认它在拦什么，再 `rm no.php` 让后续请求不再加载它，之前被拦的 `ls /`、`cat /f*` 立即放行，用通配符（`/f*`）绕开文件名不确定即可读出 flag。

## 原理

- **过滤器是「数据」不是「机制」**：真正的隔离应由内核/容器（`open_basedir` 在 php.ini、seccomp、chroot、只读挂载）保证；一旦改用「每次请求先 include 一个检查脚本」来实现，检查脚本和被检查的业务代码处于**同一权限域**。攻击者既然能执行命令，就必然能 `rm` 掉这个脚本——过滤器的存在性于是变成攻击者可以选择的开关。
- **为什么删掉后立即生效**：`auto_prepend_file`/`.user.ini` 是**每次请求重新解析并加载**的，文件不存在时通常只产生一条 warning（或按配置静默跳过），业务代码照常执行，过滤逻辑却整段消失。不需要重启 PHP-FPM，也不需要写文件。
- **为什么先要 `cat` 而不是直接删**：确认三件事——① 这个文件确实是过滤器（而不是业务逻辑，误删会导致 500）；② 它拦了哪些模式（决定删掉后能用哪些命令）；③ 它的作用域（是 `auto_prepend_file` 还是被 `index.php` 手动 `include`，后者删掉后可能连入口都挂）。读到源码后才知道删得对不对。
- **为什么最后一步是 `sudo cat /f*`**：过滤器往往只拦「读根目录 / 读 flag」这类模式，删掉后 `ls /` 与 `cat /flag` 都放行；用 `/f*` 通配是为了不依赖 flag 的确切文件名（`/flag`、`/flag.txt`、`/f1ag` 都能匹配），而 `sudo` 则用于目标进程非 root、flag 仅 root 可读的场景。
- **失败信号**：删除后请求返回 500 或空白，说明该文件被入口 `include` 而非 `auto_prepend_file`（删掉后 `include` 报 fatal）；此时应改为**改名/清空**（`echo '' > no.php`）或在能写的前提下覆盖为无操作内容，效果等价而不破坏包含链。

## 触发条件

- 已获得 Web 权限的命令执行（PHP webshell、命令注入、或任意文件写），且该权限对站点目录**可写**（`www-data` 拥有目录或文件）。
- 过滤/限制由站点目录内的 PHP 文件实现（`auto_prepend_file`、`.user.ini`、或被入口 `include` 的 `waf.php`/`no.php`/`check.php` 一类）。
- 已知或可枚举该文件名（`ls`、`cat` 常见名、或从 `phpinfo`/`.user.ini` 内容得知）。
- 目标文件系统对 flag 有通配符可匹配（`/f*`），否则需先 `ls /` 列出。

## 利用步骤

1. 确认命令执行可用但受限：`id`、`whoami` 正常，`ls /`、`cat /flag` 被拒（回显空、被替换成提示语、或直接 403/500）。
2. 定位过滤器：`ls -la` 看站点目录下可疑文件，`cat no.php`（或 `waf.php`/`check.php`）读出过滤实现，确认它是「请求前置加载」的检查脚本。
3. 确认可写：`ls -l no.php` 属主为 Web 用户，或 `touch t` 成功。
4. 删除：`rm no.php`（若担心破坏入口则 `mv no.php no.php.bak` 或 `echo '' > no.php`）。
5. 立即重发先前被拒的命令：`ls /` 应正常回显。
6. 读 flag：`sudo cat /f*`，或 `cat /f*`（进程为 root 时）／`od /f*`（`cat` 被别名或过滤时）。
7. 若仍被拦，说明还有第二层（`disable_functions`、`open_basedir` 在 php.ini）——那属于真正的机制层，删文件无效，需换其它思路。

## PoC

```text
# 1) 命令执行可用但读根目录被拦
?cmd=id                      -> uid=33(www-data)
?cmd=ls /                    -> （空 / 被替换为提示）

# 2) 找到并阅读过滤器
?cmd=ls -la
?cmd=cat no.php              -> 看到 preg_match / strpos 黑名单 与 exit

# 3) 删掉它（同权限域，直接可写）
?cmd=rm no.php

# 4) 过滤失效后取 flag
?cmd=ls /
?cmd=sudo cat /f*
```

对应的「删除即解除」示意（`auto_prepend_file` 场景）：

```ini
; .user.ini
auto_prepend_file = /var/www/html/no.php
```

```text
请求 -> PHP 启动 -> 加载 no.php（黑名单检查，命中则 exit）
     -> 删除 no.php 后：
请求 -> PHP 启动 -> auto_prepend_file 指向的文件不存在（仅 warning）
     -> 业务代码照常执行，黑名单不存在
```

## 变体与关联

- **变体（不能删只能写）**：`echo '<?php ?>' > no.php` 覆盖为空的过滤器；或写入提前 `return` 的代码。
- **变体（过滤器是扩展/OPcache 预热）**：此时删文件无效（扩展在进程内），需从 `php.ini` 或 SAPI 层绕过。
- **变体（过滤器在上级目录且不可写）**：退回到「绕过过滤」而非「移除过滤」，见关联卡里反斜杠/通配符/`$IFS` 一类拆分技巧。
- **关联**：[[web-php-rce-two-gate-str-replace-double-write-regex-backslash-system]]（同一组题里的另一条路——不删文件而是绕过黑名单）、[[web-php-rce-shell-exec-quote-concat-glob-flag]]（`/f*` 通配符读 flag 的用法）、[[web-php-file-inclusion-htaccess-self-include-dirty-bypass]]（同为「同目录 PHP 文件参与请求处理」的利用面）、[[web-php-file-inclusion-user-ini-auto-prepend-rce]]（`auto_prepend_file` 的正向利用，本卡是其反向——让前置文件消失）。
- **边界**：站点目录只读、`rm` 被 `disable_functions` 禁、或过滤器由 php.ini/扩展实现时，本技巧不成立；删除业务相关文件可能触发 500，需先用备份/改名方式验证。

## 检测与防御

- **架构层**：不要用「同目录 PHP 脚本」当安全边界——它和被保护代码同权限；限制应下沉到 `php.ini` 的 `open_basedir`、`disable_functions`、容器只读挂载、或 Web 服务器层（`mod_security`、反代规则）。
- **部署层**：`auto_prepend_file` 指向的路径放在站点根目录之外且对 Web 用户只读；站点目录默认不可写（上传目录单独隔离且 `noexec`）。
- **检测**：Web 目录内出现 `rm`/`mv`/`unlink` 针对 `.php` 文件的命令执行；`.user.ini` 或 `auto_prepend_file` 指向的文件突然消失；同一会话内先 `cat no.php` 再 `rm no.php` 再 `ls /` 的连续请求序列（强特征）。
- **响应**：从备份或镜像恢复被删文件、审计该时间段所有命令执行、检查是否落地 Webshell 与横向痕迹。
