---
id: web-generic-sqli-zzcms-adv2-update-bitwise-or-time-blind
title: zzcms adv2.php 前台整型注入：UPDATE 目标行不存在时用位或强制求值的时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: zzcms-adv2-update-bitwise-or-forced-evaluation-sqli
tags:
- sqli
- mysql
- time-blind
- php
- zzcms
- cms
- update
- bitwise-or
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V556
  verified_at: '2026-11-12T00:25:40+08:00'
  notes: 已对照原文全文与22张图（含15.gif 抽取5帧）核对：inc/global.php 对 COOKIE/POST/GET 走 addfxg=addslashes(htmlspecialchars)（图02-04）、user/adv2.php 需公司类型用户（图06-07）与发布展会/设广告前置（图08-11）、action=modify 进入 setAdv（图12-13）、setAdv 中 select/update 均裸拼 $_POST['id']（图14）；图22 mysql 对照 and 0.00s 被短路、位或 | 1.00s 强制求值，与卡内原理/PoC 注释一致；gif 帧为 POST /user/adv2.php?action=modify 带 id=1 | (select ... sleep(1)) 请求，响应约2.0s（2,018ms）与原文 post 数据逐字一致。原稿「原文在 MySQL 5.x/默认环境实测」为原文未明示的版本断言，已改为「原文在本地 MySQL 环境实测」。原文未给 zzcms 明确受影响版本区间（仅 zzcms2023 源码包），未设 affected_versions 正确。dedup 候选 SeaCMS/PHPGurukul 等均不同产品，库内无同款「UPDATE 短路 vs 位或强制求值」卡；dup-scan 无 pair。PoC 未在本机执行（sleep 属只读探测）。
url: /docs/web/generic/sqli/web-generic-sqli-zzcms-adv2-update-bitwise-or-time-blind/
draft: false
kb_aliases:
- zzcms 前台 SQL 注入
- adv2.php setAdv 注入
- UPDATE 位或注入
- 招商网管理系统 SQL 注入
---

## 一句话结论

zzcms（招商网管理系统）在 `inc/global.php` 里用 `addslashes+htmlspecialchars` 过滤了 GET/POST/COOKIE，字符串型注入基本不可用，但 `user/adv2.php` 的 `setAdv()` 把 `$_POST['id']` 原样拼进 `select ... where id=` 与 `update ... where id=`；当 UPDATE 的目标行不存在时，`where id=1 and (子查询)` 会被 MySQL 短路而跳过子查询，改用位或 `where id=1 | (子查询)` 可强制求值，从而以注册公司用户身份做时间盲注，最终拿到管理员口令。

## 原理

- 过滤面：`inc/global.php` 对 `$_COOKIE`、`$_POST`、`$_GET` 调用 `addfxg()`，其实现为 `addslashes(htmlspecialchars(...))`（无 magic_quotes 时）或仅 `htmlspecialchars`。单/双引号、反斜杠均被转义或实体化，常规字符串闭合注入被堵死；因此审计重点应放在**不需要引号的整型注入**。
- 入口与前置：`user/adv2.php` 引入 `user/check.php` 校验登录，`$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : ''`；当 `$action == 'modify'` 时按用户权限调用 `setAdv(1)` 或 `setAdv(0)`。`setAdv()` 内部先依次查 `zzcms_zhaoshang`、`zzcms_zhanhui`、`zzcms_textadv`，再进入 `zzcms_ad` 分支；因此攻击者必须先满足：注册类型为「公司」的用户（个人用户被 `$row['usersf']=='个人'` 直接 `exit`）、发布过展会信息（`$c=1`）、设置过自助广告语（`!$row` 为真）。这些都能用前台注册/用户中心自助完成。
- 脆弱点：`setAdv()` 中的
  - `$rs=query("select * from zzcms_ad where id=".$_POST["id"]);` 与
  - `query("update zzcms_ad set nextuser='".$_COOKIE["UserName"]."' where id=".$_POST["id"]);`
  两处都是裸拼接；`id` 为 POST 整型参数，过滤器对其无用。
- 为什么要用位或：MySQL 对 `WHERE id=1 AND (SELECT ...)` 在 `id=1` 无匹配行时会短路，子查询根本不执行（原文实测 `update ... where id=1 and (select ... sleep(1))` 耗时 0.00s）；而 `id=1 | (SELECT ...)` 的位或运算必须求出两侧操作数，子查询被迫执行（同一语句耗时 1.00s）。这是「UPDATE/DELETE/SELECT 目标行不存在时仍能注入」的关键技巧，同样适用于 `&、^、~、+、-、*、/、%` 等不会短路的运算。
- 注入形态：`id=1 | (select * from (select if(ascii(substr(database(),1,1))=0x7a,sleep(1),1))A)`；盲注通过响应耗时判断条件真假，逐字符可拖库（管理员表口令哈希/明文取决于版本）。
- 危害闭环：从前台注册用户 → 时间盲注取管理员凭据 → 登录后台 → 后台功能（如内置备份工具）继续拿 WebShell。

## 触发条件

- 目标为 zzcms 招商网管理系统（原文审计最新源码包 zzcms2023；原文未标注具体版本区间）。
- 前台开放用户注册且允许注册「公司」类型用户。
- 攻击者能完成发布展会、设置自助广告等前置动作（均为普通用户自助功能）。
- MySQL 优化器行为符合上述短路特性（原文在本地 MySQL 环境实测；不同版本对 AND 短路/位或求值的处理可能不同）。

## 利用步骤

1. 在 `/reg/userreg.php` 注册公司类型用户并登录。
2. 用户中心发布一条展会信息（写入 `zzcms_zhanhui`），并设置自助广告语（写入 `zzcms_textadv`），使 `setAdv()` 前面的分支条件全部通过。
3. 构造 `POST /user/adv2.php?action=modify`，`id` 参数使用 `1 | (子查询)` 形式，先用 `sleep(1)` 验证注入：
   ```
   id=1 | (select * from (select if(ascii(substr(database(),1,1))=0x7a,sleep(1),1))A)
   ```
4. 用时间盲注逐字符提取管理员表（用户名/口令哈希或明文），或先确认当前库名。
5. 用取得的管理员凭据登录后台，继续利用后台功能（例如同产品内置的 EmpireBak 备份组件）写入 WebShell。

## PoC

```http
POST /user/adv2.php?action=modify HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: UserName=<公司用户>; PassWord=<口令>

id=1 | (select * from (select if(ascii(substr(database(),1,1))=0x7a,sleep(1),1))A)
```

```text
# 条件为真（库名首字母为 'z'）时响应延迟约 1 秒；为假时立即返回。
# 对照实验（原文 mysql 客户端）：
#   update zzcms_ad set nextuser='aaaa' where id=1 and (select ... sleep(1) ...);  -- 0.00s，被短路
#   update zzcms_ad set nextuser='aaaa' where id=1 | (select ... sleep(1) ...);    -- 1.00s，子查询执行
```

## 变体与关联

- 变体：把 `sleep(1)` 换成布尔/报错/联合查询形态；若目标表存在且可利用，`id` 处也可做 UNION 或堆叠（取决于驱动与权限）。
- 变体：同样的「短路 vs 位或」技巧适用于任何 `WHERE id=$int` 的 UPDATE/DELETE/SELECT 盲注场景，不限于 zzcms。
- 关联：[[web-generic-sqli-blind-filter-bypass-functions]]、[[web-generic-sqli-cartesian-product-time-blind]]（时间盲注通用手法）；[[web-php-rce-empirebak-backup-tablename-config-injection]]（本卡后续利用：拿管理员后借内置 EmpireBak 写马）。
- 边界：前置的用户中心操作会增加请求痕迹（注册、发展会、设广告），检测方可通过账号行为链识别。

## 检测与防御

- 根治：所有 SQL 使用预处理参数化；`id` 这类整型参数强制 `intval()/cast`，不要依赖 `addslashes`（它对数字型注入无效）。
- 加固：`global.php` 的统一过滤不能当作注入防御；对 `$_REQUEST['action']` 做白名单；后台口令使用强哈希并限制登录来源。
- 检测：`/user/adv2.php` 的 `id` 参数出现 `|`、`&`、括号、`select`、`sleep` 等关键字；同一新注册账号短时间内「发展会→设广告→带特殊 id 请求」的异常序列；MySQL 慢查询日志中 `sleep()` 调用。
- 检测：WAF 对数字型参数中的运算符与子查询特征做规则；数据库账号最小权限，关闭 `FILE` 等高危权限。
