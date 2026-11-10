---
id: code-analysis-source-audit-thinkphp-i-modifier-where-escape
title: ThinkPHP 3.x 源码注入审计：I() 修饰符类型转换与 where() 双形态（字符串拼接 vs escapeString 格式化）
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: thinkphp-i-modifier-where-escape-audit
aliases:
- ThinkPHP I() 审计
- TP3 SQL 注入审计
- where 模拟预编译
- escapeString 双写单引号
- 传参修饰符强制类型转换
- ThinkPHP 正则筛注入点
- where 第二参数 vsprintf
tags:
- code-audit
- php
- thinkphp
- sqli
- source-audit
- regex
- static-analysis
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:09:38+08:00'
  notes: 已对照原文图01-10核对 I() 修饰符 switch、where() 两分支、SQLite escapeString 双写单引号、checkLogin(false)、info()/pwd() 对比与正则筛选；dedup 最相近为 JDBC/HQL 审计方法卡，非同链；原文未声明具体受影响版本。
---

## 一句话结论

审计 ThinkPHP 3.x 应用时，先把 `I("参数/修饰符")` 的修饰符还原成强制类型转换（`/d` 转 int 会毁掉注入 payload，`/s` 或无修饰符仍是字符串），再把所有 `where()` 调用分成「第二参数为空、字符串直接拼接」与「第二参数非空、`array_map(escapeString)+vsprintf` 模拟预编译」两类；只有前者且参数以字符串形式进入时才是候选注入点，配合正则 `I\("([^"/]+)(\/s)?"\)` 可从全项目快速收敛候选。

## 原理

- **`I()` 的修饰符就是类型转换**：`I()` 先用 `strpos` 找 `/`，把 `name/type` 拆开；再用 `.` 指定来源（get/post/put/param）；最后按 type 走 switch：`a`→数组、`d`→`(int)`、`f`→`(float)`、`b`→`(bool)`、`s`/default→`(string)`。因此 `I("uid/d")` 的 payload 会被强转成整数，而 `I("item_id")`、`I("item_id/s")` 保持字符串——后者才有注入可能。
- **`where()` 有两种执行路径**：`where($where, $parse = null)` 中，若 `$parse` 非空且 `$where` 是字符串，则先 `array_map([$db, 'escapeString'], $parse)` 再 `vsprintf` 格式化进 SQL；若 `$parse` 为空且 `$where` 是字符串，则原样放进查询条件（`_string`），不做转义。
- **escapeString 的效果**：SQLite 驱动的 `escapeString` 是 `str_ireplace("'", "''", $str)`，把单引号双写；格式化后的 SQL 中攻击者引号无法闭合，等价于在 PHP 层做了一次「模拟预编译」。因此两参数写法通常安全，单参数拼接写法才危险。
- **审计三条件**：① 路由无鉴权或鉴权发生在查询之后（`checkLogin(false)` 或查询在 `checkLogin()` 之前）；② 参数经 `I("xxx/s")` 或无修饰符取得（字符串）；③ 该参数被拼进只有一个参数的 `where("... '$x' ...")`。
- **为什么正则有效**：`I\("([^"/]+)(\/s)?"\)` 只匹配「无修饰符」或「`/s`」的参数名，直接排除 `/d`、`/f` 等会被强转的传参；在 PhpStorm 全项目搜索可把候选从数千处降到百处量级，再由人工检查鉴权与 where 用法。
- **案例中的对比**：同一个控制器里，`info()` 用 `where("item_domain = '%s'", array($item_domain))`（安全），而 `pwd()` 用 `$item_id = I("item_id")` 后 `where("item_id = '$item_id' ")`（可注入）；前者说明开发者知道格式化写法，后者是遗漏。
- **边界**：`C('VAR_AUTO_STRING')` 为真时无修饰符也会被当作 `s`；`I('post.')` 取整个来源数组；数组参数进入字符串拼接会报错或转换；`where()` 传数组/对象时走其他分支，需单独判断。

## 触发条件

- 能获取 ThinkPHP 3.x（如 3.2.x）项目源码，且项目使用 `I()` 取参、`D()/M()` 模型 `where()` 查询。
- 项目内存在单参数字符串 `where` 且嵌入变量；对应路由无鉴权或鉴权可绕过。
- 参数未被 `/d`、`/f` 等修饰符强制转换。
- 数据库驱动为 SQLite/MySQL 等，`escapeString` 行为与上述一致；若开发者自定义了 DB 驱动需重新核对。

## 利用步骤

1. 全项目搜索 `function I(` 确认框架版本与修饰符解析逻辑；确认 `where()` 实现（`Think/Model.class.php`）与 DB 驱动的 `escapeString`。
2. 用正则 `I\("([^"/]+)(\/s)?"\)` 搜索所有字符串型传参，得到候选参数名与文件位置。
3. 在每个候选文件中搜索 `where(`：只有一个参数且 SQL 字符串中嵌入了该变量的，标记为候选 sink；两参数 `%s` 形式先排除。
4. 回溯路由：检查控制器方法是否调用 `checkLogin(false)`、是否在查询前未鉴权，或目标代码位于 `checkLogin()` 之前。
5. 构造闭合 payload（如 `1') union select ... --`），按业务分支判断布尔/报错/时间回显，验证注入。
6. 对确认点输出「文件:行 + 路由 + 参数 + 鉴权状态 + payload」清单，作为后续利用（读 token/账号）入口。

## PoC

```text
# 1) 候选传参正则（PhpStorm/ripgrep 均可）
I\("([^"/]+)(\/s)?"\)

# 2) 安全写法（第二参数存在 → escapeString + vsprintf）
D("Item")->where("item_domain = '%s'", array($item_domain))->find();

# 3) 危险写法（第二参数为空 → 字符串直接拼接）
$item_id = I("item_id");                       // 字符串，未被强转
D("Item")->where("item_id = '$item_id' ")->find();

# 4) 修饰符对比
I("uid/d")   // (int)$uid，payload 被清洗
I("uid/s")   // (string)$uid，payload 保留
```

## 变体与关联

- [[web-generic-sqli-showdoc-item-pwd-item-id-union-captcha-ocr-user-token]]：按本方法在同一类 TP3 应用中定位到的真实注入点与利用链（`item/pwd` 的 `item_id`）。
- [[code-analysis-source-audit-jdbc-hql-concat-regex]]：同属「先建安全基线、再用正则筛拼接候选」的源码审计方法，语言/框架不同。
- [[web-generic-sqli-thinkphp-where-exp-array-injection]]：ThinkPHP 生态中 `where` 数组/exp 可控的另一类注入面。
- 变体：ThinkPHP 5.x 用 `input()` 与 `where` 数组/闭包，审计点变成 `input('x/s')` 与 `whereRaw`/`exp`；Laravel 的 `DB::raw`、Yii 的 `createCommand` 拼接同理。
- 边界：`I()` 的默认过滤（`htmlspecialchars` 等）只影响 XSS，不改变 SQL 转义；`escapeString` 对某些多字节编码/驱动可能不充分，需要按实际驱动验证。

## 检测与防御

- 代码层：禁止单参数字符串 `where` 拼接用户输入，统一使用 `where("col = '%s'", array($v))` 或查询构造器；标识符位置（表名/列名/ORDER BY）用白名单。
- 审计层：把上述正则加入 SAST/代码评审规则；对 `I()` 无修饰符参数默认视为字符串输入，追踪到 `where`/`query`/`execute`。
- 运行层：WAF 监控 `item_id`、`id` 等参数中的引号/UNION/注释；数据库账号最小权限；关闭调试页避免报错泄露。
- 响应：发现注入后轮换 `user_token` 等长期凭证，排查是否已被用于登录后台。
