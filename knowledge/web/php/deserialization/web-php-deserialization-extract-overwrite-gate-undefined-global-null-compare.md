---
id: web-php-deserialization-extract-overwrite-gate-undefined-global-null-compare
title: extract($_POST) 覆盖同名变量跳过「同值即 die」分支，再用 __wakeup 把属性赋成未定义全局（null）让严格比较成立
type: scenario
domain: web
path: web/php/deserialization
technique: extract-variable-overwrite-gate-bypass-wakeup-null-strict-compare
aliases:
- extract 变量覆盖绕过二次判断
- pucky 二仙桥
- __wakeup 未定义全局变量置 null
- 严格比较 null 绕过
- 变量覆盖 + 反序列化
tags:
- php
- deserialization
- extract
- variable-overwrite
- wakeup
- type-juggling
- strict-compare
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:15:16+08:00'
  notes: 已对照原文核对；本次核对未读取图片；extract() 覆盖 pucky 跳过二次同值 die、__wakeup 中 yuki=未定义全局(二仙桥源码 )取 null、molly 亦置 null 使 === 成立，均与原文源码一致；原文给出的 exp 只打印默认对象序列化串，卡内改用 N; 构造属正确推导（原文未直接给出该 payload，属未验证点）
---

## 一句话结论

入口先判 `$_GET['wq'] === "固定串"`，进入分支后 `extract($_POST)`，再用同一变量做第二次同样判断——只要在 POST 里带上同名参数（值是序列化串），`extract` 就把 `$pucky` 覆写成攻击者内容，第二次判断不成立、`die()` 被跳过，`unserialize($pucky)` 得以执行；随后 `__wakeup()` 里 `$this->yuki = $where_you_go` 引用一个从未定义的全局变量（值为 `null`），把 `molly` 也设为 `null` 即可让 `$this->molly === $this->yuki` 成立，拿到 flag。

## 原理

- `extract($_POST)` 以数组键为变量名、值为变量值导入当前符号表，默认 `EXTR_OVERWRITE`，会**覆盖同名局部/全局变量**。因此“同一个变量连判两次”的写法不具备保护性：第一次判断用的是 URL 参数，第二次判断用的是 POST 覆盖后的值。
- 这种“同值即终止”的分支本是反 CSRF/防重放式的粗糙校验：设计者假设变量不可变，一旦变量可被外部赋值，判断的两端就不再指向同一个输入。
- `unserialize` 会对对象立即触发 `__wakeup()`。本类 `__wakeup` 里 `$this->yuki = $where_you_go;` 中 `$where_you_go` 是 `global` 声明但从未赋值的变量，取值为 `null`；随后 `if ($this->molly === $this->yuki) echo $flag;`。
- `===` 是严格比较（类型 + 值），所以需要让 `molly` 也是 `null`，而不是 `0`、`""`、`false`。序列化格式中 `N;` 表示 `null`，因此构造 `O:7:"popmart":3:{s:4:"yuki";N;s:5:"molly";N;s:5:"dimoo";N;}` 即可让两个属性都为 `null` 而比较成立。
- 之所以是可复用模式：很多 PHP 题/旧代码用「先比对固定串、再 extract、再比对固定串」的方式做门禁，或用未初始化的全局变量做“默认值”，两者叠加就能同时绕过门禁与比较。

## 触发条件

- 应用/题目在鉴权或分支判断后调用 `extract($_POST)`/`extract($_REQUEST)`/`parse_str`（`EXTR_OVERWRITE` 默认），且被覆盖的变量参与了后续判断。
- 存在 `unserialize()` 的入口，且攻击者能控制整段序列化数据。
- 目标类的魔术方法里把属性赋成未定义全局变量、`null`、常量或其它可由序列化直接表达的值，再与攻击者可控属性做 `===`/`==` 比较。
- 需要已知类名与属性名（源码泄露、报错回显、常见命名）。

## 利用步骤

1. 读源码，确认门禁结构：第一次判断用的变量名、`extract` 的位置、`unserialize` 的实参。
2. 用同名 POST 参数把该变量换成恶意序列化串（值与原判断串不同），使第二次判断失败从而跳过 `die()`。
3. 构造序列化 payload：把参与 `===` 比较的属性设为 `N;`（`null`），即与 `__wakeup` 中未定义全局变量的取值一致。
4. 发送：`GET /?wq=<固定串>` + `POST wq=<序列化串>`，观察 flag 回显。
5. 若类中还有 `__destruct`/`__toString` 等可利用点，可把 payload 换成完整 POP 链，思路相同。

## PoC

```php
<?php
// 目标类（摘自题目源码的关键逻辑）
class popmart {
    public $yuki; public $molly; public $dimoo;
    public function __wakeup() {
        global $flag; global $where_you_go;   // $where_you_go 从未赋值 => null
        $this->yuki = $where_you_go;
        if ($this->molly === $this->yuki) { echo $flag; }
    }
}
// 构造：molly 必须是 null
$p = new popmart();
$p->yuki  = null;
$p->molly = null;
$p->dimoo = null;
echo serialize($p);
// O:7:"popmart":3:{s:4:"yuki";N;s:5:"molly";N;s:5:"dimoo";N;}
```

```http
GET /p0pmart.php?wq=%E4%BA%8C%E4%BB%99%E6%A1%A5 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

wq=O:7:"popmart":3:{s:4:"yuki";N;s:5:"molly";N;s:5:"dimoo";N;}
```

（注意 `wq` 同时出现在 query 与 body：query 满足第一次判断，body 经 `extract` 覆盖后使第二次判断失败。）

## 变体与关联

- 变体：`extract($_REQUEST)` 时 URL 参数也会覆盖，需把门禁值放在 `Cookie` 或 header 里；`parse_str($str)` 有同样效果。
- 变体：比较处用 `==` 而非 `===` 时 payload 可放宽（`0 == null`、`"" == null` 均为真），甚至不需要构造 `N;`。
- 变体：`__wakeup` 里被赋的是常量（如 `"dont_tell_you"`）时，直接用同名属性值即可；若属性是 `protected/private`，序列化键名要带 `\0*\0`/`\0类名\0` 前缀。
- 关联：[[web-generic-auth-php-variable-variable-config-array-bypass]]（`$$key`/`extract` 覆盖配置对象的认证绕过）、[[web-php-deserialization-wakeup-reference-alias-bypass]]（`R:` 引用别名让 wakeup 重置失效）、[[web-php-deserialization-wakeup-property-count-bypass]]（`__wakeup` 触发机制层面的绕过）。
- 边界：门禁第二次判断比较的是 `$_GET`/`$_POST` 原始数组而非被 extract 的变量、或 `extract` 用了 `EXTR_SKIP`/前缀、或 `unserialize` 被禁用（`allowed_classes=false`）时，本链不成立。

## 检测与防御

- 代码层：禁止对用户输入使用 `extract()`/`$$key`/`parse_str` 到当前作用域；需要动态键时用显式白名单映射数组。
- 门禁层：校验只做一次，且校验对象是不可被外部赋值的字段（如 `$request->get()` 的局部快照）；不要用“同值即 die”这种依赖变量不可变的写法。
- 反序列化层：不要对用户输入 `unserialize`，改用 JSON；必须反序列化时用 `allowed_classes` 白名单 + 签名/HMAC 校验完整性。
- 魔术方法层：`__wakeup` 里不要依赖未初始化全局变量做默认值；比较用显式类型判断。
- 检测：请求同时出现“已知门禁串”和同名 body 参数、值为 `O:`/`a:` 开头的序列化结构；`__wakeup` 相关类被实例化但无对应业务调用。
