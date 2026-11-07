---
id: web-php-deserialization-ez-uns-trailing-space-gc-php-filter-traversal
title: PHP ez_uns 三合一链：serialize/unserialize 尾部空格差异 + 重复键 GC 触发 __destruct + php://filter 目录穿越 include
type: scenario
domain: web
path: web/php/deserialization
technique: serialize-unserialize-trailing-space-gc-destruct-php-filter-traversal
tags:
- php
- deserialization
- gc
- destruct
- php-filter
- path-traversal
- include
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:20:14+08:00'
  notes: 已对照原文核对：尾部两空格绕过 serialize(unserialize()) 不等比较、重复键 GC 提前触发 __destruct、Amoda protected 属性 URL 编码、php://filter/resource=汉字/../../../../flag 穿越均一致；原文为 CTF 环境无组件版本；未实际运行 PoC。
url: /docs/web/php/deserialization/web-php-deserialization-ez-uns-trailing-space-gc-php-filter-traversal/
draft: false
kb_aliases:
- ez_uns
- Amoda
- Acc1oFl4g
- 尾部空格绕过
- 重复键 GC
- __destruct 提前触发
- php://filter resource 目录穿越
- 不会本地调试怕是写不出来了
---

## 一句话结论

当目标用 `serialize(unserialize($tou))` 与原始 `$tou` 做不等比较、并要求反序列化结果是 `Amoda` 实例时，可在 `$tou` 末尾加两个空格让 `unserialize` 忽略、`serialize` 去掉空格，从而通过不等检查；再用重复键让对象在 `unserialize` 过程中被 GC 提前释放、触发 `__destruct`，最后用 `php://filter/resource=<不存在的目录>/../../../../flag` 的目录穿越读取 `/flag`。

## 原理

- **尾部空格差异**：PHP 的 `unserialize()` 允许序列化串末尾有空白字符并忽略它们，而 `serialize()` 输出的是不含多余空白的规范形式。因此 `$tou = serialize($amoda) . '  '` 时，`$gxn = serialize(unserialize($tou))` 与 `$tou` 只差尾部空格，`$gxn != $tou` 为真，但 `unserialize($gxn)` 仍得到同一个 `Amoda` 对象，满足 `instanceof Amoda`。
- **重复键 GC 提前触发 `__destruct`**：脚本在 `unserialize($web)` 后立即 `throw new Exception`，正常流程可能来不及执行对象的 `__destruct`。构造一个数组，第一项是 `Acc1oFl4g` 对象、第二项是 `null`，再把第二项的键名改成与第一项相同（`"e";N` → `"a";N`）。`unserialize` 遇到重复键时，后一个 `null` 覆盖前一个对象，对象的引用计数在反序列化过程中降为 0，`__destruct` 立即执行，从而在异常抛出前完成攻击。
- **`__destruct` → `exec` → `include`**：`Acc1oFl4g::__destruct()` 在 `shql == "admin"` 时调用 `exec()`；`exec()` 先检查 `tou` 不含大写 `S:`，再做 `serialize(unserialize())` 与 `instanceof Amoda` 检查，最后 `include($gxngxngxn->act())`。
- **`php://filter` 目录穿越**：`Amoda::act()` 返回 `$q1 . '不会本地调试怕是写不出来了' . $q2`。把 `q1` 设为 `php://filter/resource=`、`q2` 设为 `/../../../../flag`，得到 `php://filter/resource=不会本地调试怕是写不出来了/../../../../flag`。中间的汉字是不存在的目录名，但 `..` 穿越不要求前面的目录存在，最终资源路径回到 `/flag`；`convert` 检查因结果中不含 `convert` 而通过。
- **URL 编码保护 NUL**：`Amoda` 的 `q1`/`q2` 是 `protected` 属性，序列化后的属性名包含 `\0*\0` 前缀；直接放进 POST 会被截断/破坏，必须对整个序列化串做 URL 编码，服务端解码后 NUL 字节恢复。
- **入口检查**：`stripos($web, 'admin') !== false && stripos($web, 'Amoda":') == false` 时退出；序列化串同时包含 `"admin"` 和 `O:5:"Amoda":`（含 `Amoda":`），第二个条件为假，因此不会退出。该检查实际上无法区分正常序列化结构与攻击载荷。

## 触发条件

- 存在 `unserialize($_POST[...])` 入口，且目标类 `__destruct`/`__wakeup` 中有可利用的 `include`/`eval`/文件操作。
- 代码使用 `serialize(unserialize($x))` 与原始值做不等比较（而不是直接比较对象），且允许尾部空白。
- 目标类允许实例化（无 `allowed_classes` 限制或包含所需类）。
- `include` 的参数可被拼接为 `php://filter/resource=` + 可控路径，且过滤只检查某些关键字（如 `convert`）。
- PHP 版本对重复键的处理允许后者覆盖前者并触发 GC（常见 PHP 7/8 行为）。

## 利用步骤

1. 审计源码，确认 `Acc1oFl4g::__destruct → exec → serialize(unserialize($tou)) → include(Amoda::act())` 的调用链。
2. 构造 `Amoda` 对象：`q1 = 'php://filter/resource='`，`q2 = '/../../../../flag'`（按目标 flag 路径调整）。
3. 构造 `Acc1oFl4g` 对象：`shql = 'admin'`，`tou = serialize($amoda) . '  '`（两个尾部空格，保证 `$gxn != $tou`）。
4. 构造外层数组 `['a' => $acc, 'e' => null]`，序列化后把 `"e";N` 替换为 `"a";N`，制造重复键以触发 GC。
5. 对整个序列化串做 URL 编码（保护 protected 属性名中的 NUL），作为 `webweb` POST 参数提交。
6. `unserialize` 时重复键释放对象 → `__destruct` → `exec` → `include` 读取目标文件，响应回显文件内容。

## PoC

```php
<?php
class Acc1oFl4g {
    public $shql;
    public $tou;
    public function __destruct() { /* 目标逻辑 */ }
}
class Amoda {
    protected $q1;
    protected $q2;
    public function act() { /* 目标逻辑 */ }
}

$b = new Amoda();
$b->q1 = 'php://filter/resource=';
$b->q2 = '/../../../../flag';

$a = new Acc1oFl4g();
$a->shql = 'admin';
$a->tou = serialize($b) . '  ';   // 尾部两个空格，绕过 $gxn != $tou

$d = array('a' => $a, 'e' => null);
$c = str_replace('"e";N', '"a";N', serialize($d)); // 重复键，GC 提前触发 __destruct
echo urlencode($c);
```

```text
# 关键拼接结果
php://filter/resource=不会本地调试怕是写不出来了/../../../../flag
# 不存在的目录前缀被 ../ 穿越掉，实际读取 /flag
```

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

webweb=<urlencode 后的序列化串>
```

## 变体与关联

- 尾部空白变体：除空格外，`unserialize` 还容忍 `\n`、`\t` 等空白；也可用其它“反序列化再序列化会规范化”的差异（如属性顺序、默认值）绕过不等比较。
- GC 变体：重复键覆盖是触发 `__destruct` 的一种方式；也可用数组引用计数、异常/`exit` 前的对象释放等技巧。
- 伪协议变体：`php://filter/resource=` 可换 `php://filter/read=convert.base64-encode/resource=`（若目标允许 `convert`），或其它本地文件包装器；目录穿越不要求前缀目录存在是关键。
- 关联：[[web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read]]（另一条魔术方法链）、[[web-php-deserialization-str-replace-length-lengthening-pop-eval]]（长度逃逸 POP 链）、[[web-php-file-inclusion-php-filter-insert-bypass]]（php://filter 关键字绕过）。

## 检测与防御

- 检测：请求参数中出现 URL 编码的序列化串、`%00%2A%00`（protected 属性名）、重复键结构、`php://filter`、`../`；`unserialize` 后对象属性被意外覆盖或 `__destruct` 被提前触发。
- 防御：不要用 `serialize(unserialize())` 与原始字符串做安全比较；使用 `unserialize($data, ['allowed_classes' => [...]])` 白名单；对反序列化数据做 HMAC 签名。
- 加固：`include`/`file_get_contents` 的路径使用白名单与 `realpath` 校验；禁止 `php://` 包装器或限制 resource 路径；关闭不必要的魔术方法中的敏感操作。
