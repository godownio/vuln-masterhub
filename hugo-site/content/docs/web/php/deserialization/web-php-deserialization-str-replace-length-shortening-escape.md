---
id: web-php-deserialization-str-replace-length-shortening-escape
title: PHP 序列化字符逃逸：str_replace 把 8 字符 amgoinvc 换成 4 字符 iscc，导致属性边界错位并伪造 admin123
type: scenario
domain: web
path: web/php/deserialization
technique: php-serialize-str-replace-character-escape
tags:
- php
- deserialization
- serialize
- str-replace
- character-escape
- wakeup
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:15:48+08:00'
  notes: 已对照原文核对：p2 中 key=bnhpjowd 逐字符减 1 得 amgoinvc，str_replace 成长度 4 的 iscc；x=amgoinvc×4 缩短 16 字节恰好吞掉 ";s:1:\"y\";s:23:\"，p 伪造 y=admin123，与原文构造和 PoC 一致。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-str-replace-length-shortening-escape/
draft: false
kb_aliases:
- 字符逃逸
- 序列化替换逃逸
- str_replace 变短
- amgoinvc iscc
- 属性边界错位
- 数字古墓
- PHP 序列化长度不一致
---

## 一句话结论

当应用先 `serialize()` 再对序列化串做 `str_replace()`（把长字符串替换成更短字符串）后 `unserialize()` 时，字符串声明长度不变而实际内容变短，解析器会按旧长度吞掉后面的 `";s:1:"y";...` 结构；攻击者在另一个可控属性中预置闭合片段，就能把被吞并的字节重新解释成新的属性，从而把 `y` 改成 `admin123` 并触发 `__wakeup()`。

## 原理

- PHP 序列化字符串格式是 `s:<声明长度>:"<内容>";`。`unserialize()` 只信声明长度，不校验引号位置与内容实际长度。
- 目标流程：
  ```php
  $obj = new nameA($input, $passwd);
  $ser = serialize($obj);
  $result = str_replace('amgoinvc', 'iscc', $ser);
  unserialize($result);
  ```
  其中 `amgoinvc` 长度 8，`iscc` 长度 4；每替换一次，实际字符串缩短 4 字节，但 `s:<长度>` 中的数字不会自动更新。
- 设 `x = amgoinvc` 重复 4 次（32 字节），序列化后 `x` 声明长度为 32。替换后 `x` 实际只剩 `iscciscciscciscc`（16 字节），解析器仍按 32 字节读取，于是会继续吞掉后面的 `";s:1:"y";s:23:"`（正好 16 字节）。
- 攻击者把 `y`（`$passwd`）设为 `";s:1:"y";s:8:"admin123";}`。解析器读完 `x` 的 32 字节后，期望一个闭合引号，正好遇到 `y` 内容开头的 `"`；期望分号，遇到 `;`；随后剩余内容 `s:1:"y";s:8:"admin123";}` 被解析成新的属性 `y=admin123` 并结束对象。
- 这样原本的 `x` 值被截断、原本的 `y` 序列化结构被“吃掉”，但解析器最终构造出的对象中 `y === 'admin123'`，`nameA::__wakeup()` 中的判断成立，执行 `include('relic_manifest.php')` 并输出文件名。
- 根因是“对序列化后的文本做改变长度的替换”，让声明长度与实际内容脱钩；替换函数、正则替换、HTML 转义、截断等任何改变长度的后处理都可能造成同类逃逸。
- 注意：若替换是“变长”（短替换成长），则声明长度小于实际内容，解析器会提前截断字符串，后续字节被当作结构解析，同样可能被利用；本题是“变短”方向。

## 触发条件

- 应用对用户可控数据先 `serialize()`，再经过 `str_replace`/`str_ireplace`/`preg_replace`/自定义过滤等改变字符串长度的处理，最后 `unserialize()`。
- 被替换的搜索串出现在攻击者可控的属性值中，且替换后的长度与搜索串不同。
- 目标类存在可利用的魔术方法（本题是 `__wakeup()` 中的 `include`/属性判断），且属性值可被重新解释。
- 攻击者知道或能猜出序列化结构中的属性名、顺序与长度，以便精确构造闭合片段。
- 入口对类名没有严格白名单，或目标类本身在允许范围内。

## 利用步骤

1. 审计源码，确认 `serialize()` → `str_replace()` → `unserialize()` 的顺序，以及搜索串/替换串的长度差。
2. 计算需要重复搜索串的次数：让“缩短量”恰好等于后续 `";s:<属性名>";s:<长度>:"` 等结构的前缀长度，使解析器读完 `x` 后正好停在可控位置。
3. 把 `x` 设为搜索串的 N 次重复；把 `y` 设为以 `";` 开头、后接伪造属性与对象闭合的字符串。
4. 提交 `d=<重复串>&p=<伪造片段>`；观察是否触发 `__wakeup()` 的目标分支。
5. 若一次不成功，微调重复次数与 `p` 的前缀（不同属性名/长度会改变需要吞掉的字节数）。

## PoC

```http
GET /rune_trial.php?d=amgoinvcamgoinvcamgoinvcamgoinvc&p=%22%3Bs%3A1%3A%22y%22%3Bs%3A8%3A%22admin123%22%3B%7D HTTP/1.1
Host: target
```

`p` 解码后为：

```text
";s:1:"y";s:8:"admin123";}
```

本地复现核心：

```php
class nameA {
    public $x; public $y;
    public function __construct($a, $b) { $this->x = $a; $this->y = $b; }
    public function __wakeup() {
        if ($this->y === 'admin123') { echo "wakeup hit\n"; }
    }
}
$obj = new nameA(str_repeat('amgoinvc', 4), '";s:1:"y";s:8:"admin123";}');
$ser = serialize($obj);
$out = str_replace('amgoinvc', 'iscc', $ser);
var_dump($out);
unserialize($out); // 期望输出 wakeup hit
```

## 变体与关联

- **替换方向**：长→短（本题，声明长度过大，吞掉后续结构）；短→长（声明长度过小，提前截断，后续字节被当作结构）；等长替换不产生逃逸。
- **替换函数**：`str_replace`、`str_ireplace`、`preg_replace`、`strtr`、HTML 实体编码、URL 解码后再序列化等。
- **结构变体**：嵌套对象、数组、多个属性、`__destruct` 起点；需要吞掉的字节数随属性名/类型变化，可通过脚本枚举。
- **关联**：[[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]（利用序列化格式等价写法绕过正则，而不是长度变化）；[[web-php-deserialization-session-s-hex-escape-admin-forge]]（S 类型十六进制转义）。
- **边界**：若应用在替换后重新 `serialize()`、使用 JSON、或对反序列化做结构校验/签名，本路径失效。

## 检测与防御

- **检测**：请求参数中出现大量重复的固定字符串、序列化结构片段（`O:`、`s:`、`";s:`）或长度与内容不符的序列化串；反序列化后对象属性被意外改写；`unserialize` 调用点附近存在 `str_replace`/`preg_replace`。
- **防御**：不要对用户可控数据做“序列化后再字符串替换再反序列化”；如必须过滤，先反序列化到受限对象/数组，校验后再序列化；使用 `unserialize($data, ['allowed_classes' => [...]])` 白名单。
- **加固**：移除不必要的 `__wakeup`/`__destruct` 魔术方法中的敏感操作；对反序列化数据做 HMAC 签名；改用 JSON。
