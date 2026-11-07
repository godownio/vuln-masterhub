---
id: web-php-deserialization-c-prefix-arrayobject-bypass
title: 'PHP 反序列化黑名单以 O:/a: 开头：用 ArrayObject 等 C: 格式类包装绕过'
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-c-format-wrapper-bypass
aliases:
- C: 前缀绕过
- ArrayObject 包装
- __unserialize 包装
- 反序列化黑名单绕过
- C:11:"ArrayObject"
- Serializable 反序列化格式
tags:
- php
- deserialization
- filter-bypass
- c-format
- arrayobject
- serializable
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T17:01:49+08:00'
  notes: 已对照原文C:前缀绕过段落核对：ArrayObject/ArrayIterator/RecursiveArrayIterator/SplObjectStorage内置类清单与包装思路一致；卡内已纠正原文“取决于__unserialize”为Serializable的C:格式机制，并注明仅绕过锚定开头过滤；ArrayObject序列化长度55与Taki示例82经复算一致；无sources/source_url；未在本机对目标执行
---

## 一句话结论

当过滤只拒绝以 `O:`（对象）或 `a:`（数组）开头的序列化串时，可把恶意 gadget 对象嵌进 `ArrayObject`、`ArrayIterator`、`RecursiveArrayIterator`、`SplObjectStorage` 等以 `C:` 格式序列化的内置类中，使 payload 首字节变成 `C:` 通过检查；`unserialize()` 仍会重建内层对象并触发其魔术方法。

## 原理

- PHP 序列化有多个类型前缀：`O:` 普通对象、`a:` 数组、`s:` 普通字符串、`S:` 带十六进制转义的字符串、`C:` 实现 `Serializable` 接口的类（自定义序列化）。
- 实现 `Serializable` 的类调用 `serialize()` 时输出 `C:<类名长度>:"<类名>":<数据长度>:{<自定义数据>}`，而不是 `O:`。PHP 内置的 `ArrayObject`、`ArrayIterator`、`RecursiveArrayIterator`、`SplObjectStorage` 都属于这类，可直接用于包装。
- 例如 `serialize(new ArrayObject(['property' => new stdClass()]))` 输出：
  ```text
  C:11:"ArrayObject":55:{x:i:0;a:1:{s:8:"property";O:8:"stdClass":0:{}};m:a:0:{}}
  ```
  首字符是 `C`，不匹配 `^O:`/`^a:` 黑名单；内层恶意对象仍以 `O:` 形式保存在 `a:1:{...}` 数据中。
- `unserialize()` 遇到 `C:` 会调用该类的 `unserialize()`（PHP 7.4+ 亦可对应 `__unserialize()` 机制）重建内部数据；内层对象被实例化后，其 `__wakeup()`/`__destruct()` 等魔术方法照常触发，攻击链不受影响。
- 关键限制：该技巧只绕过**锚定在开头**的检查（如 `substr($data,0,2)==='O:'`、`preg_match('/^(O|a):/',$data)`）。如果过滤在整个字符串中搜索 `O:`，内层对象仍会命中；若过滤同时禁止 `C:`，也需要换其他包装类或编码技巧。
- 另一个限制：如果业务逻辑要求反序列化结果必须是某个具体类的实例（`instanceof`），外层变成 `ArrayObject` 后语义改变，可能无法进入后续代码；该技巧适用于“只要对象图能到达 gadget 魔术方法即可触发”的场景。

## 触发条件

- 应用对用户输入调用 `unserialize()`，且存在以 `O:`/`a:` 开头的黑名单检查。
- 没有使用 `allowed_classes` 白名单，或白名单允许内置 SPL 类与 gadget 类。
- 目标 PHP 版本支持 `C:` 格式及相应内置类（PHP 5.3+ 默认可用）。
- gadget 的触发不依赖顶层对象的具体类型（`__wakeup`/`__destruct` 在对象图释放时即可触发）。

## 利用步骤

1. 确认过滤规则只匹配开头（阅读源码或测试 `O:`、`a:`、`C:` 前缀的响应差异）。
2. 在本地构造 gadget 对象，放入 `ArrayObject` 的数组数据中：`new ArrayObject(['property' => $gadget])`。
3. `serialize()` 得到 `C:11:"ArrayObject":...` 开头的 payload；检查内层 `O:` 是否被其他规则拦截。
4. 必要时调整包装类的数据键名/结构，使内层对象在反序列化时被重建并触发魔术方法。
5. 提交 payload，观察 gadget 的 sink（文件读取、命令执行、`eval` 等）是否生效。

## PoC

```php
class Taki {
    public $cmd = "system('id');";
    public function __destruct() { eval($this->cmd); }
}

$payload = new ArrayObject(['property' => new Taki()]);
echo serialize($payload);
```

输出形如：

```text
C:11:"ArrayObject":82:{x:i:0;a:1:{s:8:"property";O:4:"Taki":1:{s:3:"cmd";s:13:"system('id');";}};m:a:0:{}}
```

若入口检查 `if (substr($data,0,2) === 'O:' || substr($data,0,2) === 'a:') die();`，上述 payload 可通过；`unserialize()` 后 `Taki::__destruct()` 执行 `eval`。原文仅给出包装思路与内置类清单，未给出具体目标环境；PoC 结构按文章代码补全，未在本机对目标执行。

## 变体与关联

- 包装类变体：`ArrayIterator`、`RecursiveArrayIterator`、`SplObjectStorage`；不同类的 `C:` 数据格式不同，需按实际序列化结果填充。
- 编码变体：`S:` 十六进制字符串、`R:`/`r:` 引用、对象属性名转义等也可绕过只看字面量的正则，见 [[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（gadget 链）、[[web-php-deserialization-str-replace-length-lengthening-pop-eval]]（另一种结构错位绕过）。
- 边界：全字符串关键字扫描、`allowed_classes` 白名单、先解析结构再校验的应用不受影响。

## 检测与防御

- 检测：请求参数中出现 `C:` 开头的序列化串，且内部嵌套 `O:` 对象；`ArrayObject`/`ArrayIterator`/`SplObjectStorage` 等内置类出现在不可信输入中。
- 修复：不要用字符串前缀/正则黑名单校验序列化数据；使用 `unserialize($data, ['allowed_classes' => [...]])` 限制可实例化类，且白名单不包含不需要的内置类；优先改用 JSON。
- 加固：对反序列化结果做结构校验与类型检查；移除 gadget 类中的 `eval`/文件/命令 sink；升级 PHP 并关注 `Serializable` 相关行为变化。
