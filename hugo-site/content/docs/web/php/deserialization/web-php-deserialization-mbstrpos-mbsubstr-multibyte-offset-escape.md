---
id: web-php-deserialization-mbstrpos-mbsubstr-multibyte-offset-escape
title: PHP mb_strpos/mb_substr 多字节偏移差异导致字符逃逸：绕过方括号黑名单注入序列化数据
type: scenario
domain: web
path: web/php/deserialization
technique: php-mbstrpos-mbsubstr-multibyte-offset-escape
tags:
- php
- deserialization
- multibyte
- mb-strpos
- mb-substr
- filter-bypass
- character-escape
- utf-8
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:05:35+08:00'
  notes: 已对照原文与6张图核对：mb_strpos/mb_substr偏移、%9f/%f0实测与最终unserialize触发system一致；偏移表按原文实测、未本机复跑。
url: /docs/web/php/deserialization/web-php-deserialization-mbstrpos-mbsubstr-multibyte-offset-escape/
draft: false
kb_aliases:
- mb_strpos mb_substr 字符逃逸
- 多字节偏移逃逸
- '%f0abc 吃掉三位'
- '%9f 方括号泄漏'
- 方括号黑名单绕过
- unserialize 注入
---

## 一句话结论

当代码用 `mb_strpos()` 定位 `[`/`]` 后，把返回的字节位置直接当作 `mb_substr()` 的字符偏移使用，攻击者可在分隔符前放入 `%f0abc`、`%f0%9fab` 等非法 UTF-8 序列，使 `mb_substr()` 的起点比真实 `[` 位置多跳过 N 个字符；选择 N 等于序列化外层头长度后，截取结果就从攻击者可控的内层序列化数据开始，`unserialize()` 因而解析攻击者对象并触发反序列化 RCE。

## 原理

- **两套计数语义混用**：`mb_strpos()` 返回 haystack 中 needle 的位置，`mb_substr()` 的 `start` 参数是字符偏移；两者都依赖 mbstring 的内部编码。正常 UTF-8 文本中位置与字符偏移可以对齐，但遇到非法/不完整的多字节序列时，PHP 对“多少个字节算一个字符”的处理在两者之间出现差异。于是 `mb_strpos($data, "[") + 1` 这个数值传给 `mb_substr()` 后，落点并不是 `[` 的下一个字符，而是又向后偏移了若干字符。
- **典型代码**：
  ```php
  $start = mb_strpos($data, "[");
  $end   = mb_strpos($data, "]");
  return mb_substr($data, $start + 1, $end - 1 - $start);
  ```
  这里 `$start`、`$end` 被当作同一坐标系使用，且第三个参数是长度而非结束下标。只要前缀中存在 mbstring 解析不一致的字节，`$start + 1` 在 `mb_substr()` 中就会“多吃”前缀之后的字符。
- **原文实测的偏移表**（针对其测试环境，具体 PHP 版本/编码不同可能有变化，利用前需本地校准）：
  - 每个 `%f0abc`（4 字节的非法序列）：`mb_strpos` 与 `mb_substr` 相差 3 个字符；
  - 每个 `%f0%9fab`：相差 2 个字符；
  - 每个 `%f0%9f%9fa`：相差 1 个字符。
  直接在 `[` 前放一个 `%9f` 时，`mb_strpos` 返回的 `[` 位置变成 0，而 `mb_substr` 把 `%9f` 当作一个字符，截取结果会把 `[` 本身包含进来，说明不是简单的“整体后移一位”，而是两个函数对非法序列的字符边界判断不同。
- **为什么能绕过过滤**：过滤器通常写成 `preg_match("/\[|\]/i", $input)`，只拦截字面量 `[`、`]`。`%f0abc` 等序列解码后是非法 UTF-8 字节，不含方括号，能通过正则；但它们在 mbstring 的偏移计算中产生可控的“吞字符”效果。
- **为什么能注入序列化数据**：应用先拼接 `$prefix . "[" . serialize($obj) . "]"`，再调用上述截取函数。序列化外层有固定长度的头部（例如 `O:6:"Hacker":3:{s:5:"start";s:216:"{{{` 共 38 个字符），而攻击者可控的内容紧跟在 `{{{` 之后。让 N=38，`mb_substr()` 的起点就跳过整个外层头，截取结果以内层序列化值（如 `a:2:{...}`）开头；随后 `unserialize()` 把内层值当作顶层数据解析，攻击者对象图中的魔术方法链（示例中嵌套 `C`→`T`→`F`→`E`→`R`，最终 `r=system("ls /")`）被触发，形成 RCE。
- **本质**：这是一类“解析器差异/字符边界差异”问题，而不是序列化格式本身的缺陷；与 `str_replace` 改变长度导致的字符逃逸类似，都是让“长度/偏移的声明”和“实际解析”脱钩。

## 触发条件

- 代码使用 `mb_strpos()` 查找 `[`/`]`，并把结果直接作为 `mb_substr()` 的 `start`/长度参数；常见于“截取两个分隔符之间内容”的自定义函数。
- 攻击者能控制分隔符之前的前缀，且输入在 URL 解码后允许出现任意字节（PHP 的 `$_GET`/`$_POST` 默认会解码 `%f0` 等）。
- 过滤只检查字面量方括号或常见关键字，没有拒绝非法 UTF-8；`mb_check_encoding()` 未被调用。
- 截取结果会被送入 `unserialize()`（或其他对格式敏感、可被字符偏移影响的解析器）。
- 目标 PHP 启用了 mbstring 扩展，且内部编码为 UTF-8 等多字节编码；不同 PHP 版本对非法序列的处理可能不同，需实测偏移表。
- 若目标是 RCE，还需存在可用的 gadget 链或 `__destruct`/`__wakeup`/`__toString` 等魔术方法 sink；示例题依赖题目自带的类链。

## 利用步骤

1. **确认 sink**：审计源码，定位 `mb_strpos($data, "[")` + `mb_substr($data, $start + 1, ...)` 后接 `unserialize()` 的调用链；确认 `[`/`]` 是代码拼接进去的，攻击者只控制前缀或某个字段。
2. **确认过滤**：检查 `preg_match("/\[|\]/i", $prefix)` 之类的规则是否只拦截字面量方括号；确认参数经过 URL 解码后能携带非法 UTF-8 字节。
3. **测量偏移**：在目标 PHP 版本上构造只含非法序列的前缀，利用页面回显的 `$start`、`$end` 或自行写最小脚本，测出每种序列让 `mb_substr()` 多吃多少字符；原文给出的表为 `%f0abc`=3、`%f0%9fab`=2、`%f0%9f%9fa`=1。
4. **计算需要跳过的长度**：数出从 `[` 之后到攻击者可控字段开头的字符数。示例中为 `O:6:"Hacker":3:{s:5:"start";s:216:"{{{`，共 38 个字符。
5. **组合前缀**：用偏移量拼出目标长度，例如 12 个 `%f0abc`（12×3=36）加 1 个 `%f0%9fab`（+2）共 38；前缀中不能出现 `[`、`]`，否则会被正则拦截或改变 `mb_strpos` 的定位。
6. **构造内层序列化值**：把攻击者对象图序列化后放在可控字段中，使外层 `serialize()` 的字符串长度与实际内容一致；示例内层为 `a:2:{i:1;O:6:"Hacker":3:{...};i:2;N;}`，其中嵌套对象的魔术方法最终调用 `system("ls /")`。
7. **提交**：发送 `substr=<前缀>` 与承载内层序列化值的参数；截取函数跳过 38 字符后返回内层值，`unserialize()` 触发 gadget 链，命令执行结果随异常/析构输出返回。

## PoC

前缀（URL 编码，12 个 `%f0abc` 加 1 个 `%f0%9fab`）：

```text
%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0%9fab
```

对应的请求形态（内层 payload 为示意，实际需按目标类链替换）：

```http
GET /index.php?substr=%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0%9fab&ez_ser.from_you=a%3A2%3A%7Bi%3A1%3BO%3A6%3A%22Hacker%22%3A3%3A%7B...%7Di%3A2%3BN%3B%7D HTTP/1.1
Host: target
```

漏洞函数的最小形态（用于识别，不是完整挑战代码）：

```php
function substrstr($data) {
    $start = mb_strpos($data, "[");
    $end   = mb_strpos($data, "]");
    return mb_substr($data, $start + 1, $end - 1 - $start);
}
$pre = $_GET['substr'];              // 只过滤字面量 [ ]
$ser = $pre . "[" . serialize($obj) . "]";
$a   = unserialize(substrstr($ser));
```

原文截图显示该 payload 触发 `system("ls /")`，响应中出现 `bin dev etc flag ...` 等目录项；未在本机复跑，且原文的偏移算术存在笔误（文中一处把 `%f0%9fab` 写成 `%f0%9ab`），实际利用应以目标环境实测偏移为准。

## 变体与关联

- 变体：把 `%f0abc` 换成其他能产生 1/2/3 字符差值的非法 UTF-8 序列，按需要的跳过长度组合；也可利用 `%9f` 让截取结果包含分隔符本身。
- 变体：把 `unserialize()` 换成 `include`、`eval`、JSON 解析或自定义协议解析，只要攻击者能让截取起点落在自己控制的数据上，都可能形成注入。
- 关联：`str_replace` 变长/变短造成的同族字符逃逸，见 [[web-php-deserialization-str-replace-length-shortening-escape]]、[[web-php-deserialization-str-replace-length-lengthening-pop-eval]]、[[web-php-deserialization-char-escape-pop-dbctrl-sqli]]。
- 关联：序列化过滤器只匹配小写 `s` 时用大写 `S` 十六进制转义绕过，见 [[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]；`S` 十六进制属性值绕过字母黑名单，见 [[web-php-deserialization-s-hex-letter-blacklist-eval]]。
- 关联：`serialize`/`unserialize` 尾部空格差异与重复键 GC 触发析构，见 [[web-php-deserialization-ez-uns-trailing-space-gc-php-filter-traversal]]。

## 检测与防御

- **静态审计**：搜索 `mb_strpos` 与 `mb_substr` 的组合，重点关注“`mb_strpos` 的结果直接加 1 作为 `mb_substr` 的 `start`”“长度由两个 `mb_strpos` 结果相减”的代码，以及其后紧跟 `unserialize`/`include`/`eval` 的调用点。
- **输入检测**：请求参数中出现非法 UTF-8 序列（如 `%f0` 开头但后续不是合法 4 字节序列、孤立 `%9f`、重复的 `%f0abc`）且参数值中不含字面量方括号时，应提高告警；结合“参数长度与实际可见字符数不一致”“同一前缀重复多次”等特征。
- **运行时**：对 `mb_strpos` 回显位置、`unserialize` 调用做审计日志；在 WAF 中同时拦截非法 UTF-8 和反序列化特征，不要只拦截 `[`/`]`。
- **修复**：对字节串使用 `strpos`/`substr`（按字节计数）并保持同一坐标系；若必须使用 mbstring，先 `mb_check_encoding($input, 'UTF-8')` 拒绝非法序列，并在 `mb_substr` 中显式传入与 `mb_strpos` 相同的编码；不要用“找分隔符再截取”的方式解析不受信任的结构。
- **根因缓解**：不要对用户可控数据直接 `unserialize`；使用 `unserialize($data, ['allowed_classes' => [...]])` 白名单或改用 JSON；对序列化数据做完整性签名，禁止在拼接后再做字符级截取。
- **版本注意**：mbstring 对非法序列的行为随 PHP 版本变化，修复后应使用多组非法字节做回归测试，不能只验证合法 UTF-8。
