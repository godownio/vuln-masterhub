---
id: web-php-deserialization-s-hex-letter-blacklist-eval
title: PHP 反序列化 S 十六进制转义绕过属性值字母黑名单执行 passthru
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-s-hex-letter-filter-bypass
tags:
- php
- deserialization
- filter-bypass
- hex-escape
- eval
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T17:01:51+08:00'
  notes: 已对照原文过滤属性关键字段落与图02核对：S:18十六进制转义解码为passthru('dir /');（逐字节复算18字节）、O:8:"passthru"结构与eval(->S) sink一致；原文check.php正则未展示，卡内已标注过滤规则为原文描述推断；无sources/source_url；未在本机复跑
url: /docs/web/php/deserialization/web-php-deserialization-s-hex-letter-blacklist-eval/
draft: false
kb_aliases:
- S 十六进制转义
- 属性值不能含字母
- passthru 类
- eval($this->S)
- 字母黑名单绕过
- \70\61\73\73
---

## 一句话结论

当过滤只允许某个属性值由数字和符号组成、禁止出现字母时，可把要执行的 PHP 代码（如 `passthru('dir /');`）全部写成大写 `S` 字符串的 `\xx` 十六进制转义，原始 payload 中该值不含任何字母，`unserialize()` 解码后仍还原成可执行代码，由 `__destruct()` 中的 `eval($this->S)` 执行。

## 原理

- PHP 序列化支持两种字符串类型：小写 `s:<len>:"..."` 普通字符串；大写 `S:<len>:"..."` 带十六进制转义的字符串，`\70`、`\61` 等会被还原为对应字节。
- `S` 的 `<len>` 写的是**解码后**的字节数，不是转义文本长度。例如 `passthru('dir /');` 为 18 字节，写作 `S:18:"\70\61\73\73\74\68\72\75\28\27\64\69\72\20/\27\29;"`（其中 `\29` 后的 `;` 位于引号内，也是内容的一部分）。
- 如果应用的过滤器只检查属性值字符集（例如“只能包含数字或符号、不能包含字母”），转义文本 `\70\61...` 只由反斜杠和数字构成，能通过检查；但 `unserialize()` 按 `S` 语义解码后得到完整的 `passthru('dir /');`。
- 目标类 `passthru` 的 `__destruct()` 执行 `eval($this->S)`，解码后的字符串被当作 PHP 代码执行，`passthru('dir /')` 调用系统命令；类名与函数名相同只是巧合，eval 内实际调用的是全局函数 `passthru`。
- 该技巧同样适用于任何“只检查序列化文本字面量”的过滤器：过滤器看到的是转义形态，引擎看到的是解码结果，两者语义不一致。

## 触发条件

- 应用对用户输入调用 `unserialize()`，且允许实例化目标类（无白名单或白名单包含该类）。
- 存在把用户可控属性传给 `eval`/`assert`/动态函数调用的 sink（本题是 `__destruct` 中的 `eval($this->S)`）。
- 过滤器检查的是属性值中的字母/关键字，而不是解码后的语义；且没有规范化序列化格式。
- 目标 PHP 支持 `S` 十六进制转义字符串（PHP 5/7/8 的 `unserialize` 均支持）。

## 利用步骤

1. 审计源码，确认过滤器检查哪个属性、字符集规则是什么，以及 sink 是否为 `eval`。
2. 把要执行的 PHP 代码（函数名、引号、空格、分号）逐字节写成 `\xx` 十六进制转义，确保转义文本中不含被禁字母。
3. 统计解码后的字节数，写成 `S:<解码长度>:"<转义文本>";`。
4. 构造对象 payload（本题 `O:8:"passthru":2:{s:1:"S";S:18:"...";s:3:"dir";N;}`），必要时 URL 编码。
5. 提交后对象析构触发 `eval`，观察命令回显。

## PoC

```text
O:8:"passthru":2:{s:1:"S";S:18:"\70\61\73\73\74\68\72\75\28\27\64\69\72\20/\27\29;";s:3:"dir";N;}
```

解码过程：

```text
\70\61\73\73\74\68\72\75  -> passthru
\28                       -> (
\27\64\69\72\20/\27       -> 'dir /'
\29;                      -> );
```

解码结果 `passthru('dir /');` 由 `eval($this->S)` 执行。原文中的过滤规则为“属性 S 不能含有字母，只能是数字或符号”，payload 的 S 值只含 `\` 与数字，因此通过检查；原文未在本机复跑。

## 变体与关联

- 编码变体：可编码任意函数调用/代码片段；若过滤器同时禁用反斜杠，可考虑其他等价序列化写法（`C:` 包装、引用等），见 [[web-php-deserialization-c-prefix-arrayobject-bypass]]。
- 过滤器差异变体：只匹配小写 `s:` 的正则可用大写 `S` 绕过，见 [[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]；Session 反序列化中的 `S` 转义见 [[web-php-deserialization-session-s-hex-escape-admin-forge]]。
- sink 变体：`eval`、`assert`、`call_user_func`、动态函数名调用；只要最终把解码后的值当代码/命令执行即可。
- 边界：若过滤器在解码后做语义检查、或使用 `allowed_classes` 禁止目标类，路径失效。

## 检测与防御

- 检测：请求参数中出现大写 `S:` 与大量 `\xx` 转义；序列化串声明长度与原始文本长度不一致；反序列化后出现 `eval`/命令执行。
- 修复：不要对序列化文本做字符集/正则黑名单；使用 `unserialize($data, ['allowed_classes' => [...]])` 限制可实例化类，或改用 JSON。
- 加固：移除 `__destruct`/`__wakeup` 中的 `eval` 与动态调用；对进入 sink 的字符串做解码后的白名单校验。
