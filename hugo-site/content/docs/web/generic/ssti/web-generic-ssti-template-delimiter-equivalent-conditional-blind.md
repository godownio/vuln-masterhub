---
id: web-generic-ssti-template-delimiter-equivalent-conditional-blind
title: 模板引擎定界符变体与条件盲注：禁用 $ 后 ~ 仍可解析（读解析器源码找等价字符），if+正则做逐字符 oracle
type: scenario
domain: web
path: web/generic/ssti
technique: template-delimiter-equivalent-char-conditional-blind-injection
tags:
- ssti
- template
- delimiter
- waf-bypass
- blind-injection
- oracle
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:59:06+08:00'
  notes: 已对照原文与图01/02/03核对：chunk-templates解析器源码 if (firstChar == '$' || firstChar == '~') 同时接受$与~（图03），应用preventRecursiveTags只replace("$","")（图02）故$被ban后{~flag}仍可解析（图01模板为${name}/${color}语法）；if+正则盲注payload {{% if(flag=~/^.../) %}}{test}{{% endif %}}与原文一致，.htaccess If+ErrorDocument 404 "wupco"同oracle思路已注明为另一载体并关联既有卡。confidence medium（案例为CTF、语法依引擎实现）合理。未复现：无该CTF环境。dedup无同链候选（Twig过滤器、Mako/Jinja盲注、SQLi oracle等均不同载体）；dup-scan无本片配对。
url: /docs/web/generic/ssti/web-generic-ssti-template-delimiter-equivalent-conditional-blind/
draft: false
kb_aliases:
- chunk-templates 定界符绕过
- $ 被 ban 用 ~
- 模板解析器等价字符
- 模板 if 正则盲注
- 模板语法 oracle
- 解析标识绕过
---

## 一句话结论

模板引擎的“解析标识”往往不止文档里那一种：chunk-templates 类引擎的解析器源码用 `if (firstChar == '$' || firstChar == '~')` 同时接受 `$` 与 `~`，应用只过滤 `$` 时用 `{~flag}` 即可继续注入；同理，模板的条件语法（if + 正则匹配）可以当盲注 oracle——反复提交 `if(flag=~ /^已知前缀/)` 并根据可控输出是否出现，逐字符爆破出完整敏感值。

## 原理

- **定界符由解析器实现决定**：模板引擎解析时先看首字符/前缀判断“这是不是表达式”。文档可能只写 `${...}`，但解析器可能兼容多个等价字符（如 `$` 与 `~`）、多段语法（`{{ }}`、`{% %}`、`${ }`）或大小写/空白变体。应用层 WAF 若只按文档字符过滤，就会漏掉解析器实际接受的等价写法。
- **读源码找等价字符**：拿到/反编译模板解析器（或对照开源实现），搜索 `firstChar ==`、`startsWith`、`substring(0,2)` 等判断，列出所有被接受的前缀；chunk-templates 的源码判断就是 `firstChar == '$' || firstChar == '~'`，因此 `$` 被替换为空后 `~` 仍进入解析流程。
- **条件语法即 oracle**：模板语言普遍支持 if/elseif + 比较/正则。若模板可控但输出受限（只渲染固定页面），可构造 `if(敏感值 =~ /^猜测前缀/) 显示已知标记 endif`，根据标记是否出现在响应中判断猜测是否正确；逐字符扩展前缀即可盲注出完整值（flag、密钥、配置）。
- **为什么可行**：模板表达式在服务端求值，比较结果影响渲染分支，而响应差异（标记出现/消失、状态码、长度）可被攻击者观测；不需要回显敏感值本身。
- **边界**：需要模板注入点（用户输入成为模板源码/表达式）、引擎支持条件与正则等价语义、以及至少一个可观测的输出差异；若引擎禁用正则/条件或响应完全固定，则需换用其他 oracle（错误、时间）。

## 触发条件

- 应用把用户输入拼进模板源码或模板表达式（SSTI）。
- 存在基于字符/关键字的过滤（如只 ban `$`），但模板解析器接受等价定界符或多个语法形式。
- 模板引擎支持 if/else 与字符串/正则比较，可让渲染结果随条件变化。
- 攻击者可观察响应差异（内容、长度、状态码、时间）。
- 仅用于授权测试。

## 利用步骤

1. 确认模板注入：提交引擎语法（`${7*7}`、`{{7*7}}`、`{% if ... %}`）观察是否求值。
2. 分析过滤与解析器：尝试被禁字符的等价物（`$`→`~`、`{{`→`{%`、大小写/空白/编码变体）；有源码/二进制时直接搜首字符判断逻辑，列出全部可用定界符。
3. 构造条件 oracle：提交 `if(目标值 =~ /^猜测前缀/) <标记> endif` 形式，确认条件为真时标记出现、为假时不出现。
4. 逐字符爆破：从已知前缀（如 `flag{`）开始，遍历字符集，保留使标记出现的字符，扩展前缀直到闭合。
5. 若正则被限制，改用字符串比较/长度/包含等条件；若无输出差异，尝试错误信息或时间差异。
6. 记录 payload 与响应差异，复现完整值。

## PoC

```text
# chunk-templates：应用把 $ 过滤为空（preventRecursiveTags 只 replace "$"）
TEMPLATE_HTML = "<p>How are you ${name}?</p><p>${color} is ...</p>"
# 解析器源码实际接受两个首字符：
if (firstChar == '$' || firstChar == '~') { this.leftSide = SnippetTag.parseTag(test); }

# 因此 $ 被 ban 后可改用 ~：
{~flag}
```

```text
# 条件盲注模板（示意）：条件为真才输出 test 标记
{{%/* if(flag =~ /^{{re.escape(guess)}}/) */%}}{test}{{%/* endif */%}}
# 逐字符扩展 guess：响应中出现 {test} 即该字符正确
```

```text
# .htaccess 的同类条件 oracle（另一载体，原理相同）
<If "file('/etc/passwd') =~ /root/">
ErrorDocument 404 "wupco"
</If>
# 404 页面出现 wupco => 条件为真
```

## 变体与关联

- 变体：不同模板引擎的等价定界符不同（`{{`/`{%`、`${`/`#{`、`<%=`/`<%`），以解析器源码为准；也可利用编码（Unicode/URL 编码）让过滤层与解析层看到不同字符串。
- 变体：条件判断可用字符串比较、`contains`、长度、循环次数等替代正则；标记可用页面元素、状态码或响应长度差。
- 变体：.htaccess 的 `<If "file(...) =~ /.../">` + ErrorDocument 是同一 oracle 思路在 Apache 配置层的应用（已有专门卡）。
- 关联：[[web-php-file-inclusion-htaccess-if-errordocument-blind-read]]（.htaccess 条件+ErrorDocument 盲读）、[[web-generic-ssti-twig-filter-map-reduce-callback-rce]]（Twig 过滤器函数调用链）、[[web-generic-ssti-engine-identification-decision-tree-errors]]（先识别引擎再选语法）。

## 检测与防御

- 检测：审计模板解析器接受的定界符/语法全集，过滤规则要覆盖所有等价形式；监控请求中出现多种模板定界符与条件关键字；对响应长度/状态的异常波动告警。
- 防御：禁止用户输入进入模板源码（根本修复）；无法避免时使用沙箱/白名单语法；过滤不能只按文档字符（应从解析器实现出发覆盖全部入口）；统一错误与响应，减少 oracle 差异；敏感值不放在模板可访问的数据中。
- 说明：本文是模板引擎定界符变体与条件盲注 oracle 的技巧（chunk-templates 案例），severity medium、confidence medium（案例来自 CTF，具体语法依引擎实现）；仅用于授权测试。
