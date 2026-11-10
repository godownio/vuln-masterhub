---
id: code-analysis-sast-rips-php-token-stream-normalization
title: RIPS v0.55 PHP token 流规范化：token_get_all 后的删除/重写、数组键折叠、控制结构补括号与三元裁剪
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: rips-php-token-stream-normalization
aliases:
- RIPS token 解析
- RIPS prepare_tokens
- array_reconstruct_tokens
- fix_tokens
- fix_ternary
- PHP token 流重构
- PHP 静态分析词法预处理
tags:
- php
- sast
- rips
- token
- static-analysis
- code-audit
- ast
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V352
  verified_at: '2026-11-09T00:46:34+08:00'
  notes: 已对照原文全文与61张本地图核对：Scanner 构造 new Tokenizer+implode(lines) tokenize（图01）、token_get_all→prepare_tokens→array_reconstruct_tokens→fix_tokens→fix_ternary（图02）、prepare 的删 T_IGNORE/闭合标签转分号/<?=转echo/删@/数组花括号转方括号（图04-05）、键折叠进 tokens[i][3] 与 MAX_ARRAY_KEYS=10（图06-10）、fix_tokens 反引号/补花括号/替代语法/switch-case-default/函数名小写/do-while重排（图11-13）、fix_ternary 及 1==a() 残留 1==（图13 与正文）、auto_prepend/append_file 的 add_auto_include 前插后插（图15-16）均一致。工具版本非受影响组件版本，未设 affected_versions 符合同类 SAST 工具卡惯例。无 PoC 已注明；frontmatter 无 sources/source_url；dup-scan(19:10)早于本批建卡无涉及 pair。注：正文另有4张 xzfile.aliyuncs.com 外链图未落在 img 目录，其内容为源码/调试截图，正文文字已覆盖，未影响核对。
---

## 一句话结论

RIPS v0.55 的源码扫描不是直接解析 PHP 语法树，而是先用 Zend 的 `token_get_all()` 取 token 流，再经四步规范化——`prepare_tokens` 删无关 token 并重写特殊 token、`array_reconstruct_tokens` 把多维数组键折叠进变量 token 的第四个元素、`fix_tokens` 给无花括号控制结构补括号并把 do-while 改写成 while、`fix_ternary` 剔除三元表达式条件——把语义等价但写法各异的 PHP 统一成后续污点扫描可直接消费的 token 序列。

## 原理

- **总入口**：`Scanner` 构造时 `new Tokenizer($this->file_pointer)`，对 `implode('', $this->lines_pointer)` 调 `tokenize()`；`Tokenizer::tokenize` 依次执行 `token_get_all` → `prepare_tokens` → `array_reconstruct_tokens` → `fix_tokens` → `fix_ternary`，返回规范化 token 数组（每个 token 为 `[token_id, 值, 行号]`）。`ini_get('auto_prepend_file')`/`auto_append_file` 还会被 `add_auto_include` 转成 `require '<文件>';` 的 token，分别前插/后插到 token 流，模拟 PHP 运行时自动包含。
- **prepare_tokens（删除与重写）**：
  - 删除 `Tokens::$T_IGNORE` 中的 token（空白、`<?php` 开标签等），使 `if ()` 变成 `if()` 便于条件解析；`if(): ... endif`/`while(): ... endwhile` 中间的替换语法文本也按需清理。
  - `T_CLOSE_TAG`（`?>`）统一改写为 `;`；`T_OPEN_TAG_WITH_ECHO`（`<?=`）的值改写为 `echo`。
  - 删除错误抑制符 `@`（避免干扰相邻 token 处理）。
  - 把 PHP 旧式数组下标 `$array{index}` 改写为 `$array[index]`：当 `{` 的前一个 token 是变量或 `]` 时，向后找到配对的 `}`，把两侧花括号都替换成方括号。
- **array_reconstruct_tokens（数组键折叠）**：对 `T_VARIABLE` 且下一个 token 为 `[` 的变量，把各维键存进该 token 的第四个元素 `tokens[i][3]`：常量键（`T_CONSTANT_ENCAPSED_STRING`/`T_LNUMBER`/`T_NUM_STRING`/`T_STRING`）直接保存为字符串；变量键则把它对应的 token 子数组保存下来，供后续 `get_tokens_value` 回溯。最多处理 `MAX_ARRAY_KEYS=10` 维；处理完 unset 掉括号与键 token 并重建索引。这样 `$a = $_GET['x']`、`$a[$b][$c]` 在后续扫描中都以“变量 + 键信息”的单一形态出现。
- **fix_tokens（控制结构归一）**：反引号 `` `xxx` `` 改写为 `backticks(xxx)`；`if/elseif/for/foreach/while` 只有单条语句时补花括号；替代语法（`if(): ... endif;`）把 `:` 到结束标记之间包进花括号；`else` 无花括号时按单条语句补；`switch(): ... endswitch`、`case`/`default` 无花括号时补；函数定义与函数调用名统一转小写（PHP 函数名不区分大小写）；`do { ... } while(cond);` 重排成 `while(cond) { ... }`（条件先于循环体，便于解析）。
- **fix_ternary（三元裁剪）**：对每个 `?`，把其前面的判断条件删除，只保留 `?` 后的两个取值分支；分别处理 `(...) ?`（回退 unset 到左括号，左括号前是 `!`/`T_STRING`/`T_EMPTY`/`T_ISSET` 时一并删）、`a()==b ?`（删操作数与运算符）和单变量 `$a ?`。文中明确记录了该实现的缺陷：`1==a()` 这种“常量在左”的写法匹配不到函数调用分支，会残留 `1==`。
- **为什么这样设计**：RIPS v0.55 是 token 级扫描器而非 AST 解析器，后续 source/sink 回溯依赖“变量 token + 键 + 语句范围”的固定形态；先把语法差异（花括号、替代语法、do-while、三元、数组下标）抹平，扫描逻辑才能只处理少数 token 模式。

## 触发条件

- 分析对象是 RIPS v0.55 开源版源码（`lib/scanner.php`、`lib/tokens.php` 等），或基于其 token 流思路改造 PHP 静态分析工具。
- 目标源码为 PHP；`token_get_all` 能解析即进入规范化流程，语法错误会在各步的配平检查中报错并跳过（如找不到闭合花括号/反引号/括号）。
- 需要理解 RIPS 的误报/漏报来源时（例如三元裁剪缺陷、替代语法重构），适用于复核其扫描结果。

## 利用步骤

1. 读 `Scanner` 构造函数：确认待扫描内容如何按行拼接后交给 `Tokenizer::tokenize`，以及 `auto_prepend_file`/`auto_append_file` 如何被前插/后插。
2. 按 `prepare_tokens` → `array_reconstruct_tokens` → `fix_tokens` → `fix_ternary` 顺序跟踪 token 变化；在每一步后 `print_r($this->tokens)` 对照，理解某段源码最终变成什么形态。
3. 对目标项目构造覆盖性测试文件：无花括号的 if/for/foreach/while、替代语法、do-while、三元表达式、`$a[$b][$c]`、反引号、`<?=`、`$array{idx}`，观察规范化结果。
4. 依据规范化后的 token 形态解释 RIPS 的扫描行为：数组键为何出现在变量 token 的第四元素、函数名为何统一小写、三元条件为何消失。
5. 若要扩展/修复 RIPS，优先在这些重构函数上补充语法分支（如修复常量在左的比较、补充新语法），再谈 source/sink 规则。

## PoC

无 PoC（源码走读与工具改造方法）。可用最小脚本对照 token 规范化前后的差异：

```php
<?php
// 观察 PHP 原生 token 流的起点
print_r(token_get_all('<?php $a[$b][$b]=1; if($a) echo 1; ?>'));
```

说明：上面的 `token_get_all` 输出只是原始 token；RIPS 的四步规范化在 `Tokenizer` 内部完成，需在 `lib/scanner.php` 对应函数处打断点或插打印观察。

## 变体与关联

- **变体（解析路线）**：RIPS 走 token 级重构，不建 AST；phply/Neo4j 与 CodeQL 走 AST/代码属性图，能表达更复杂的数据流，但对 PHP7+ 语法需要降级或专用前端。
- **已知缺陷**：`fix_ternary` 对 `1==a()` 残留 `1==`；`fix_tokens` 对替代语法的重构若遇到嵌套/异常写法可能配平失败；`array_reconstruct_tokens` 最多 10 维键。这些会转化为扫描漏报或误报。
- **关联**：[[code-analysis-sast-rips-source-sink-taint-scan]]（同工具的 source/sink 与污点回溯，本卡是其前置）、[[code-analysis-sast-phply-neo4j-php-callchain-sink-query]]（PHP AST 调用图路线）、[[code-analysis-sast-ast-chain-depth-escalation-triage]]（扫描结果到可验证漏洞清单的复核方法）。

## 检测与防御

- **使用者视角**：理解 token 规范化能解释 RIPS 结果中的行号/代码片段为何与源码写法不完全一致；对三元、替代语法、复杂数组下标处的告警要人工复核。
- **工具改进**：为 `fix_ternary` 补齐常量在左的比较与嵌套三元；为 `fix_tokens` 增加新语法分支；用测试集回归每次改动，避免规范化本身引入漏报。
- **防御侧**：SAST 工具应尽量基于 AST/数据流而非纯 token 启发式；无论哪种实现，扫描结果都需要人工确认 source 可控性与净化函数上下文（如 `htmlspecialchars` 在 HTML 属性/onclick 中的局限）。
- **边界**：RIPS v0.55 较老，PHP7/8 新语法支持有限；对现代 PHP 项目建议配合 CodeQL/phply 或商业工具交叉验证。
