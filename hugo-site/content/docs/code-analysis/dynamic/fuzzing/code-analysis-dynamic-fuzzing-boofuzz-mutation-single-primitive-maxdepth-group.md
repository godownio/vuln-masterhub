---
id: code-analysis-dynamic-fuzzing-boofuzz-mutation-single-primitive-maxdepth-group
title: boofuzz 变异粒度：默认一次只变异一个原语，靠 group 与组合变异（max_depth）把覆盖扩展到多字段组合
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: boofuzz-mutation-granularity-group-combination
tags:
- boofuzz
- fuzzing
- protocol-fuzzing
- mutation
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:35:34+08:00'
  notes: 已对照原文核对：Fuzzable.get_mutations 每次迭代只返回含一个 Mutation 的 list、Block.group 时返回 group_mutations+mutations、不传 max_depth 启用组合变异返回 mutations+ms 且 depth 从 1 递增、skip_elements 控制参与原语、render 阶段按 qualified_name 是否在 mutation_context.mutations 决定是否应用变异值，均与正文『结论』三条一致。本次核对未读取图片；正文 23 张截图中源码/调试输出细节未核对，卡内说明限于正文文字明确部分；PoC（s_block+group、fuzz(max_depth=1)）是按正文 group 说明构造的演示代码，非原文原样 PoC。dedup：t2_card 判 duplicate 但 top 为草稿自身（1.000），排除后最高外部候选为同篇互补卡（0.114）与 libFuzzer/AFL 卡（0.050/0.049），非同一条链
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-boofuzz-mutation-single-primitive-maxdepth-group/
draft: false
kb_aliases:
- boofuzz 变异策略
- boofuzz max_depth
- boofuzz group
- boofuzz 组合模糊测试
- boofuzz 一次只变异一个字段
---

## 一句话结论

boofuzz 的 `Request.get_mutations` 每次迭代只产出一个 `Mutation`，即**一轮只对一个原语执行一次生成策略**，其余原语用默认值 render；想让多个字段同时变化，要么给 `Block` 设 `group` 让一组原语同步变异，要么不给 `session.fuzz()` 传 `max_depth` 从而进入组合变异（depth 从 1 递增，depth=n 时同时变异 n 个原语），这正是它能持续跑下去而不很快穷尽的原因。

## 原理

- **单原语变异是结构决定的，不是配置项**：Session 调 `Request.get_mutations()` → `FuzzableBlock.mutations()` 遍历其 stack 上的 Block/Primitive → 元素的 `get_mutations()`（继承自 `Fuzzable`）调用原语自身的 `mutations()`。`Fuzzable.get_mutations` 是迭代器，每次 `yield` 的 list 里只有一个 `Mutation` 对象，`Mutation.value` 是"这一次的值（或函数）"、`qualified_name` 唯一标识原语。所以一轮只有一个字段被换掉。
- **`group` 是显式放宽粒度**：Block 的 `group` 属性让 Block 与其绑定的原语一起变异；此时迭代器返回的是 `group_mutations + mutations`，即 list 里有两个 `Mutation`，同一轮里多个字段同时被替换。这是"必须成对变化才有效"的字段（长度字段 + 内容字段、键 + 值）的标准做法。
- **组合变异解决次数上限**：单原语变异的用例总数是各原语生成策略数量的线性累加，很快就跑完；`session.fuzz()` 不指定 `max_depth`（默认 `None`）时启用组合模糊测试，depth 从 1 开始递增，返回的是 `mutations + ms`——把 depth=n 到 depth=1 的 Mutation list 串起来。depth=n 表示一次同时变异 n 个原语：先让 primitive1 取一个生成值、其余原语把各自生成策略全跑一遍，再让 primitive1 取下一个值，如此遍历组合。`skip_elements` 进一步控制每个 depth 里哪些原语参与变异，避免重复组合。
- **为什么 render 阶段不会"多变异"**：render 时 `Fuzzable.render` 调 `get_value`，只有当原语的 `qualified_name` 出现在 `mutation_context.mutations` 里才应用变异值，否则用默认值。因此"这一轮变异了谁"完全由 MutationContext 决定，不存在意外的多字段联动。
- **实践含义**：默认配置下你要测的"两个字段互相影响才触发"的解析缺陷几乎测不到；反过来说，一上来就开组合变异会让用例数爆炸，需要先用 `group` 精确表达"必须同时变"的字段对，再用 `max_depth` 加宽。

## 触发条件

- 用 boofuzz 定义含多个原语的 Request（`s_simple`、`s_string`、`s_group`、`s_static` 等），并用默认的 `Session.fuzz()` 启动。
- 需要判断"该测单字段还是字段组合"：单字段适合字段级解析缺陷；组合适合长度/校验和/多字段一致性检查类的缺陷。
- 组合变异只在未指定 `max_depth` 时自动启用；显式传 `max_depth=1` 就退回单原语（含 group）行为。

## 利用步骤

1. 列出 Request 里的原语及其生成策略数量（`s_simple` 的 `fuzz_values` 长度、`s_string` 的策略数量等）。
2. 若被测逻辑中存在"必须同时变化"的字段对（如 `Content-Length` 与实际 body、`type` 与 `value`），把它们放进同一个 Block 并设 `group`。
3. 先用 `max_depth=1` 跑一轮，确认单字段变异能触达目标解析分支、无大量超时或鉴权失败。
4. 确认基线可用后，去掉 `max_depth` 让组合变异接管；用 `skip_elements` 排除无需参与组合的原语（如固定头部），控制用例规模。
5. 结合回调维护会话状态（见关联卡），否则组合变异会在大量未登录请求上空转。
6. 观察用例增长率：组合变异下用例数随 depth 与各原语策略数做笛卡尔式增长，需提前估容量与去重策略。

## PoC

```python
from boofuzz import *

s_initialize("pair")
# 同一 Block 内 group 绑定：两个字段会在同一轮同时被替换
with s_block("len_and_body", group="len_and_body"):
    s_static("Content-Length: ")
    s_simple("5", fuzz_values=["0", "1", "9999"], name="clen")
    s_static("\r\n\r\n")
    s_simple("hello", fuzz_values=["", "A" * 100, "hello"], name="body")
s_static("\r\n")

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 8080)))
session.connect(s_get("pair"))
# 第一轮：只测单字段（含 group）
session.fuzz(max_depth=1)
# 第二轮：组合变异，depth 自增，多个原语同时变化
# session.fuzz()
```

```text
判据：max_depth=1 时每轮只有一个 Mutation（group 内为两个）；
去掉 max_depth 后 depth 递增，同一轮内同时变异的原语数量随之增加。
```

## 变体与关联

- 关联：`[[code-analysis-dynamic-fuzzing-boofuzz-stateful-path-callback-session-variables]]`（同一工具的另一半：Paths 与回调如何维持会话状态）。库内其他 fuzz 卡（libFuzzer/AFL/go-fuzz 系列）是覆盖率引导的字节级变异，本卡处理的是"结构化协议字段的变异粒度"，不重叠。
- 边界：`group` 只能表达"固定的一组同时变"，表达不了条件组合；组合变异在字段多时用例数爆炸，实际常配合 `skip_elements`、协议字典与自定义 `mutations()` 裁剪；若原语生成策略本身是无限/随机函数，组合的"遍历完成"语义会失效。
- 与请求生成次数相关的另一个现象：若 `fuzz_values` 已被某个原语穷尽，后续 depth 增加只会在"其余原语"上产生新组合，用例数仍在增长但重复度上升，需要注意去重。

## 检测与防御

- 检测（被测方视角）：同一连接/会话上出现高度相似的请求序列，只有单个或少数几个字段在高频变化（默认单原语变异）；或出现大量字段长度与内容不自洽的请求（组合变异）。
- 防御：协议解析层对每个字段做独立校验并快速失败，避免深度解析后才崩溃；限制单 IP 的请求速率与非正常字段长度；记录畸形请求的字段分布，用于识别结构化 fuzz 而非随机噪声。
