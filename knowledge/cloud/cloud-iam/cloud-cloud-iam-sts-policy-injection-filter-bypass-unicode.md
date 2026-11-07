---
id: cloud-cloud-iam-sts-policy-injection-filter-bypass-unicode
title: STS Policy 注入黑名单绕过：字符串双写与 JSON Unicode 转义恢复被过滤的 Action/通配符
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: sts-policy-injection-filter-bypass
aliases:
- Policy 注入修复绕过
- ActActionion 双写
- \u002a 通配符绕过
- Action Unicode 转义
- JSON Unicode 转义绕过
- strings.ReplaceAll 黑名单绕过
- STS 注入二次绕过
tags:
- cloud
- sts
- policy-injection
- filter-bypass
- unicode
- json
- blacklist
- waf-bypass
- double-write
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:23:01+08:00'
  notes: 已通读全文并逐张查看50张图。核对：weakSanitize 用 strings.ReplaceAll 删 *、Action、{、}（图47）；AI 示例与 fix 讨论（图46/47）；Unicode 侧图48 \u0066a 解码为 fa 被报 Invalid action format，图49/50 \u002a 被云控制台接受、策略显示 452/452；阿里云大写 \u0041ction/\u0052esource、腾讯云小写 \u0061ction/\u0072esource 与原文一致。修正：原文/初稿的双写示例 ActACtionion 删掉 Action 后并不会还原（大小写 C 不匹配），已改为 ActActionion（Act+Action+ion，删除中间 Action 后剩 Action），并同步修正检测特征与嵌套说明。未验证点：双写部分原文仅提思路、无云侧验证，故 confidence medium 保留；Unicode 部分有控制台截图；PoC 未在本机执行；无版本区间。frontmatter 无 sources/source_url。
---

## 一句话结论

当修复只是在拼接前用 `strings.ReplaceAll` 删除 `*`、`Action`、`{`、`}` 等黑名单 token 时，攻击者可用“删一个还剩一个”的双写（`ActActionion`、`{{`）或 JSON Unicode 转义（`\u002a`、`\u0041ction`、`\u0052esource`）让被过滤的字符/字段名在替换后或 JSON 解析后重新出现，从而继续完成 STS Policy 注入。

## 原理

- **黑名单替换不是解析器感知的净化**：`weakSanitize` 这类实现逐个 token 做 `strings.ReplaceAll(input, token, "")`。它只保证“处理后的字符串不含这个子串”，不保证“JSON 解析后的语义不含这个 token”。
- **双写绕过**：删除是一次性的、从左到右的子串替换。`ActActionion` 删掉中间的 `Action` 后，前后残片会拼成 `Action`；`{{` 删掉一个 `{` 后仍留下一个 `{`。攻击者用“多写一份”抵消过滤器的删除。
- **JSON Unicode 转义绕过**：JSON 标准允许用 `\uXXXX` 表示字符，解析器会在语法解析阶段把它还原。过滤器在原始字符串上匹配 `*` 或 `Action`，看不到 `\u002a` / `\u0041ction`；等字符串进入 JSON 解析器，`\u002a` 变成 `*`、`\u0041ction` 变成 `Action`、`\u0052esource` 变成 `Resource`，注入语义重新成立。
- **绕过成立的顺序条件**：净化必须发生在 JSON 解析之前（绝大多数“拼接前过滤”的实现都是如此）。如果应用先把 JSON 解码成对象、再对解码后的字段值做白名单，Unicode 字符已被还原，此路不通；但双写类问题仍取决于过滤实现。
- **云侧行为**：原文在云控制台验证了 `Action: "\u002a"` 能被接受；而 `Action: "\u0066a"` 解码后是 `fa`，不是合法 Action，被拒绝为 `Invalid action format`。这说明云厂商按 JSON 解码后的语义校验，转义只在“过滤”和“解析”之间形成盲区。
- **与主卡的关系**：本卡是 [[cloud-cloud-iam-sts-policy-injection-object-key]] 的二次利用阶段；漏洞根因仍是用户值进入 Policy 语法，只是修复层引入了可绕过的黑名单。

## 触发条件

- 应用仍使用字符串拼接生成 `AssumeRole` 会话 Policy，只是在拼接前加了黑名单替换。
- 过滤 token 是字面量（如 `*`、`Action`、`{`、`}`），未做 JSON 解析后的语义校验，也未使用结构化序列化。
- 过滤发生在 JSON 解析之前；云 STS 接受 `\uXXXX` 转义和/或重复键/多 Statement 结构。
- 原始模板的闭合引号仍保留，payload 能补齐 JSON 尾部。
- 阿里云需注意字段大小写 `Action`/`Resource`；腾讯云为 `action`/`resource`，且拒绝重复键，需要新增 Statement。

## 利用步骤

1. 先按主卡确认基础 Policy 注入可用，再观察修复后的行为：提交含 `*`、`Action`、`{`、`}` 的 payload，判断是报错、被替换还是被拒绝。
2. 推断过滤 token 与过滤时机（替换为空、报错、还是 JSON 解析后校验）。
3. 双写尝试：把 `Action` 写成 `ActActionion`，把 `{` 写成 `{{`，观察删除后是否还原出目标 token。
4. Unicode 尝试：把 `*` 写成 `\u002a`，把字段名写成 `"\u0041ction"` / `"\u0052esource"`（腾讯云用小写 `\u0061ction` / `\u0072esource`）。
5. 保留闭合原 Resource 字符串的 `"`，发送请求，检查返回的 Policy / statementCount 与临时凭据权限。
6. 用 STS 调对象存储 SDK 验证列桶、覆盖、删除；若仍失败，检查是否被解析后白名单或角色上限拦截。

## PoC

阿里云（大写字段名）：

```text
uploads/alice/x.txt"],"\u0041ction":["\u002a"],"\u0052esource":["\u002a
```

腾讯云（小写字段名）：

```text
uploads/alice/x.txt"],"\u0061ction":["\u002a"],"\u0072esource":["\u002a
```

双写思路（针对 `strings.ReplaceAll` 删除 `Action` / `{`）：

```text
Action  -> ActActionion
{       -> {{
```

被过滤后的还原示意：

```text
ActActionion --删除 "Action"--> Action
{{           --删除 "{"------> {
```

说明：Unicode 转义在原文中已通过云控制台验证（`\u002a` 被接受）；双写部分原文作为思路提出，未给出同等的完整握手/云侧验证，故本卡 confidence 记 medium。以上均未在本会话执行，payload 需按目标模板尾部调整。

## 变体与关联

- 变体（大小写混合）：字段名首字母用 `\u0041ction` / `\u0061ction`、`\u0052esource` / `\u0072esource`，适配不同云的字段大小写。
- 变体（部分转义）：只转义通配符 `\u002a`，字段名保持明文，适用于过滤只盯 `*` 的实现；反之亦然。
- 变体（双写/嵌套）：针对替换后拼接的 token，可重复包裹（如 `ActActionion`）；更深的嵌套只有在替换循环执行时才会再次还原，需按过滤器实现验证，也可与其他空白/转义技巧组合。
- 变体（结构差异）：阿里云重复键覆盖；腾讯云新增 Statement；换云时需重新确认字段大小写、Resource 格式、重复键是否接受、`Resource:["*"]` 是否接受。
- 关联：[[cloud-cloud-iam-sts-policy-injection-object-key]]（主漏洞与完整越权链）。
- 边界：净化在 JSON 解析之后进行、使用结构化序列化（不会把用户值当键）、或对 Key 做严格字符白名单时，本绕过不成立；`fa` 这类解码后非法的 Action 会被云侧拒绝，转义必须还原成合法语义。

## 检测与防御

- 检测：STS 请求体/参数中出现 `*`、`Action`、`Resource`、`ActActionion`、`{{` 等组合；Policy 中字段名带转义；同一来源反复提交结构字符与通配符。
- 检测：返回的 Policy/临时凭据权限突然从单对象扩大到桶级；云侧 `Invalid action format` 与成功请求交替出现，像是过滤器探测。
- 防御（根因）：不要用黑名单替换修复注入。使用 JSON 序列化或结构化策略构造器，把用户值作为字符串值传入；用户值永远不能成为 JSON 键。
- 防御（正向约束）：对 Object Key 做服务端生成或严格白名单（字符集、长度、前缀、用户归属），拒绝 `"`、`]`、`}`、`{`、`\`、`*` 等结构字符。
- 防御（纵深）：角色权限上限收敛到单 Bucket/单前缀，会话 Policy 只给单对象 PutObject；开启禁止覆盖与版本控制；对 AssumeRole 请求做审计告警。
- 防御（验证）：修复后用主卡与本卡的 payload 回归测试，确认过滤不是“删字符串”，而是“数据不再参与语法”。
