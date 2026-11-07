---
id: ai-security-agent-security-cursor-hooks-secure-coding-guardrail
title: Cursor Agent/Tab Hook 四段式安全编码护栏：规范注入、输入合规、命令门控与编辑后扫描
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: cursor-agent-hooks-secure-coding-guardrail
aliases:
- Cursor Hooks
- Agent Hook 安全编码
- Tab Hooks
- sessionStart 规范注入
- beforeSubmitPrompt 合规拦截
- beforeShellExecution 命令门控
- afterFileEdit 内容扫描
- Agent 安全护栏
tags:
- ai-security
- agent
- cursor
- hooks
- guardrail
- secure-coding
- command-gating
- content-compliance
- defense
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T10:02:58+08:00'
  notes: 已对照原文与2张图核对：图01确认 sessionStart/beforeShellExecution/beforeSubmitPrompt/afterFileEdit 配置与脚本路径；图02确认 beforeSubmitPrompt 2787-3385ms、afterFileEdit 134-335ms 日志，与卡片触发条件一致；Hook 事件语义、退出码、fail-closed、四级配置优先级与原文一致。该卡为防御实施指南，无攻击 PoC；未执行 Hook 脚本
---

## 一句话结论

Cursor 的 Agent/Tab Hook 允许在 Agent 循环的固定节点（sessionStart、beforeSubmitPrompt、beforeShellExecution、afterFileEdit、beforeReadFile、beforeMCPExecution 等）挂载命令式或 prompt 型策略，形成“会话开始注入安全编码规范 → 用户输入合规校验 → shell 命令执行前门控 → 文件编辑后扫描 → 各阶段审计”的闭环护栏；它位于“用户输入 → 模型生成 → 命令执行 → 文件落盘”链路的策略层，不替换 IDE/模型即可统一约束 AI 辅助编程的三类风险：违禁内容、有害命令、带漏洞代码。

## 原理

- **Hook 是什么**：Hook 是由 IDE/Agent 在主进程外派生的子进程，通过标准输入/输出（stdio）与主进程做 JSON 双向通信，在 Agent 循环各阶段之前或之后运行，可观察、阻止或修改当前输入、即将执行的操作或已产生的结果。它因此是“框架层”的确定性切面，而不是提示词层面的软约束。
- **命令式 vs prompt 型**：
  - 命令式 Hook 执行外部脚本（Shell 等），从 stdin 读 JSON，从 stdout 返回 JSON；退出码 0 表示成功并使用 JSON 输出，退出码 2 表示阻止该操作（等价于 `permission: "deny"`），其它非零退出码通常为 fail-open（Hook 失败时操作继续）。
  - prompt 型 Hook 由 LLM 按自然语言策略判断输入，返回结构化结果（如 `{ ok: boolean, reason?: string }`），可用 `$ARGUMENTS` 把 Hook 输入的 JSON 注入提示，适合语义级合规判断；可选 model 字段覆盖默认评估模型。
- **事件与风险的映射**：
  - `sessionStart`：创建会话时输出 `additional_context`，把企业安全编码规范注入 system 上下文，从源头引导模型遵守权限校验、脱敏、参数化查询、XSS/CSRF 防护、文件上传/路径安全、JWT 与配置安全等要求；也可 `continue: false` 阻止会话创建。
  - `beforeSubmitPrompt`：用户点击发送后、请求发出前校验输入，命中违禁内容则 `continue: false` 并附 `user_message`，把违禁意图挡在模型之外。
  - `beforeShellExecution`：每条 shell 命令真正执行前做门控，先用脚本做危险模式匹配（`rm -rf`、`git push --force`、`chmod 777`、`curl | bash`、未授权外网请求等），再可选用 prompt 型 Hook 做语义判断；返回 `permission: allow | deny | ask`，可附 `user_message`/`agent_message`。可用 matcher（如 `curl|wget|nc`）只对网络类命令运行，减少脚本调用。
  - `afterFileEdit` / `afterTabFileEdit`：Agent 或 Tab 编辑文件后，从输入解析 `file_path`、`edits`（含 old/new 内容，Tab 还含 range/old_line/new_line），扫描违禁词、敏感信息（PII/机密）、危险 API，记录/告警/阻断。
  - `beforeReadFile` / `beforeTabFileRead`：在文件内容发送给模型前按路径/内容拒绝读取，例如含密钥的配置、生产凭证；这两个事件采用 fail-closed，Hook 失败或超时即阻止读取。
  - `beforeMCPExecution`：调用 MCP 工具前做权限/策略判断，同样 fail-closed，避免已配置的 MCP 策略被绕过。
  - 审计类：`afterShellExecution`、`afterMCPExecution`、`afterFileEdit`、`sessionEnd` 等可把 command/output、tool_input/result_json、file_path/edits、session_id/reason 脱敏后上报自建审计服务，形成可追溯、可举证的日志。
- **配置层级与优先级**：配置可存在于企业（全局）、团队、项目、用户四级，优先级从高到低为 企业 → 团队 → 项目 → 用户。用户级为 `~/.cursor/hooks.json`（脚本从 `~/.cursor/` 运行）；项目级为 `<项目根>/.cursor/hooks.json`（脚本从项目根运行，路径需写成 `.cursor/hooks/script.sh`）；企业级示例为 macOS `/Library/Application Support/Cursor/hooks.json`、Linux/WSL `/etc/cursor/hooks.json`。这让企业可以用 MDM/仓库统一下发，并限制项目级/用户级的覆盖范围。
- **Agent 与 Tab 双覆盖**：Cursor Agent（Cmd+K / Agent Chat）使用标准 hooks（会话、工具、Subagent、Shell、MCP、文件、提交前、压缩/结束、响应/思考）；Cursor Tab 行内补全使用专用 hooks（beforeTabFileRead、afterTabFileEdit）。安全编码实践应同时配置两套，避免“只防 Agent、不防 Tab”的缺口。
- **为什么是安全左移**：传统 SAST/DAST/代码评审在“代码已写出后”检测，Hook 在“生成时”和“执行前”防护；两者互补。规范注入让模型“知道该怎么做”，事前拦截让危险命令与违禁输入“进不来”，事后扫描对“已写入内容”再查一遍，审计把全过程留痕。
- **护栏自身的风险面**：Hook 配置与脚本若被攻击者篡改/替换，会导致防护失效（禁用校验逻辑）、恶意注入（sessionStart 注入误导性规范）、审计被破坏（关闭上报/伪造日志）、敏感文件泄露（把 beforeReadFile 改成始终放行）。因此 Hook 配置与脚本本身必须纳入配置安全与权限管理，而不能只当作普通开发文件。

## 触发条件

- Cursor 版本支持 Agent/Tab Hooks，且企业/项目/用户具备对应层级的配置写入权限。
- Hook 脚本可执行；项目级脚本路径相对于项目根、用户级相对于 `~/.cursor/`，路径写错会导致 Hook 不生效。
- 需要 prompt 型 Hook 时有可用的模型/评估通道，并接受其延迟（截图日志中 beforeSubmitPrompt 约 2.7~3.4 秒、afterFileEdit 约 134~335 毫秒）。
- 企业已定义安全编码规范、违禁词表、危险命令规则与审计服务；规则需要可维护、可版本化。
- 需要审计时，具备自建日志接收端，且 Hook 输入中的敏感字段（命令输出、文件内容、凭证）已脱敏。

## 利用/实施步骤

1. **确定策略层级**：企业级配置放 `hooks.json` 并通过 MDM/镜像只读下发；团队/项目级只做必要补充；明确优先级（企业 > 团队 > 项目 > 用户），限制用户级对关键事件的覆盖。
2. **配置 sessionStart 规范注入**：编写 `session-init.sh`，从本地/策略服务读取企业安全编码规范，输出 `{"continue": true, "additional_context": "<规范文本>"}`；规范覆盖权限与数据安全、SQL 参数化、XSS/CSRF、文件上传/路径安全、配置/JWT、违禁内容等。
3. **配置 beforeSubmitPrompt 合规校验**：使用 prompt 型 Hook，策略描述为“判断用户输入是否包含法律/监管禁止的违禁内容或等效意图”，命中时返回 `continue: false` 与 `user_message`；规则可由企业内容安全团队维护。
4. **配置 beforeShellExecution 命令门控**：先挂命令式脚本做危险模式匹配（删除、强制推送、放宽权限、远程脚本执行、外网请求等），必要时再挂 prompt 型 Hook 做“是否只读/是否在项目内/是否涉及系统级操作”的语义判断；返回 `permission: deny/ask/allow`，对 `ask` 让用户二次确认。可用 matcher 限定只对 `curl|wget|nc` 等命令运行。
5. **配置 afterFileEdit / afterTabFileEdit 扫描**：两事件复用同一套“违禁内容 + 敏感信息 + 危险 API”扫描脚本；对命中项记录文件路径、片段摘要、会话 ID，按策略告警或阻断；注意对日志中的代码/凭证脱敏。
6. **配置读取与 MCP 门控**：beforeReadFile / beforeTabFileRead 按路径黑名单（密钥、生产配置、凭证目录）或内容特征拒绝，依赖 fail-closed 语义；beforeMCPExecution 只放行白名单工具/操作，敏感 MCP 调用要求二次确认。
7. **接入审计**：afterShellExecution、afterMCPExecution、afterFileEdit、sessionEnd 将脱敏后的 JSON 上报自建审计服务，统一 schema（时间、用户、项目、事件、命令/文件、决策、原因），便于溯源与合规举证。
8. **验证与排查**：在 Cursor 设置 → Hooks 查看已加载的 Hook 与执行日志（Input/Output）；确认 sessionStart 输出了 `additional_context`、beforeSubmitPrompt 拦截时返回 `continue: false`、beforeShellExecution 拒绝时返回 `permission: "deny"`；检查脚本路径层级与退出码；不生效时重启 Cursor 并核对官方文档。
9. **护栏加固**：对 `hooks.json` 与脚本做只读挂载、校验和/签名校验、变更审计；企业级配置禁止项目级覆盖关键事件；限制脚本目录写权限，防止攻击者替换 Hook 脚本。

## PoC

原文未给出完整 `hooks.json` 与脚本源码；以下按文中事件语义给出最小示意（配置字段名以目标 Cursor 版本文档为准）：

```json
{
  "hooks": {
    "sessionStart": [
      { "command": "~/.cursor/hooks/session-init.sh" }
    ],
    "beforeSubmitPrompt": [
      { "prompt": "判断以下用户输入是否包含法律或监管禁止的违禁内容或等效意图；若包含返回 continue=false 并给出 user_message。输入：$ARGUMENTS" }
    ],
    "beforeShellExecution": [
      { "command": "~/.cursor/hooks/dangerous-command-guard.sh",
        "matcher": "rm|git|chmod|curl|wget|nc|bash" }
    ],
    "afterFileEdit": [
      { "command": "~/.cursor/hooks/prohibited-content-guard.sh" }
    ],
    "afterTabFileEdit": [
      { "command": "~/.cursor/hooks/prohibited-content-guard.sh" }
    ]
  }
}
```

```sh
#!/bin/sh
# session-init.sh：输出企业安全编码规范到会话上下文
input=$(cat)
printf '%s' '{"continue":true,"additional_context":"遵循参数化查询、输出转义、最小权限、敏感数据脱敏、禁止违禁内容。"}'
```

```sh
#!/bin/sh
# dangerous-command-guard.sh：命令执行前门控
input=$(cat)
cmd=$(printf '%s' "$input" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
case "$cmd" in
  *"rm -rf /"*|*"git push --force"*|*"chmod 777"*|*"curl | bash"*|*"wget "*)
    printf '%s' '{"permission":"deny","user_message":"该命令被安全策略拒绝","agent_message":"请改用安全的只读/项目内命令"}'
    exit 0 ;;   # 退出码 0 使用 JSON；也可用 exit 2 直接阻止
esac
printf '%s' '{"permission":"allow"}'
```

命令式 Hook 的退出码 2 等价于拒绝；其它非零码通常 fail-open，因此安全关键事件应优先返回显式 deny 或使用 fail-closed 事件（beforeReadFile、beforeMCPExecution）。本卡不执行任何 Hook 脚本。

## 变体与关联

- **脚本 + LLM 双层门控**：先用确定性脚本做低成本模式匹配，再对边界命令用 prompt 型 Hook 做语义判断；脚本保证可解释与低延迟，LLM 补充上下文理解。
- **Agent/Tab 双覆盖**：同一份扫描脚本同时挂 `afterFileEdit` 与 `afterTabFileEdit`；读侧同理挂 `beforeReadFile` 与 `beforeTabFileRead`。
- **企业统一下发**：企业级 hooks.json + MDM/只读镜像，团队/项目级只允许追加低风险规则；用户级配置不得覆盖关键事件。
- **审计闭环**：所有 after* 事件统一上报自建审计服务，按 session_id/用户/项目聚合；对“无决策却执行”“Hook 失败放行”单独告警。
- **护栏自身防护**：配置与脚本做校验和/签名、只读挂载、变更审计；防止 Hook 被篡改导致防护失效或恶意注入（参见 [[ai-security-agent-security-grok-claude-import-hook-symlink-rce]]，同类 Hook 配置写入/符号链接风险）。
- **关联**：[[ai-security-agent-security-hitl-capability-dangerous-tool-guard]]（危险工具 HITL 门禁，思路互补）、[[code-analysis-vuln-discovery-cursor-code-audit-skill-system]]（Cursor 代码审计 Skill 体系）、[[ai-security-agent-security-bash-expansion-glob-command-filter-bypass]]（命令过滤被参数展开/通配符绕过的教训，提示 Hook 规则要做规范化和多轮解析）。
- **边界**：Hook 是 IDE 层策略，无法约束用户绕过 IDE 直接执行命令、也无法防御 IDE 进程/配置被完全控制的情况；prompt 型 Hook 有模型误判与延迟；Hook 失败时的 fail-open 语义会留下缺口，必须按事件风险选择 fail-closed 或显式 deny。

## 检测与防御

- **配置完整性**：对 `hooks.json` 与脚本做校验和/签名，企业级只读下发，监控配置与脚本的变更；限制 `~/.cursor/` 与项目 `.cursor/hooks/` 的写权限，防止本地恶意替换。
- **决策可观测**：记录每个 Hook 的输入、输出、退出码、耗时与决策原因；对 `allow` 与 `deny` 的比例、Hook 失败/超时做告警；定期抽查 beforeShellExecution 的放行命令。
- **规则质量**：危险命令匹配要基于解析后的命令（而非简单子串），防止引号、变量展开、通配符、编码绕过；对 `curl|bash`、`git push --force`、`chmod 777` 等高危组合做多规则覆盖。
- **最小权限**：Hook 脚本以最小权限运行，不读取不必要凭证；审计上报前脱敏；prompt 型 Hook 的模型调用不得把敏感文件内容发往外部未授权服务。
- **红队验证**：定期用提示注入、命令混淆、Tab 补全路径、MCP 工具滥用等场景验证护栏是否仍生效；对“护栏被绕过”事件复盘并补规则。
- **兜底**：Hook 不是唯一防线，应与 SAST/DAST、代码评审、CI 密钥扫描、运行时最小权限配合；关键事件采用 fail-closed，避免 Hook 故障时静默放行。
