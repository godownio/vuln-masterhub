---
id: ai-security-agent-security-ctf-agent-prompt-pack-runtime-routing
title: CTF/授权渗透 Agent 提示词工程：执行闭环 + 运行时能力盘点 + 题型路由 + 首轮动作 + 证据化输出
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: ctf-agent-prompt-pack-runtime-routing
aliases:
- CTF 强提示词
- Prompt Pack
- 题型路由
- 首轮侦察 5 分钟
- 决策卡与证据块
- Agent 注意力分配
tags:
- ai-security
- agent-security
- prompt-engineering
- ctf
- agent
- runtime
- routing
- evidence
- tool-use
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V143
  verified_at: '2026-11-06T06:01:35+08:00'
  notes: 已对照原文全文核对：五层结构（全局闭环、运行时能力、题型路由、前5分钟固定动作、输出协议）、prompt_pack 目录、build/refresh/test 脚本与协作方式均与原文一致；原文自述提升幅度未科学验证且部分论述来自 GPT-5.5，卡内 confidence=medium 合理。本卡为方法论/流程卡，severity=low，PoC 为提示词片段而非漏洞利用。未验证点：未实际运行该提示词；原文无组件版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

CTF 里真正有效的提示词不是“你是顶级 CTF 选手”的角色扮演，而是一套可执行的 Agent 运行规范：用全局闭环约束行动、用运行时能力清单告诉模型本机有哪些工具与绝对路径、用题型路由限制主/副模块、用各题型前 5 分钟固定动作启动侦察、用决策卡/证据块/结果校验协议强制模型先验证再下结论。

## 原理

- LLM 在 CTF 中“看起来很懂却打不穿”，通常不是缺 SQL 注入/JWT/SSTI 知识，而是缺稳定行动流程：不先识别架构就猜漏洞、不保存证据就把直觉当结论、不调用本机工具只在文字里空转、一条错路堆十轮 payload、拿到疑似 flag 不校验、不知道本机有哪些工具。
- 强提示词应把模型组织成与环境闭环的 Agent，骨架为：目标边界 → 环境能力 → 题型路由 → 首轮侦察 → 最小验证 → 工具调度 → 自动化放大 → 止损切换 → 结果校验 → 复盘输出。
- 三个常见硬伤：
  - 把 CTF 当问答题：诱导模型列漏洞清单，而不先回答“环境是什么、输入点在哪、输出面是什么、成功标准是什么”。
  - 把“多思考”误解成“多说话”：长篇解释不如三个最小验证 payload（正常输入、单引号、布尔恒真/恒假），无稳定差异就止损。
  - 没有设备意识：不说明 shell 类型、工具是否存在、绝对路径、可用 MCP/Skill，模型只会给“你可以安装 Wireshark/jadx”的泛化建议。
- 提示词本质是注意力分配器：CTF 题会制造假 flag、误导字符串、无用页面、错误提示、变形漏洞链；强提示词让模型始终围绕事实、假设、最小验证、最快工具、失败切换和结果校验运行。
- 工程化拆分：`00_policy`（稳定规则/边界/闭环）、`10_runtime.generated`（自动探测的环境事实）、`20_router`（题型识别与模块切换）、`30_output`（决策卡/证据块/结果校验）、`40_machine_tuning`（本机调度偏好）、`modes/`（sprint/deep/max/report）、`modules/`（web/pwn/reverse/crypto/forensics/misc 与 sqli/jwt_auth/ssti_rce/deserialize/race/post_access 等副模块），配合 build/refresh/test 脚本。

## 触发条件

- 使用 LLM/Agent 辅助 CTF、靶场、本地实验或明确授权的渗透测试。
- 能向模型提供运行时事实（工具绝对路径、WSL 发行版、Python 模块、可用 MCP/Skill）。
- 有明确的题型范围（Web/Pwn/Reverse/Crypto/Forensics/Misc）与成功标准（flag/敏感数据/shell）。
- 接受“先最小验证、再自动化放大”的低影响原则，不用于未授权目标。

## 利用步骤

1. **写稳定 policy**：适用边界、默认解题闭环、结果校验、止损切换、输出格式；一句话总纲可写成“基于真实环境，以证据驱动方式，把目标尽快、尽稳、尽深地打穿”。
2. **生成 runtime 事实**：用 `refresh_runtime` 脚本每次启动探测 python/node/git/docker、tshark/hashcat/jadx/adb/7z/sqlmap、WSL 工具、Python 模块；写绝对路径，并声明“工具缺失不阻塞，优先 Python/PowerShell/WSL/自写脚本降级”。
3. **写题型路由**：一次只选 1 个主模块，最多 3 个副模块；题型未知先低成本广覆盖侦察；副模块必须由证据触发；某路线连续两轮无增量必须重排或换模块。
4. **写各题型前 5 分钟固定动作**：Web（规范化目标、抓首页/响应头、低成本泄露、抽前端 JS、选一个最短输入点最小验证）；Pwn（file/checksec/strings/readelf、本地跑一次、绑 libc、搜危险函数、验证一个最强原语）；Forensics（hash、真实载体、结构清单、关键词搜索、二层载体）；Reverse/APK（类型/壳/混淆、strings/资源、Manifest/so、校验/网络/加解密入口、选最短路径）；Crypto（给定量、类型、参数规模、脚本化、交互 oracle 最小请求器）。
5. **写输出协议**：进入利用前输出决策卡（目标/已知事实/当前假设/下一步最小验证/切换条件）；关键发现输出证据块（现象/来源/结论/仍需验证）；输出 flag/key/token/shell 前必须说明来源路径、原始证据、二次校验方式、截断/编码/诱饵/大小写风险。
6. **工程化拆分与测试**：按 prompt_pack 目录拆分文件，写 `test_router.ps1` 防路由规则改坏、`test_prompt_quality.ps1` 防缺关键段落；按比赛/深挖/报告等 mode 切换。
7. **协作方式**：给模型“案件材料”（题型、目标、已知、已测、目标）而非猜谜；每轮只推进一个明确目标，例如“基于刚才响应差异判断是否值得进入 SQLi 路线”。

## PoC

```markdown
## 全局闭环
任务建模 -> 能力盘点 -> 首轮侦察 -> 假设生成 -> 最小验证 -> 自动化放大
-> 结果提取 -> 严格校验 -> 复盘

卡住时必须执行其一：
1. 回退到最近已确认事实，重建假设；
2. 切换到备选路径；
3. 降低单次验证成本；
4. 更换更合适的工具、MCP、Skill 或脚本；
5. 明确当前阻塞点、缺口与下一步。
```

```markdown
## 路由
一次只选择 1 个主模块，最多加载 3 个副模块。
题型未知时先做低成本广覆盖侦察；副模块必须由证据触发。
主模块：web / pwn / reverse / crypto / forensics / misc
副模块：sqli / jwt_auth / ssti_rce / deserialize / race / post_access / pcap_focus / apk_focus
```

```markdown
## 决策卡
- 目标:
- 已知事实:
- 当前假设:
- 下一步最小验证:
- 切换条件:

## 关键证据
- 现象:
- 来源:
- 结论:
- 仍需验证:

## 最终结果
- Flag / 敏感数据 / shell:
- 结果来源:
## 校验
- 校验方式:
- 仍存疑点:
```

## 变体与关联

- 变体：把 prompt pack 作为系统提示词、项目级 `AGENTS.md` 或 Agent 框架的 Profile 配置；模块可换成具体靶场/业务场景。
- 变体：无 MCP/Skill 时退化为纯工具+脚本路由；有 Wireshark MCP、jadx、frida 等专用能力时写入机器调优段。
- 关联：[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]（证据驱动流水线）、[[ai-security-agent-security-hitl-capability-dangerous-tool-guard]]（危险工具门禁）、[[defense-detection-ai-agent-edr-session-boundary-rules]]（Agent 会话检测）。

## 检测与防御

- 对 Agent 构建方：用测试脚本校验路由与提示词质量，限制适用边界为 CTF/靶场/授权环境，危险操作保留 HITL 与最小影响原则。
- 对防守方：这类提示词会提升 Agent 的工具调度与自动化能力，需按会话监控工具调用、敏感路径访问与外联；不能因“提示词只是文本”而忽略其放大效应。
- 对使用者：提示词中的“自动化放大/最大强度 mode”应绑定明确授权范围，避免越界扫描或破坏性验证。
