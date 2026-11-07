# 提示词注入

## 这层是什么

直接/间接注入、工具调用劫持与防御。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AI WAF 提示注入：<|im_end|> 伪造对话结束 + 非法 Python 语法触发回退原文](ai-security-prompt-injection-ai-waf-special-token-invalid-syntax-fallback.md) | verified | high | 2026-11-06 |
| [AI WebShell 检测大模型的结构盲区：强比较信任、PHP 作用域误判、业务代码后置与数据化载荷](ai-security-prompt-injection-ai-webshell-detector-structural-blindspots.md) | verified | medium | 2026-11-06 |
| [AI 摘要 Agent 的恶意网页 title 注入：从 System Prompt 套取数据库凭据到后续 RCE](ai-security-prompt-injection-summarizer-title-system-prompt-credential-leak.md) | verified | high | 2026-11-05 |
| [Bing Chat Sydney 系统提示词逐句抽取：忽略指令与续写追问](ai-security-prompt-injection-system-prompt-incremental-extraction.md) | verified | high | 2026-11-05 |
| [Copilot Reprompt 一键链：q 参数 P2P 注入 + 双重请求绕过 + Markdown 外传 + 远程指令闭环](ai-security-prompt-injection-copilot-reprompt-p2p-chain.md) | verified | medium | 2026-11-06 |
| [CoT 劫持：长链推理模板 + 伪审计方法论 + 输出硬约束让安全审查 Agent 放行敏感写入](ai-security-prompt-injection-cot-hijack-methodology-output-constraint.md) | verified | low | 2026-11-06 |
| [Gemini App Google Tasks 跨用户任务指派注入：任务名藏指令诱导批量改名（等效删除）](ai-security-prompt-injection-gemini-tasks-chat-space-assignment.md) | verified | high | 2026-11-06 |
| [Gemini App 日历日程标题间接提示词注入：短期/长期记忆投毒劫持 Google Home/Zoom 工具与数据外带](ai-security-prompt-injection-gemini-calendar-event-title-agent-hijack.md) | verified | high | 2026-11-06 |
| [GitAI-Assistant 系统提示词硬编码 GitHub PAT：一句“忽略之前的指令”套出 Token 接管仓库](ai-security-prompt-injection-gitai-system-prompt-github-pat-leak.md) | verified | high | 2026-11-07 |
| [GitHub MCP 间接提示注入：公开 Issue 驱使 Agent 读取私有仓库并写入公开 README](ai-security-prompt-injection-github-mcp-issue-cross-repo-exfil.md) | verified | high | 2026-11-05 |
| [LLM 应用多层防护绕过：多语言关键词规避、角色扮演 Guardrail 绕过、API Key 权威冒充与输出编码](ai-security-prompt-injection-multilayer-defense-bypass.md) | verified | high | 2026-11-05 |
| [LLM 文档评分系统间接提示注入：在简历中伪造评分字段与重复指令拉高分数](ai-security-prompt-injection-document-scoring-field-injection.md) | verified | medium | 2026-11-05 |
| [LLM 隐藏口令套取靶场：角色扮演、编码/字符干扰、情景带入与怜悯引导](ai-security-prompt-injection-llm-secret-extraction-roleplay-encoding-pity-hints.md) | verified | high | 2026-11-06 |
| [Markdown 图片 URL 自动外联：LLM 输出把对话上下文带出到攻击者服务器](ai-security-prompt-injection-markdown-image-url-context-exfiltration.md) | verified | medium | 2026-11-05 |
| [MSP 客服 AI 被排障话术套出 RMM 设备 ID 与密码：PCAP 还原提示注入凭据泄露](ai-security-prompt-injection-helpdesk-rmm-credential-leak.md) | verified | high | 2026-11-07 |
| [Nerd Sniping 式系统提示词套取：把内部规则嵌入计算题、权重对比与版本历史](ai-security-prompt-injection-nerd-sniping-system-prompt-extraction.md) | verified | medium | 2026-11-05 |
| [ObliInjection 顺序无关提示注入：影子数据 + orderGCG 优化出任意排列下都劫持输出的污染片段](ai-security-prompt-injection-order-oblivious-multi-source-injection.md) | verified | medium | 2026-11-06 |
| [Slack AI 跨频道间接注入：公开频道隐藏指令经检索执行并 Markdown 外带私有数据](ai-security-prompt-injection-slack-ai-cross-channel-indirect-exfil.md) | verified | medium | 2026-11-06 |
| [ToT 评估器操控：用高分关键词锚定 LLM-as-judge，使空洞候选分支胜出并被剪枝固化](ai-security-prompt-injection-tot-evaluator-keyword-anchoring.md) | verified | low | 2026-11-06 |
| [Unicode 混淆 + 自动解码角色：护栏只看到转义/零宽/同形字，模型解码后生成 PHP WebShell](ai-security-prompt-injection-unicode-obfuscation-decode-role.md) | verified | high | 2026-11-06 |
| [不可见 Unicode 标签字符/变体选择符走私：隐藏指令与数据外传](ai-security-prompt-injection-invisible-unicode-tag-variation-selector-smuggling.md) | verified | medium | 2026-11-05 |
| [业务参数藏 WebShell：order_id 承载 base64 命令，preg_replace_callback 重组 system 绕过 AI 检测](ai-security-prompt-injection-webshell-business-param-regex-callback.md) | verified | medium | 2026-11-06 |
| [业务范围护栏的语义桥接绕过：企业场景包装个人需求 + 权威/多样性/系统更新伪装](ai-security-prompt-injection-business-scope-semantic-bridging.md) | verified | medium | 2026-11-07 |
| [主流大模型系统提示词提取：单轮 repeat 模板 + 关键词 fuzz + 编码/角色伪装组合](ai-security-prompt-injection-mainstream-model-system-prompt-template-fuzz.md) | verified | high | 2026-11-07 |
| [代码注释提示词注入绕过 AI WebShell 检测](ai-security-prompt-injection-ai-webshell-detector-comment-bypass.md) | verified | medium | 2026-11-05 |
| [加密推理块供应链提示注入：带毒 blob 混入共享轨迹，下游 Agent 当作自身历史推理执行](ai-security-prompt-injection-encrypted-reasoning-supply-chain.md) | verified | medium | 2026-11-05 |
| [合规任务中嵌入强制分支/兜底与伪授权：条件触发、角色对立和噪声包裹带出非业务内容](ai-security-prompt-injection-forced-branch-fallback-output-hijack.md) | verified | low | 2026-11-07 |
| [合规编码任务铺垫 + 触发条件输出非业务内容](ai-security-prompt-injection-compliant-task-trigger-output.md) | verified | high | 2026-11-07 |
| [场景限定绕过：把非业务内容伪装成拼音/改写/格式/翻译任务](ai-security-prompt-injection-task-reframing-scope-bypass.md) | verified | high | 2026-11-07 |
| [增量输出拆分：先要无害代码头部再续写命令执行模块，绕过逐次输出检测](ai-security-prompt-injection-incremental-output-splitting-webshell.md) | verified | high | 2026-11-06 |
| [外部引用间接绕过：输入只含“学习这个链接”与无害请求，模型从被引用文章补全恶意代码](ai-security-prompt-injection-external-reference-indirect-bypass.md) | verified | high | 2026-11-06 |
| [多模态图片包装：把恶意需求藏进图片文字，借“按图排版/生成”让视觉模型转写为可用代码](ai-security-prompt-injection-multimodal-image-instruction-smuggling.md) | verified | high | 2026-11-06 |
| [多模态评分服务图片文字指令注入：把 rating=1337 写进图片让 MLLM 覆盖车型评分并吐出 flag](ai-security-prompt-injection-mllm-image-text-score-override.md) | verified | high | 2026-11-07 |
| [多轮变量拼接拆分恶意请求：单轮静态护栏只见无害片段，模型拿到完整语义](ai-security-prompt-injection-multiturn-variable-split-guardrail-bypass.md) | verified | high | 2026-11-06 |
| [客户端全量 messages 伪造对话历史：上下文污染绕过安全拒绝并驱动危险工具调用](ai-security-prompt-injection-forged-history-context-poisoning.md) | verified | high | 2026-11-06 |
| [开源模型 chat template 特殊 token 注入：伪造系统/助手回合实现系统提示泄露与身份冒充](ai-security-prompt-injection-chat-template-special-token.md) | verified | high | 2026-11-06 |
| [护栏输入截断不对称：无害 padding 把恶意请求推到 512 token 检测窗口之后](ai-security-prompt-injection-guardrail-input-truncation-tail-payload.md) | verified | medium | 2026-11-06 |
| [模拟被攻破场景渐进诱导系统提示词：保护机制探查→假设泄露→批量拼接→/debug 规则枚举](ai-security-prompt-injection-simulated-breach-system-prompt-extraction.md) | verified | medium | 2026-11-07 |
| [流式输出与输出审核的时间差：拦截消息到达前已从 token 流取得恶意内容](ai-security-prompt-injection-streaming-output-guardrail-race.md) | verified | high | 2026-11-06 |
| [系统提示词泄露隐藏工具与口令：诱导 LLM 输出 exec_command_online 密码后经工具执行反弹 Shell](ai-security-prompt-injection-system-prompt-hidden-tool-password-rce.md) | verified | high | 2026-11-06 |
| [翻译任务框架套取系统提示词：要求把上文翻译为猫猫语/繁体中文并逐段对照，诱导输出含 flag 的 System Prompt](ai-security-prompt-injection-translation-bilingual-system-prompt-leak.md) | verified | high | 2026-11-06 |
| [调试模式套出系统提示词：其中的工具 Token + SM3 校验规则被复用，直接调用内部工具拿 flag](ai-security-prompt-injection-debug-mode-system-prompt-tool-token-reuse.md) | verified | high | 2026-11-06 |
| [间接提示注入的隐藏载荷载体：PDF/DOCX/HTML 白字、隐藏层、元数据与零宽字符](ai-security-prompt-injection-hidden-document-carrier-white-text-metadata.md) | verified | medium | 2026-11-06 |
| [间接提示词注入劫持 Agent 工具调用](tool-call-hijack.md) | draft | medium | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
