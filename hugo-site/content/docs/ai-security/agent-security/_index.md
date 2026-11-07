---
title: Agent 安全
weight: 1
---

# Agent 安全

## 这层是什么

工具调用、权限、记忆、规划与多 Agent 风险。

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
| [A2A Agent Session Smuggling：恶意 remote Agent 隐藏控制块诱导宿主回传会话上下文与 API Key](ai-security-agent-security-a2a-session-smuggling-hidden-control-context-exfil/) | verified | medium | 2026-11-06 |
| [Agent 代码执行器 SSRF 读 GCP 元数据：带 Metadata-Flavor 请求窃取服务账号令牌](ai-security-agent-security-code-executor-metadata-ssrf/) | verified | medium | 2026-11-06 |
| [Agent 危险工具 HITL 权能门禁：授权标记只能由前端写入，阻断越权与间接提示注入](ai-security-agent-security-hitl-capability-dangerous-tool-guard/) | verified | high | 2026-11-05 |
| [Agent 宿主沙箱的路径黑名单被引号路径与变量展开绕过](ai-security-agent-security-path-denylist-quoted-variable-expansion-bypass/) | verified | medium | 2026-11-05 |
| [Agent 工具参数 SQL 注入：提示注入把单 ID 查询改成批量笔记导出](ai-security-agent-security-agent-tool-parameter-sqli-note-dump/) | verified | medium | 2026-11-06 |
| [Agent 工具目录热加载后门：写入伪造工具绕过权限策略并覆盖全局工具外带文件](ai-security-agent-security-agent-tool-file-hotload-backdoor-persistence/) | verified | high | 2026-11-06 |
| [Agent 文件读取工具的 normpath 边界检查被符号链接绕过：压缩包内软链接读取 /etc/passwd](ai-security-agent-security-file-read-tool-symlink-realpath-bypass/) | verified | high | 2026-11-06 |
| [Agent 运行时能力闭包：工具链、记忆与身份三维度导致内部数据外泄](ai-security-agent-security-capability-closure-tool-memory-identity/) | verified | medium | 2026-11-05 |
| [Agentic RAG 带内信道走私：低可信检索内容经 ReAct/AutoGen/Function Calling 进入工具执行](ai-security-agent-security-agentic-rag-inband-retrieval-to-tool-execution/) | verified | high | 2026-11-05 |
| [AI Skill 自动登录流水线：agent-browser 快照定位 + 本地默认口令库 + ddddocr 验证码识别与失败自修复](ai-security-agent-security-ai-skill-auto-login-default-credential-captcha/) | verified | medium | 2026-11-06 |
| [AI 代码审计接口 Prompt Injection 强制触发沙箱：从“安全判定”到 vm2 逃逸](ai-security-agent-security-prompt-injection-force-sandbox-vm2-escape/) | verified | high | 2026-11-06 |
| [AI 代码执行沙箱跨账号共享制品属性信道：Artifactory Item Properties 写入与受害者连接器任务借用](ai-security-agent-security-sandbox-shared-artifactory-property-channel/) | verified | medium | 2026-11-05 |
| [AI 安全扫描器 Host 头 SSRF：提示注入让扫描器以内部网络身份访问 admin 面板并删除用户](ai-security-agent-security-ai-scanner-host-header-ssrf-internal-admin/) | verified | high | 2026-11-05 |
| [AI 安全扫描器间接提示注入数据外带：诱导扫描器调用 accountDetails 取 API Key 并公开评论](ai-security-agent-security-ai-scanner-indirect-prompt-injection-data-exfil/) | verified | high | 2026-11-05 |
| [AI 安全扫描器间接提示注入：UGC 评论冒充管理员诱导扫描器删除用户，并补上 CSRF token](ai-security-agent-security-ai-scanner-indirect-prompt-injection-destructive-action/) | verified | high | 2026-11-05 |
| [AI 浏览器 URL 路径提示词注入：以当前用户会话权限打开任意站点](ai-security-agent-security-ai-browser-url-path-prompt-injection/) | verified | high | 2026-11-06 |
| [AI 渗透 Agent 证据驱动流水线：候选 + 原始请求/响应，人工做成立判断](ai-security-agent-security-ai-pentest-evidence-driven-pipeline/) | verified | high | 2026-11-05 |
| [AI 编程代理只读命令白名单把 find 当安全命令：find -exec 绕过审批执行任意命令（Amazon Q Developer CLI 1.8.1）](ai-security-agent-security-amazon-q-readonly-find-exec-allowlist-bypass/) | verified | medium | 2026-11-06 |
| [AI 编程助手源码注释间接注入：读取 /etc/passwd 并经 Markdown 图片 URL 零点击外带](ai-security-agent-security-coding-agent-comment-injection-markdown-image-exfil/) | verified | medium | 2026-11-06 |
| [AutoGPT 禁用块未校验 disabled：硬编码 UUID 调用 BlockInstallationBlock 执行任意 Python（CVE-2026-24780）](ai-security-agent-security-autogpt-disabled-block-install-rce/) | verified | high | 2026-11-06 |
| [Bash 参数展开与通配符混淆绕过 Agent 命令检测：子串/正则与 Shell 解析深度差](ai-security-agent-security-bash-expansion-glob-command-filter-bypass/) | verified | high | 2026-11-06 |
| [CAI find_file 参数注入：find -exec 绕过 shell 元字符依赖到 RCE（CVE-2026-25130）](ai-security-agent-security-cai-find-file-argument-injection-cve-2026-25130/) | verified | high | 2026-11-06 |
| [CAI 框架 find_file 参数注入：HTML 注释提示注入 + shell=True 命令执行（CVE-2026-25130）](ai-security-agent-security-cai-find-file-argument-injection-rce-cve-2026-25130/) | verified | high | 2026-11-06 |
| [Chainlit <2.9.4 /project/element 任意文件读取：custom element path 直达数据层后被 /project/file 取回](ai-security-agent-security-chainlit-custom-element-path-arbitrary-file-read/) | verified | high | 2026-11-06 |
| [Claude 拒绝魔术值与编码变体：把触发字符串嵌入样本/图片/文档以瘫痪 AI 辅助分析](ai-security-agent-security-magic-string-refusal-anti-ai-analysis/) | verified | high | 2026-11-06 |
| [CLI 编程助手工具滥用：读取本地密钥并用 ping 占位符替换经 DNS 外带](ai-security-agent-security-cli-agent-file-read-ping-dns-exfil/) | verified | high | 2026-11-06 |
| [Codex 沙箱 PATH 劫持：向 /tmp 白名单目录写入同名 helper bin，借沙箱外调用逃逸](ai-security-agent-security-codex-tmp-path-helper-binary-sandbox-escape/) | verified | medium | 2026-11-06 |
| [CoPhish：Copilot Studio 官方域名托管 Agent 的 OAuth 同意钓鱼与令牌窃取](ai-security-agent-security-cophish-copilot-studio-oauth-consent-phishing/) | verified | high | 2026-11-06 |
| [CrewAI FileWriterTool + PickleHandler 组合链：任意写 pickle + ../ 穿越 + pickle.load RCE](ai-security-agent-security-crewai-filewriter-picklehandler-chain-rce/) | verified | high | 2026-11-06 |
| [CrewAI SandboxPython 沙箱逃逸：().__class__.__bases__[0].__subclasses__() 找 catch_warnings 恢复原始 builtins](ai-security-agent-security-crewai-sandboxpython-dunder-subclasses-builtins-escape/) | verified | high | 2026-11-06 |
| [CTF/授权渗透 Agent 提示词工程：执行闭环 + 运行时能力盘点 + 题型路由 + 首轮动作 + 证据化输出](ai-security-agent-security-ctf-agent-prompt-pack-runtime-routing/) | verified | medium | 2026-11-06 |
| [ctfSolver 请求模板 {{addon()}} 反射调用 run_python/run_shell：目标页面提示注入导致 Agent 宿主机 RCE](ai-security-agent-security-ctfsolver-addon-template-prompt-injection-rce/) | verified | medium | 2026-11-06 |
| [Cursor Agent/Tab Hook 四段式安全编码护栏：规范注入、输入合规、命令门控与编辑后扫描](ai-security-agent-security-cursor-hooks-secure-coding-guardrail/) | verified | high | 2026-11-06 |
| [Cursor 打开恶意项目即命令执行：.vscode/tasks.json 的 runOn=folderOpen + task.autoDetect 在缺失工作区信任校验时自动执行](ai-security-agent-security-cursor-tasks-json-folderopen-autorun-rce/) | verified | high | 2026-11-06 |
| [DeepChat MermaidArtifact XSS + presenter:call + MCP addMcpServer 命令执行（CVE-2025-66481）](ai-security-agent-security-deepchat-mermaid-xss-ipc-mcp-command-exec/) | verified | high | 2026-11-06 |
| [DeepChat MermaidArtifact XSS + presenter:call 动态 IPC + FilePresenter 路径遍历：任意文件读写与明文 API Key 泄露](ai-security-agent-security-deepchat-mermaid-xss-ipc-filepresenter-path-traversal/) | verified | high | 2026-11-06 |
| [Dify 代码节点沙箱默认允许网络：工作流作者可执行命令并经 DNS 外带](ai-security-agent-security-dify-code-sandbox-network-egress/) | verified | high | 2026-11-05 |
| [GoT 图拓扑注入：高信任文档节点 + 自然语言条件边自动生成，使恶意结论绕过内容审核直达输出](ai-security-agent-security-got-graph-topology-trust-node-injection/) | verified | low | 2026-11-06 |
| [iOS 锁屏 Siri 上下文越权：读取 ChatGPT 记忆、当前聊天分享链接与 Safari 页面 URL](ai-security-agent-security-ios-lockscreen-siri-context-leak/) | verified | medium | 2026-11-06 |
| [iOS 隐藏相册 Face ID 绕过：锁屏 Siri 把已缓存私密照片作为附件发给 ChatGPT](ai-security-agent-security-ios-siri-hidden-album-cache-faceid-bypass/) | verified | medium | 2026-11-06 |
| [kilocode 环境变量配置中的 {file:} 模板替换导致任意文件读取（CVE-2026-8766）](ai-security-agent-security-kilocode-config-file-template-arbitrary-read/) | verified | high | 2026-11-05 |
| [LangChain Core 的 lc 信任标记注入（CVE-2025-68664 LangGrinch）：密钥窃取、任意类实例化与 RCE](ai-security-agent-security-langchain-lc-tag-serialization-injection/) | verified | high | 2026-11-05 |
| [LangChain PythonAstREPLTool 直接 exec 模型输出：提示词注入升级为任意代码执行（langchain-experimental 归档包）](ai-security-agent-security-langchain-python-ast-repl-exec-injection/) | verified | medium | 2026-11-05 |
| [Langflow build_public_tmp 未认证 data 参数直达自定义组件 exec：公开流程端点 RCE（CVE-2026-33017）](ai-security-agent-security-langflow-build-public-tmp-data-code-exec/) | verified | high | 2026-11-05 |
| [Langflow CodeParser 返回类型注解 eval 无沙箱：custom_component 端点已认证用户 RCE（1.8.3/1.8.4）](ai-security-agent-security-langflow-code-parser-return-annotation-eval-rce/) | verified | high | 2026-11-06 |
| [Langflow CSV Agent 硬编码 allow_dangerous_code=True：LLM 生成 pandas/Python 代码经 DataFrame Agent 执行导致 RCE（CVE-2026-27966）](ai-security-agent-security-langflow-csv-agent-allow-dangerous-code-rce/) | verified | medium | 2026-11-06 |
| [Langflow CVE-2025-3248 未授权 RCE：/api/v1/validate/code 编译并 exec 顶层函数定义，默认参数表达式在定义期执行](ai-security-agent-security-langflow-cve-2025-3248-validate-code-default-arg-rce/) | verified | high | 2026-11-06 |
| [Langflow CVE-2026-10561 未授权 RCE：auto_login 签发 superuser JWT + /run tweaks 覆盖 python_code + PythonREPL 隐式 __builtins__](ai-security-agent-security-langflow-auto-login-tweaks-pythonrepl-builtins-rce/) | verified | high | 2026-11-05 |
| [LangGraph SQLite Store 过滤操作符注入：$ne 逻辑绕过与 filter key SQL 注入](ai-security-agent-security-langgraph-sqlite-store-filter-operator-injection/) | verified | high | 2026-11-06 |
| [LangGraph 检查点序列化回退 RCE（CVE-2025-64439）：孤立代理字符逼出 JSON，Reviver 执行构造器](ai-security-agent-security-langgraph-checkpoint-json-fallback-rce/) | verified | high | 2026-11-05 |
| [Letta "Running" 消息参数直接 eval 导致 RCE](ai-security-agent-security-letta-running-message-eval-rce/) | verified | medium | 2026-11-04 |
| [Letta <= 0.16.7 /v1/tools/run 未授权代码执行：source_code 无过滤 + 默认 Actor 回退](ai-security-agent-security-letta-tools-run-unauth-code-exec/) | verified | high | 2026-11-06 |
| [Letta AST 白名单异常回退 eval 与 allow_unsafe_eval 硬编码导致补丁绕过 RCE](ai-security-agent-security-letta-ast-whitelist-eval-fallback-bypass/) | verified | medium | 2026-11-04 |
| [LLM Tool Call SSRF：间接提示注入驱动 fetch_url 访问内网与云元数据](ai-security-agent-security-llm-tool-call-indirect-injection-ssrf/) | verified | medium | 2026-11-05 |
| [LLM 中转 API/BaseURL 劫持：篡改模型响应伪造 Tool Call 实现 Agent 命令执行与数据窃取](ai-security-agent-security-llm-relay-baseurl-tool-call-hijack/) | verified | high | 2026-11-06 |
| [LLM 聊天 Agent 的 read_file 工具未限制路径边界：提示词注入用 ../ 直读用户 SSH 私钥](ai-security-agent-security-read-file-tool-path-traversal-ssh-key/) | verified | high | 2026-11-06 |
| [MindsDB BYOM 未认证 PUT 上传 Python 代码：type=inhouse 经 exec 在当前进程执行](ai-security-agent-security-mindsdb-byom-unauth-code-exec/) | verified | high | 2026-11-06 |
| [MINJA 记忆注入：正常查询 + 满意反馈写入长期记忆，渐进缩短提示把桥接逻辑锚定为无痕后门](ai-security-agent-security-minja-progressive-shortening-memory-injection/) | verified | medium | 2026-11-06 |
| [OpenClaw Control UI 无条件信任 gatewayUrl：WebSocket 握手自动外带 Gateway Token 导致 Gateway 接管与宿主机 RCE（CVE-2026-25253）](ai-security-agent-security-openclaw-control-ui-gatewayurl-token-leak-rce/) | verified | medium | 2026-11-06 |
| [OpenClaw Docker exec PATH 环境变量命令注入：CVE-2026-24763 认证用户注入容器命令](ai-security-agent-security-openclaw-docker-exec-path-command-injection-cve-2026-24763/) | verified | high | 2026-11-06 |
| [OpenClaw Feishu 扩展 SSRF：sendMediaFeishu/文档图片直 fetch 内网 URL，响应回传为飞书媒体（CVE-2026-28451）](ai-security-agent-security-openclaw-feishu-ssrf-media-upload/) | verified | high | 2026-11-06 |
| [OpenClaw Gateway node.invoke 审批字段注入：params.approvalDecision 绕过 system.run 审批执行任意命令（CVE-2026-28466）](ai-security-agent-security-openclaw-node-invoke-approval-field-injection-rce/) | verified | high | 2026-11-06 |
| [OpenClaw web_fetch 多阶段网页诱导：伪造 302/解谜任务链绕过外部内容安全包装并 exec RCE](ai-security-agent-security-openclaw-webfetch-multistage-prompt-injection-rce/) | verified | high | 2026-11-06 |
| [OpenClaw 反向代理未配置 trustedProxies：外部请求被当作 127.0.0.1 本机连接绕过 Gateway 鉴权](ai-security-agent-security-openclaw-trusted-proxies-localhost-auth-bypass/) | verified | medium | 2026-11-06 |
| [OpenCode <1.0.216 无认证 /pty + WebSocket：任意 command/args/cwd/env 直接 spawn 成交互式 shell](ai-security-agent-security-opencode-unauth-pty-websocket-interactive-rce/) | verified | high | 2026-11-06 |
| [Prefab UI Pyodide 沙箱经 js.Deno 桥接越权读写宿主文件并落 .pth 实现后续 RCE（CVE-2026-120338）](ai-security-agent-security-prefab-ui-pyodide-deno-host-file-escape/) | verified | high | 2026-11-06 |
| [Repeat-After-Me 诱导 Agent 输出原生 tool_calls 执行越权工具](ai-security-agent-security-repeat-after-me-tool-call/) | verified | medium | 2026-11-04 |
| [Seek 终端 Agent plan 模式 grep 越界读取：README 注入绕过工作区路径边界](ai-security-agent-security-seek-plan-grep-workspace-bypass/) | verified | high | 2026-11-05 |
| [ServiceNow Agent BodySnatcher：共享静态密钥 + 邮箱自动信任导致管理员冒充与记录篡改（CVE-2025-12420）](ai-security-agent-security-servicenow-bodysnatcher-shared-key-email-impersonation/) | verified | medium | 2026-11-06 |
| [SpAIware：ChatGPT 长期记忆投毒实现跨会话持久化与自动数据外带](ai-security-agent-security-spaiware-chatgpt-memory-poisoning-persistent-exfil/) | verified | medium | 2026-11-06 |
| [SSE chunked 流式走私：单字符拆分 tool_calls 绕过 Agent 检测代理](ai-security-agent-security-sse-chunked-smuggling-tool-detection-bypass/) | verified | high | 2026-11-06 |
| [VEGA 自进化漏洞赏金 Agent：7 Agent 分工 + 结构化文件通信 + 三维经验库](ai-security-agent-security-vega-self-evolving-bounty-agent-architecture/) | verified | medium | 2026-11-06 |
| [VS Code Agent 自动运行与源码注释间接注入：改写 settings.json 并执行 calc](ai-security-agent-security-vscode-agent-autorun-comment-injection-rce/) | verified | high | 2026-11-06 |
| [Web Agent 点击动作的 TOCTOU 重绑定：DOM 元素索引与屏幕坐标](ai-security-agent-security-web-agent-toctou-click-rebinding/) | verified | high | 2026-11-05 |
| [xAI Grok CLI 导入 Claude 设置跟随仓库 .grok 符号链接：全局 Hook 写入与命令执行](ai-security-agent-security-grok-claude-import-hook-symlink-rce/) | verified | high | 2026-11-05 |
| [ZCode Trust Folder 旁路：插件/MCP 注册路径漏挂 admission，打开工作区即 spawn 命令](ai-security-agent-security-zcode-trust-folder-plugin-mcp-admission-bypass/) | verified | high | 2026-11-05 |
| [中性知情披露击穿环境授权限制记录：自主攻击 Agent 的欺骗式防御归零](ai-security-agent-security-informed-disclosure-authz-record-bypass/) | verified | medium | 2026-11-05 |
| [多代理系统攻击面枚举：DO NOT DELEGATE 阻断委派拿代理/工具清单 + AutoGen 显式转移跨代理套提示词](ai-security-agent-security-multi-agent-roster-enumeration-transfer-injection/) | verified | medium | 2026-11-06 |
| [多智能体共享记忆 Redis 未授权投毒：standing_instructions/override 覆盖与管理员冒充导致密钥泄露、命令执行](ai-security-agent-security-multi-agent-shared-memory-redis-poisoning/) | verified | high | 2026-11-05 |
| [工具语义授权缺口 + 审计框架：verify_user_access 对任意 user_id 在“官方审计”名义下返回数据，诱导模型越权读取 admin 笔记](ai-security-agent-security-audit-tool-scope-bypass-admin-data/) | verified | high | 2026-11-06 |
| [恶意 Skill 行为后门：向 SOUL.md/AGENTS.md 写入持久指令，删除 Skill 后仍控制 Agent](ai-security-agent-security-skill-behavior-backdoor-soul-agents-persistence/) | verified | medium | 2026-11-06 |
| [推理编排共享状态污染：ToT 检索缓存跨分支复用与 GoT 节点全局缓存跨租户污染](ai-security-agent-security-reasoning-shared-state-cross-branch-tenant-poisoning/) | verified | low | 2026-11-06 |
| [推理轨迹泄漏：CoT/反思日志暴露内部验证规则与敏感上下文，被用于绕过验证或窃取数据](ai-security-agent-security-cot-trace-leakage-rule-and-sensitive-context/) | verified | low | 2026-11-06 |
| [移动 APP 六阶段 AI 分析流水线：SKILL 总控 + 阶段 Agent + 分阶段 MCP + Python 探针与结构化产物继承](ai-security-agent-security-mobile-reverse-six-stage-skill-pipeline/) | verified | high | 2026-11-06 |
| [编码 Agent 间接提示注入：README 闭合 Prompt 分隔符并借 COMMAND 协议经 shell=True 执行命令](ai-security-agent-security-coding-agent-readme-delimiter-command-rce/) | verified | medium | 2026-11-06 |
| [能力令牌范围包含判定错误导致委托越权：** 短路径、空段与路径归一化](ai-security-agent-security-capability-scope-subsumption-bypass/) | verified | medium | 2026-11-05 |
| [语义扫描：向公网 LLM Agent 发送自然语言载荷做 SSRF 探测与 OOB 回连验证](ai-security-agent-security-semantic-scanning-llm-agent-ssrf-oob/) | verified | medium | 2026-11-06 |
| [面向渗透 Agent 的任务失效化蜜罐：多入口诱饵事实链 + PPF 伪进展反馈](ai-security-agent-security-task-invalidating-honeypot-ppf/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
