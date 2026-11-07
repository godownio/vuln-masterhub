---
id: code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow
title: AI 代码审计工作流：AST Source→Sink 链路提取 + 逐链独立 LLM 分析 + 鉴权专项 + 二次反思补漏
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: ast-chain-per-link-llm-code-audit-workflow
aliases:
- AI 代码审计工作流
- AST 链路提取
- 逐条链路 LLM 分析
- 鉴权 Skill
- AI 二次反思
- 农场主大法
tags:
- ai
- llm
- code-audit
- sast
- ast
- call-chain
- source-sink
- auth-analysis
- vuln-discovery
- workflow
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:47:50+08:00'
  notes: 已对照原文与图01、03-14核对：AST Source→Sink 链路提取、逐链独立 LLM 会话、鉴权 Skill（自定义 Filter/Interceptor、22 敏感端点、4 类绕过）、二次反思、评分公式（Base7-Friction2-Weapon0-Ver0=5 Medium）、PHP 上传报告与 Codex/Claude CLI 验证工具（workers=7、timeout=180）均与图文一致。未验证点：作者 CVE/CNVD 产出声明未独立核验（卡片未采用该数字，confidence=medium）；工具闭源、PoC 为工作流伪代码未执行；无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

面对几百到几千文件的项目，不要把整个仓库丢给 LLM；先用 AST/正则静态分析提取 Source→Sink 调用链，把每条链路作为一次独立对话交给带专项 Prompt 的模型分析，再单独跑鉴权分析 Skill 和“确认/排除后二次反思”，可在控制上下文与 token 成本的同时覆盖 SQL 注入、文件操作、RCE、SSRF、XXE 与鉴权绕过。

## 原理

- 全量 LLM 审计的瓶颈：一套小系统 400+ 文件、大系统 3000+ 文件，超出上下文后模型会“变笨”；全量分析 token 成本可能 100–1000 元，还会重复跑代码或漏掉部分代码，导致漏报/误报。
- 链路化方案：静态分析先定位危险函数（Sink）与用户输入点（Source），提取完整调用链；每条链路只带涉及的文件与精心设计的 Prompt，独立会话分析。优点是上下文短、每条链互不污染、弱模型也能用、token 成本低。
- 核心风险在链路提取：静态工具漏掉 Sink，或遇到反射调用（如 `Class.forName("caigo")` 后再调用）、复杂变量赋值、方法封装在 JAR 包中，链路会中断，产生漏报。PHP 因语言灵活、自研写法多，AST 误报/漏报更明显；ThinkPHP 等成熟框架相对好。
- 放宽规则不是解法：把变量赋值等点也纳入提取，可能从 100 条链增到 300 条，只多覆盖 3 条真漏洞，却增加约 197 条误报，AI 分析成本反而上升。
- 鉴权专项：先识别框架与鉴权装配方式（Spring MVC 拦截器、Struts2 Action 继承、Filter、Shiro 等），分析白名单匹配逻辑与组件绕过 CVE；提取白名单/未授权接口，检查 URL 获取方式（如 `getRequestURI` + `endsWith`）与字符串匹配缺陷，输出 semicolon、path traversal、encoding、case 等绕过风险。
- 二次反思：把已确认漏洞与已排除漏洞从上下文中移除，让 AI 分析“系统是否还存在遗漏漏洞”，并解释静态工具为何没提取到对应链路，讨论能否用技术手段补全提取规则。
- 评分可用“基础分 - 摩擦 - 武器化 - 版本限制”的方式（案例：Base=7 任意文件上传可直接 getshell，Friction=2 需管理员登录，Weapon=0，Ver=0，最终 5 分 Medium），把可利用性量化后再排序。

## 触发条件

- 获得授权的 Java/PHP 等项目源码审计，项目规模大到不适合整库塞给 LLM。
- 有可用的 AST/正则静态分析能力（自研或现成工具），能输出 Source→Sink 调用链。
- 有 LLM API/CLI 预算，且接受“AI 产出候选 + 人工复核”的流程。
- 可选：能通过 MCP/本地环境复现 PoC，做二次确认以排除误报。

## 利用步骤

1. **架构分析**：识别框架（Spring MVC/Struts2/传统 JavaWeb/ThinkPHP 等）、鉴权装配位置、路由规则与框架特有漏洞面。
2. **鉴权缺陷挖掘**：提取白名单接口与鉴权实现，分析 URL 获取与匹配逻辑，检查未授权访问、路径/编码/大小写/分号绕过及 Shiro 等组件 CVE。
3. **AST 链路提取**：静态定位 Source 与 Sink，提取调用链；按漏洞类型（SQLi、文件读写/上传、RCE、SSRF、XXE）分类，控制每条链只包含相关文件。
4. **逐链 LLM 分析**：每条链路一次独立对话，Prompt 中给出漏洞成立条件、危险函数语义、过滤/编码检查要求与输出格式；要求模型给出证据、可达性与置信度。
5. **PoC 复现与二次确认**（可选）：对高置信候选生成 PoC，用 MCP 对接本地环境复现，排除不可达/已过滤/仅管理员可用的误报。
6. **AI 二次反思**：移除已确认与已排除项，让模型寻找遗漏漏洞并分析静态提取失败原因，反哺规则与工具。
7. **整合报告**：输出架构分析、鉴权分析、确认漏洞（类型/文件/行号/评分/置信度/调用链/PoC）与不确定链路，供人工复核。

## PoC

```text
# 工作流伪代码
chains = ast_extract(source_patterns, sink_patterns, project)
for chain in chains:
    result = llm_analyze(chain.files, chain.call_path, prompt_by_vuln_type)
    if result.confirmed:
        poc = generate_poc(result)
        verify_in_local_env(poc)          # 可选，MCP/本地环境
report = merge(results) + auth_analysis(project) + ai_reflection(results)
```

```text
# 案例：PHP 任意文件上传链路（报告字段）
Source: $request->file('file')
Sink:   $file->move(...) 第 575 行
Chain:  POST /api/v1/im/upload -> AuthMiddleware::process() -> IMController::upload()
        -> getUploadMimeType()/getUploadExtension() -> move() 到 public/uploads/im/
结论:   MIME 可伪造、扩展名未过滤，.php 写入 Web 可访问目录 -> Webshell
评分:   Base=7 - Friction=2(需管理员登录) - Weapon=0 - Ver=0 = 5 (Medium)
```

## 变体与关联

- 变体：只做链路提取，把链路文件交给本地 AI/人工分析，避免在线 API 与数据外发。
- 变体：静态工具可切换 only-regex / only-ast / JSP 解析 / verbose 等模式，按项目类型与覆盖率取舍。
- 变体：鉴权分析可独立成 Skill，针对不同框架（Spring Security、Shiro、自定义 Filter/Interceptor）维护检查项。
- 关联：[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（分阶段 LLM + 上下文补全）、[[code-analysis-vuln-discovery-agent-miner-langgraph-whitebox-audit-poc-verification]]（多 Agent + PoC 验证）、[[code-analysis-vuln-discovery-autocve-target-count-multi-agent-orchestration]]（多 Agent CVE 挖掘）、[[code-analysis-sast-taie-java-taint-audit-toolchain]]（PTA 污点分析工具链）。

## 检测与防御

- 审计方：用已知漏洞项目回归链路提取覆盖率，重点检查反射、动态分发、JAR 内方法、复杂赋值等断链点；AI 结论必须人工复核，不能直接把模型输出当漏洞。
- 开发方：减少动态执行与反射调用面，统一鉴权中间件与白名单匹配（规范化路径后再比较），危险 Sink 前做类型/白名单校验。
- 检测：关注“链路提取失败”的盲区而非只看已报漏洞；对 AI 生成的 PoC 在隔离环境验证，避免对生产造成影响。
- 合规：仅用于授权源码审计；在线 AI 分析需评估源码外发风险，敏感项目优先本地模型。
