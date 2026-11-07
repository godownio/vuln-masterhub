---
id: code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline
title: LLM 驱动 Python 代码审计（VulnHuntr）：五阶段 prompt + Jedi 上下文补全 + 置信度评分与检测边界
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: llm-sast-vulnhuntr-python-audit-pipeline
aliases:
- VulnHuntr
- LLM 代码审计
- Claude prefill
- Jedi 上下文补全
- 多阶段 prompt
- 置信度评分
- Python SAST
- LLM 漏洞挖掘
tags:
- llm
- sast
- vulnhuntr
- python
- code-audit
- prompt-engineering
- jedi
- vuln-discovery
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V102
  verified_at: '2026-11-05T22:37:26+08:00'
  notes: 已对照原文与10张图核对；PoC为原文示例终端输出，未独立运行；无CVE/版本，属方法卡。
---

## 一句话结论

VulnHuntr 把“读代码→找入口→构造调用链→写 PoC”拆成五个阶段的 LLM prompt pipeline：README 摘要注入 System Prompt、逐文件初筛可疑落点、按 7 类漏洞专项下钻、用 Jedi 静态解析按需补全跨文件定义（最多 7 轮）、输出 PoC 与置信度评分；它对 3–5 层以内的直接调用链（request 参数→危险 sink）命中率高，但对间接/动态调用、隐式反序列化、业务逻辑（IDOR）、多语言/微服务与正则未覆盖的入口基本失效。

## 原理

- **为什么要分阶段**：不把整个仓库一次性塞给 LLM，而是拆成独立阶段，每阶段只做一件事，既控制 token 消耗，又避免上下文过长导致注意力稀释。原文的五个阶段：
  1. 读 README，生成项目摘要并写入 System Prompt，让后续分析知道项目是做什么的；
  2. 逐文件扫描，用 `INITIAL_ANALYSIS_PROMPT_TEMPLATE` 标记所有“可能接收远程用户输入”的落点，不限定漏洞类型；
  3. 按漏洞类型下钻，用对应专项 prompt（RCE 关注 `eval/exec/subprocess/os.system/os.popen/pickle.loads/yaml.load`，LFI 关注 `open/file` 等）；
  4. 上下文补全循环：LLM 主动请求缺失的函数/类/变量定义，工具端用 Jedi 静态分析提取并打包回传；
  5. 生成 PoC 与置信度评分（低于 7 一般不考虑，7 以上值得查，8 以上基本是真洞）。
- **Prompt 组件化与 XML 包裹**：用户 prompt 由 `FileCode`、`definitions`（Jedi 提取的上下文）、`ExampleBypasses`（已知绕过技巧）、`Instructions`（漏洞类型模板）、`AnalysisApproach`、`PreviousAnalysis`、`Guidelines`、`ResponseFormat`（Pydantic JSON Schema）等组件拼成，并用 pydantic_xml 序列化为 XML 标签。XML 标签让 LLM 能区分 `<file_code>` 与 `<context_code>`，减少来源混淆。
- **Claude prefill 引导 JSON**：Claude 没有 GPT 的 `response_format={"type":"json_object"}`，VulnHuntr 在 assistant 消息中预填 `{"scratchpad": "1.` 强制模型续写 JSON；配合 Pydantic schema 校验输出。不同后端（Claude/GPT/Ollama）共用 prompt，但 Claude 效果最好。
- **正则预过滤网络入口**：`RepoOps` 内置 90+ 条正则，覆盖 Flask `@app.route`、Django `url/re_path`、FastAPI `@app.get/@router.post`、Tornado `RequestHandler`、aiohttp、Sanic、Bottle、Falcon、CherryPy、Quart、Starlette、AWS Lambda handler、Azure Functions、gRPC server 等；先用正则筛出“可能是网络入口”的文件，再交给 LLM 精分析。正则未命中的入口文件不会进入后续流程。
- **上下文补全循环实现**：`for i in range(7)`，第一轮不做补全；后续轮次遍历 `secondary_analysis_report.context_code`，用 `symbol_finder`/Jedi 的 `extract(name, code_line, files)` 找定义，累积到 `stored_code_definitions`；把新代码、上一轮分析结果（`PreviousAnalysis`）与专项 prompt 一起发回；若本轮不再请求新上下文则 break。设计要点：最多 7 轮、上下文逐轮累积、历史分析累积、重复请求检测（原文指出只比较数量不比较内容，换名请求同样函数可能检测不到）。
- **为什么能挖到真实漏洞**：原文称 VulnHuntr 用几行 prompt 找到了 gpt_academic 的 LFI、ComfyUI 的 XSS、Langflow 的 RCE、Ragflow 的 RCE 等；核心是把“确定性正则预过滤 + LLM 语义分析 + 静态符号补全 + PoC/置信度”组合起来，而不是纯靠 LLM 读整个仓库。
- **检测边界（原文重点）**：
  - **间接调用链**：调用链超过 5 层，或中间有 `getattr(self, 'handle_' + action)` 这类动态分发，LLM 容易断链，Jedi 也定位不到动态属性；
  - **反序列化**：显式 `pickle.loads(request.data)` 能扫到，但框架在 session/缓存中隐式反序列化、链式反序列化（A 反序列化 B，B 里再藏 pickle）基本扫不到；
  - **业务逻辑漏洞**：IDOR 需要理解“资源归属/权限校验是否正确”，LLM 只能看到“有没有权限校验代码”，无法判断“校验写得对不对”，误报/漏报都高；
  - **多语言/微服务**：只支持 Python，前端 JS 输入校验、RPC 服务边界、protobuf/thrift schema 都会断链；
  - **正则盲区**：自研路由框架、配置注入路由、中间件中的入口点可能不被 90+ 正则覆盖。
- **置信度评分的局限**：评分是一次 LLM 输出，不同项目波动大；“模型自信”不等于“准确”。原文建议双重验证（另一 prompt 独立复核）、多轮采样取方差、最低 token 消耗阈值等改进。

## 触发条件

- 目标为 Python 代码库，且网络入口文件能被内置正则覆盖（主流 Web 框架、Lambda/Functions、gRPC 等）；自研路由/中间件入口可能被漏掉。
- 有可用的 LLM 后端与 API Key（Claude 效果最好；也支持 GPT/Ollama），并接受将代码发送给对应模型/服务的合规要求。
- 运行环境为 Python 3.10（Jedi 在该版本最稳定），安装 VulnHuntr 依赖。
- 目标是“明显但量大”的漏洞（直接 source→sink、调用链 3–5 层以内、有明确危险函数）时收益最高；业务逻辑/长链/隐式反序列化需要人工补充。
- 扫描结果需要人工复核：置信度 ≥7 值得查，≥8 基本可信，但仍需实际验证 PoC。

## 利用/实施步骤

1. **准备环境**：Python 3.10，`git clone` VulnHuntr，`pip install -r requirements.txt`，设置 `ANTHROPIC_API_KEY`（或 `OPENAI_API_KEY`/Ollama 地址）；自定义代理可配 `ANTHROPIC_BASE_URL`。
2. **选择目标**：优先含主流 Python Web 框架路由的仓库；确认没有把敏感代码发送给不允许的第三方模型的合规问题。
3. **运行扫描**：`python -m vulnhuntr -r /path/to/repo` 扫描整个仓库；`-a /path/to/app.py` 指定单文件/子目录；`-l gpt` 切换后端；`-v` 开启详细输出。
4. **阅读阶段输出**：观察 README 摘要、正则命中的网络文件、初筛入口点、漏洞专项下钻、上下文请求（Jedi 提取了哪些定义）、最终 PoC 与置信度。
5. **人工复核**：对置信度 ≥7 的候选逐条检查 source 可控性、sink 可达性、sanitizer/过滤是否可绕过、调用链是否真实；用本地环境验证 PoC。
6. **调优**：补充自定义框架正则、为项目增加专项 prompt/绕过示例、扩展上下文轮数或主动预取；对误报建立反馈。
7. **边界测试**：用含间接调用、隐式反序列化、IDOR、多语言/微服务的样本验证工具盲区，明确哪些结论不能依赖工具。

## PoC

安装与运行：

```bash
git clone https://github.com/protectai/vulnhuntr
cd vulnhuntr
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-xxx

python -m vulnhuntr -r /path/to/target-repo          # 扫描整个仓库
python -m vulnhuntr -a /path/to/app.py               # 单文件
python -m vulnhuntr -r /path/to/repo -l gpt          # GPT 后端
python -m vulnhuntr -r /path/to/repo -v              # 详细输出
```

原文示例输出（Flask 文件管理器靶场）：

```text
[INFO] Scanning: app.py
[WARN] Potential LFI at app.py:45 - user input passed to open()
[INFO] Requesting context: read_file() defined in utils.py
 -> symbol_finder.py: reading utils.py...
 -> acquired 24 lines of context code
[INFO] Chain complete: /read-file -> app.py:45 -> utils.py:12 -> open()
[RESULT] LFI | Confidence: 8 | PoC: /read-file?path=../../etc/passwd
```

```text
[LLM] Tracing call chain: /download -> app.py:112 -> utils.py:44 -> open()
[LLM] Sanitization check: path has os.path.basename() but bypassable
[RESULT] LFI FOUND | Confidence: 8 | app.py:112
[LLM] Tracing call chain: /admin/exec -> app.py:203 -> subprocess.check_output
[LLM] Input filter: blacklist of dangerous commands detected
[LLM] Trying: $(touch${IFS}/tmp/pwned) - not blacklisted
[RESULT] RCE FOUND | Confidence: 9 | app.py:203
```

核心上下文补全循环（伪代码）：

```python
for i in range(7):
    if i > 0:
        for context_item in secondary_analysis_report.context_code:
            if context_item.name not in stored_code_definitions:
                match = code_extractor.extract(context_item.name,
                                                context_item.code_line, files)
                if match:
                    stored_code_definitions[context_item.name] = match
        user_prompt = (
            FileCode(...).to_xml() +
            CodeDefinitions(list(stored_code_definitions.values())).to_xml() +
            PreviousAnalysis(previous_analysis).to_xml() + ...
        )
        secondary_analysis_report = llm.chat(user_prompt)
        if not secondary_analysis_report.context_code:
            break
```

## 变体与关联

- **后端替换**：Claude（prefill JSON）效果最好；GPT 用 `response_format`；Ollama 用于本地/离线代码，但模型能力与 JSON 稳定性下降。
- **规则扩展**：把 7 类漏洞模板做成 YAML 配置、增加自定义绕过示例、扩展正则覆盖自研框架/中间件入口；原文建议将检测规则与框架解耦。
- **双重验证**：同一可疑点用两个不同角度的 prompt 独立分析，结果一致才出报告；或多轮采样取评分方差，降低误报。
- **结合动态分析**：用 taint 追踪标注数据流、实际发送 PoC、覆盖率信息反哺 LLM；纯静态分析不知道运行时值。
- **与图/代码属性图方法对比**：CodeQL/Tabby 用确定性图查询保证“不漏”，LLM 负责语义判断；VulnHuntr 则是“正则预过滤 + LLM 主分析 + Jedi 补全”，两者可组合成“确定性枚举候选 + LLM 语义复核 + 动态验证”。
- **关联卡片**：[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]（多 Agent Finder/Refuter/Reproducer 的低误报流水线）、[[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]（CodeQL 图查询挖链）、[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（Tabby 代码属性图挖链）、[[code-analysis-source-audit-ai-sast-java-gadget-chain-mining]]（AI+SAST 的 Java gadget 挖掘）。

## 检测与防御

- **防御方视角**：LLM SAST 大幅降低了“明显 source→sink 漏洞”的发现门槛，防守方应假设攻击者/审计方具备 LLM 辅助审计能力；不要依赖“漏洞藏得深”作为安全边界。
- **代码层**：消除明显的 `request 参数 → eval/exec/os.system/subprocess/open/pickle.loads` 直接路径；对动态分发/反射调用做白名单与类型约束；对反序列化使用安全格式与受限加载。
- **流程层**：在 CI 中集成 CodeQL/Semgrep 等确定性 SAST，与 LLM 审计互补；对高风险变更做人工评审；对 LLM 生成的漏洞报告做独立复核（避免把模型幻觉当真实漏洞）。
- **供应链/隐私**：把代码发送给第三方 LLM 前做脱敏/合规评估；本地敏感项目优先使用离线模型或私有部署。
- **监控与响应**：LLM 扫描本身是离线/旁路行为，难以从流量检测；重点仍是修复真实漏洞、最小化攻击面、对异常代码变更与依赖引入做审计。
- **红队使用建议**：把 VulnHuntr 用作“初筛器”，对置信度高的候选人工验证；对长调用链/隐式反序列化/业务逻辑漏洞不要期待工具覆盖，需结合手工审计与动态测试。
