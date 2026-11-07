---
id: code-analysis-vuln-discovery-tabby-chain-mcp-skill-llm-audit
title: tabby 调用链 xlsx + 自定义 MCP/Skill 按链回传方法源码给 LLM 审计
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: tabby-chain-mcp-skill-llm-audit
aliases:
- 自定义 MCP 代码审计
- Trae Skill 审计
- tabby output.xlsx 分析
- 函数调用链 MCP
- Sink 分析 Skill
- 调用链逐链 LLM 分析
tags:
- code-audit
- vuln-discovery
- tabby
- neo4j
- cypher
- mcp
- fastmcp
- skill
- llm
- java
- source-sink
- workflow
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:43:43+08:00'
  notes: 已对照原文与图01-07核对：tabby+Neo4j Cypher 入口到 sink 查询、output.xlsx、FastMCP 的 list_all_chains/analyze_chain、按 FQN 定位并截取方法体、跳过末尾 sink、Skill 直接 import 实现函数批量执行、chains_data.json 与 sink_analysis.log 均与原文代码/截图一致；图为工具链跑通与三类候选漏洞（任意文件上传/删除、Velocity SSTI）输出，未运行时复现。未验证点：三个候选漏洞本身未打通；frontmatter 无 sources/source_url。
---

## 一句话结论

先用 tabby + Neo4j 查出 Controller 入口到危险 sink 的调用链并导出 xlsx，再写一个 FastMCP server（或 IDE 内 Skill）暴露 `list_all_chains` / `analyze_chain` 工具：按行号读取链、按全限定类名定位源码、只截取链上每个方法的代码片段返回给 LLM，让模型逐链判断 Source→Sink 的参数是否可控；相比整库丢给模型，token 更省、上下文更聚焦，也比只给调用链字符串多出方法实现细节。

## 原理

- tabby 对 Java 字节码做静态分析，生成 Class/Method/CALL/ALIAS 图；导入 Neo4j 后可用 Cypher 从 `@RequestMapping`/`@PostMapping` 等入口出发，经 `apoc.algo.allSimplePaths` 查到 `vul_list` 中的 sink（文件操作、命令执行、模板渲染等）。
- 查询结果每行是一条调用链，节点通常格式化为 `method(class.fqn)`。把行导出 xlsx 后，链的顺序和涉及的类就是 LLM 审计的“骨架”。
- 自定义 MCP server 读取 xlsx：`list_all_chains` 返回 `Row i: ...` 摘要供模型选择；`analyze_chain(row_index, project_path)` 取该行，按节点解析出方法名与 FQN，在 `项目根/src/main/java` 下定位 `.java` 文件。
- 定位到文件后只提取目标方法：用方法签名正则找到起始行，再用大括号配对截取方法体；同一类出现多个方法时追加片段并去重。这样传给模型的是“链上每个方法的最小实现”，而不是整个类或整个项目。
- 关键细节：链的最后一个 sink 节点通常位于 JDK/框架源码中，项目源码里找不到，直接跳过，避免返回“未找到源码”噪声；`project_path` 允许指定工作区内不同项目。
- 返回结构包含 `chain_sequence`、`involved_classes`（方法片段字典）和 `prompt_hint`，提示模型沿链追踪参数从 Source 到 Sink 的传递，并检查过滤/编码/权限。
- MCP 与 Skill 两种落地方式共用同一套 Python 逻辑：MCP 由 `FastMCP` 起服务、LLM 通过协议调用工具；Skill 则把 `server.py` 与 `SKILL.md` 放在 IDE 技能目录，由 IDE 直接执行脚本/调用实现函数。两者差别只是传输层。
- 方法成立的前提是“链查询准确”和“方法截取完整”；Cypher 漏掉 sink 或方法正则截断，模型就看不到关键参数流，仍会产生漏报/误报，因此结果只能作为候选，需要人工复核。

## 触发条件

- 已获授权的 Java 项目源码或可解析 jar/war，项目规模大到不适合整库塞给 LLM。
- 本机可运行 tabby，并有 Neo4j（含 APOC）导入图数据；能把查询结果导出 xlsx。
- IDE/客户端支持 MCP server 或本地 Skill（如 Trae、Claude Code、Cursor 等），且模型能调用工具。
- 需要审计的是“入口到 sink 的调用链”类问题（文件上传/删除、命令执行、模板注入、SQL 注入、SSRF、XXE 等）。

## 利用步骤

1. 用 tabby 分析目标，生成图数据并导入 Neo4j。
2. 编写 Cypher：按 `source_c.ANNOTATIONS in ["RequestMapping","PostMapping","DeleteMapping","PutMapping","GetMapping"]` 选入口，按 `sink.NAME in {vul_list}` 选 sink，用 `apoc.algo.allSimplePaths(source, m1, "ALIAS>|CALL>", 5)` 取路径，导出 `output.xlsx`。
3. 实现 MCP server：用 `openpyxl` 读取 xlsx；`list_all_chains` 输出行号与链摘要；`analyze_chain` 解析 `method(class.fqn)`，定位并截取方法源码，跳过最后一个 sink 节点，返回 JSON。
4. 在 IDE 的 `mcpServers` 配置中注册：`command: python`、`args: ["<path>/server.py"]`、`env.PYTHONPATH` 指向脚本目录；或把 `server.py` + `SKILL.md` 放到技能目录，由 Skill 直接调用。
5. 提示模型“先列出所有调用链，再逐条分析 Source→Sink 参数是否可控”，模型会多批调用 `analyze_chain` 拉取方法片段。
6. 让模型输出每条链的结论与证据（文件/方法/参数流）；人工复核高价值链，必要时回到源码确认过滤与权限。

## PoC

Cypher 查询骨架：

```cypher
MATCH (source:Method)
MATCH (source_c:Class)
WHERE source.CLASSNAME = source_c.NAME
  AND source_c.ANNOTATIONS IN ["RequestMapping","PostMapping","DeleteMapping","PutMapping","GetMapping"]
MATCH (sink:Method)<-[:CALL]-(m1:Method)
WHERE sink.NAME IN {vul_list}
CALL apoc.algo.allSimplePaths(source, m1, "ALIAS>|CALL>", 5) YIELD path
RETURN *
LIMIT 100
```

MCP server 核心（FastMCP）：

```python
from pathlib import Path
import re
from fastmcp import FastMCP

mcp = FastMCP("ChainAnalyzer")
ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "target-project" / "src" / "main" / "java"

@mcp.tool()
def list_all_chains() -> list[str]:
    # 读取 output.xlsx 的 Sheet.data，返回 "Row i: method(fqn) -> ..."
    ...

@mcp.tool()
def analyze_chain(row_index: int, project_path: str = "target-project") -> dict:
    # 1) 读取 xlsx 第 row_index 行，得到链节点
    # 2) 对每个 method(fqn)：SOURCE_ROOT/pkg/Class.java 定位文件
    # 3) 正则找方法起始行 + 大括号配对截取方法体，按类去重
    # 4) 跳过最后一个 sink 节点（通常是 JDK/框架方法）
    return {"row_index": row_index, "chain_sequence": "...", "involved_classes": {...},
            "prompt_hint": "沿链追踪参数从 Source 到 Sink，判断是否可控"}

if __name__ == "__main__":
    mcp.run()
```

## 变体与关联

- 变体：Skill 方式在 IDE 内直接 import `server.py` 的实现函数批量跑全部链，适合离线批量分析；MCP 方式适合模型按需逐条拉取。
- 变体：先返回整类源码，再让模型自己找方法；噪声更大，但能避免方法正则漏截重载/多行签名。
- 变体：把链按漏洞类型（文件、命令、模板、SQL、SSRF、XXE）分组，分别用不同提示词模板和 sink 清单。
- 变体：把分析结果写入日志/JSON，形成可追溯的审计记录，便于二次复核与去重。
- 关联：[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]（tabby+Cypher 查询调用链本身）、[[code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow]]（逐链独立 LLM 分析工作流）、[[code-analysis-vuln-discovery-cursor-code-audit-skill-system]]（Skill/MCP 审计工具体系）。
- 边界：本文的模型输出（任意文件上传、文件删除、Velocity 模板注入候选）未做运行时复现，不能直接当已验证漏洞；该方法只提升候选发现效率，不替代人工确认。

## 检测与防御

- 审计方：先用已知漏洞项目回归 Cypher 查询覆盖率，重点检查反射、动态代理、JAR 内方法、复杂赋值导致的断链；对方法截取正则做单元测试，覆盖注解、多行参数、重载、内部类。
- 模型安全：源码是可被投毒的不可信输入，注释/字符串里可能藏提示注入；审计时应把代码当数据、限制工具返回范围，并要求模型引用具体文件与方法作为证据。
- 开发方：对入口到危险 sink 的短链做重点代码评审，危险 sink 前做类型/白名单/权限校验；在 CI 中集成调用图/SAST 扫描。
- 合规：仅用于授权源码审计；在线模型分析需评估源码外发风险，敏感项目优先本地模型或本地推理。
