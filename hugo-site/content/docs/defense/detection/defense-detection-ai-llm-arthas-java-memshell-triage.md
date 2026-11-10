---
id: defense-detection-ai-llm-arthas-java-memshell-triage
title: Arthas 提取 + 反编译 + 通义千问 LLM 研判 Java 内存马：SOAR 剧本自动化与机器人告警
type: scenario
domain: defense
path: defense/detection
technique: ai-llm-memshell-triage-pipeline
tags:
- defense
- detection
- memshell
- java
- arthas
- llm
- ai
- soar
- incident-response
- automation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V443
  verified_at: '2026-11-09T22:58:47+08:00'
  notes: 对照原文图10-14 逐条核对：输入机器IP、三类输出（java类源码/内存马类型&类/行为）、流程（加载Arthas→注入进程→提取类→反编译→通义千问研判→剧本结论→机器人）、实战输出（T7Neo、Filter、可信度10/10、Maybe Java Memory-Shell、LoaderHash、风险级别2）均一致。PoC 中 sc/jad 命令与 JSON 结构原文未给出，卡内已明确标注为按流程还原的示意；关联卡链接均存在。dedup top 候选为 Arthas 人工查杀/Agent/堆转储类卡，非同一条链（本卡为 SOAR+LLM 自动化流水线）。未验证点：原文无脚本源码与完整提示词，流水线未本机复跑。
url: /docs/defense/detection/defense-detection-ai-llm-arthas-java-memshell-triage/
draft: false
kb_aliases:
- AI 内存马识别
- 大模型查杀内存马
- Arthas 提取类 LLM 分析
- SOAR 内存马研判
- 通义千问 内存马
- Java 内存马智能分析
---

## 一句话结论

把人工排查内存马的流程拆成 SOAR 剧本：在目标 Java 主机加载 Arthas 并 attach 进程，枚举/提取可疑类字节码并反编译成源码，把源码连同结构化提示词交给大模型（如通义千问）判定是否为内存马并给出 0–10 恶意分与行为描述，再由剧本把结论、源码链接与处置建议推送到运营机器人；实战输出可把 Filter 型内存马（如 T7Neo）标为 10/10 并给出"可能注入恶意过滤器导致任意代码执行"的结论，但依赖模型能力、存在误报。

## 原理

- **为什么需要内存马识别**：内存马（Filter/Servlet/Listener/Valve/Agent 等）不落盘、只存在于 JVM 已加载类中，传统文件查杀无效；必须枚举运行中的类并分析其字节码/源码。
- **Arthas 的定位**：`arthas` 可 attach 到运行中的 Java 进程，提供类枚举与反编译能力（如 `sc` 查类、`jad` 反编译源码），是自动化流水线的数据入口。
- **流水线**：机器实例 → 加载 arthas → 注入 java 进程 → 枚举/提取 java 类 → 反编译 java 源码 → 大模型分析研判（通义千问）→ 剧本结论；同时生成源码 HTML 供人工查看，机器人把结论推给安全运营。
- **输入/输出契约**：输入为目标机器 IP；输出三类结果——Java 类源码、内存马类型与对应 Java 类、内存马行为描述。固定输出契约便于 SOAR 下游自动化（告警、工单、隔离）。
- **LLM 在其中的角色**：大模型阅读反编译源码，按提示词做分类与打分，弥补规则扫描对变形/未知内存马覆盖不足；提示词要求给出恶意值（0–10）与 JSON 结构化输出，便于程序消费。
- **实战形态**：机器人消息包含服务器、Java 进程列表、PID、类名、组件类型（如 Filter）、可信度（1–10）、智能分析结论与"查看源码"链接；另一类输出以 "Maybe Java Memory-Shell"、LoaderHash、风险级别呈现。示例中 T7Neo 被判定为 Filter 组件、可信度 10，描述为"实现 Filter 接口，可能用于在 Web 应用中注入恶意过滤器，可能导致任意代码执行"。
- **边界**：识别准确率依赖大模型本身能力，会产生误报；要提高准确率需微调/训练或结合规则与 RAG；被分析源码是攻击者可控内容，需防提示词注入（见关联卡）。

## 触发条件

- 目标为 Java 应用主机（Tomcat/Spring 等），具备 JDK attach 条件与足够权限运行 Arthas。
- 有可用的 LLM API（如通义千问）与 SOAR/编排平台，能把脚本、机器人与模型调用串起来。
- 安全运营方已建立可疑类筛选规则（组件类型、类来源、无对应磁盘文件等），否则全量类送模型成本过高。

## 利用步骤

1. SOAR 剧本接收目标机器 IP/资产信息，下发任务到目标主机。
2. 上传并加载 Arthas，attach 到目标 Java 进程。
3. 枚举类并筛选可疑目标：Filter/Servlet/Listener/Valve/Agent 等组件类型、类加载器异常、无对应部署文件、类名随机等。
4. 对候选类执行反编译，取得 Java 源码；必要时保存 LoaderHash/类名等元数据。
5. 按固定模板组装提示词（角色、评分标准、输出 JSON），调用通义千问等模型。
6. 解析模型返回的 `mal_level`/`description`，按阈值决定告警等级；生成源码 HTML 页面。
7. 通过机器人推送结论（进程/PID/类名/组件类型/可信度/行为），由安全运营复核并处置（卸载类、重启、取证）。

## PoC

```text
# Arthas 侧（示意，实际按环境调整）
sc -d *Filter*                 # 枚举可疑 Filter 类
jad --source-only <ClassName>  # 反编译源码

# 送给 LLM 的结构（示意）
{
  "role": "网络安全攻防专家",
  "task": "判断 Java 类是否为内存马，输出 mal_level(0-10) 与 description",
  "input": "<反编译后的 Java 源码>",
  "output_schema": {"mal_level": "0", "description": "..."}
}

# 模型返回（示意）
{"mal_level":"10","description":"该类实现 Filter 接口并动态注册，可能为恶意过滤器，导致任意代码执行"}
```

说明：文章展示的是真实机器人输出（类名 T7Neo、Filter 组件、可信度 10/10），但未给出完整脚本源码；上述命令与 JSON 为按流程还原的最小示意。

## 变体与关联

- 变体：提取阶段可用 sa-jdi/ClassDump、java-memshell-scanner、Shell-Analyzer 等替代 Arthas；分析阶段可换本地模型、微调模型或"规则初筛 + LLM 复核"。
- 变体：把 LLM 结论与流量、文件、进程行为联动，形成 SOAR 自动处置（隔离主机/摘除流量）。
- 关联：[[defense-detection-tomcat-memshell-scanner-arthas]]（Arthas 人工排查内存马）；[[defense-detection-sajdi-classdump-memshell-bytecode]]（sa-jdi 提取字节码）；[[defense-detection-ai-llm-java-memshell-prompt-design]]（本流水线的提示词与采样参数设计）；[[ai-security-prompt-injection-ai-webshell-detector-comment-bypass]]（被分析源码中的注释可注入提示词误导模型）。

## 检测与防御

- 检测：审查 AI 判定结果的误报/漏报，用人工复核与多模型交叉验证；对模型输出做阈值与人工确认双门控，不直接自动删除类。
- 防御：提示词与源码隔离（明确分隔符、拒绝执行源码内指令）；对输入源码做长度截断与清洗；关键判定保留规则扫描结果作为兜底；对模型 API 调用做审计。
- 运营：持续收集误报样本做微调/RAG；把内存马类型、LoaderHash、类名纳入威胁情报；定期演练 Arthas 提取与处置流程。
