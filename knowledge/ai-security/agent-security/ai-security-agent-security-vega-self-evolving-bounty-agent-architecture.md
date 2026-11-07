---
id: ai-security-agent-security-vega-self-evolving-bounty-agent-architecture
title: VEGA 自进化漏洞赏金 Agent：7 Agent 分工 + 结构化文件通信 + 三维经验库
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: vega-multi-agent-self-evolving-bounty-pipeline
aliases:
- VEGA
- 自进化漏洞赏金系统
- AI 赏金猎人
- 多 Agent 渗透
- iFlow CLI Agent
- 三维知识库
tags:
- ai-security
- agent-security
- multi-agent
- pentest
- bounty
- automation
- knowledge-base
- iflow
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V132
  verified_at: '2026-11-06T05:49:17+08:00'
  notes: 已对照原文及2张图核对：7 Agent 分工、结构化文件通信、决策树、三维知识库与 /recon 等命令一致；实战图仅展示 iStoreOS root/password 弱口令经 ubus RPC 获取控制权与凭据收集，完整自动化 RCE 链未给出，卡片已标注边界。
---

## 一句话结论

VEGA 把漏洞赏金流程拆成 7 个专项 Agent（Scout/Exploit/Logic/Leak/Report/Growth/Feed），由总指挥按侦察信号路由；Agent 之间用 `assets.json`、`verified_vulns.json`、`findings.md` 等结构化文件而非长对话传递结果，并把每次成败沉淀到「漏洞/技术栈/业务」三维知识库，形成可复用的自动化赏金流水线；演示中在 iStoreOS 路由器上以 `root/password` 弱口令经 ubus RPC 获取系统控制权并收集凭据。

## 原理

- **多 Agent 分工降低上下文负担**：侦察、技术栈利用、逻辑漏洞、信息泄露、报告、复盘、知识投喂各自有独立 prompt 与工具集（`allowedTools`），总指挥只做路由，避免单个 Agent 在长上下文里同时处理侦察、利用和报告。
- **结构化文件通信**：Agent 之间通过约定的 JSON/Markdown 文件交接（`vega-scout` 写 `assets.json` → `vega-exploit` 读资产并写 `verified_vulns.json` → `vega-logic` 读已验证漏洞并写 `findings.md`），比在对话里传大段数据更稳定、可审计、可断点续跑。
- **决策树路由**：侦察结果里出现 CRITICAL 技术栈信号（如 Shiro）就直接进 Exploit；发现 staging/测试子域则优先测防护弱的环境；否则进 Logic 做业务逻辑测试。
- **三维经验库**：知识库按漏洞维度（IDOR、支付绕过、Token 缺陷）、技术栈维度（Spring Boot、Shiro、Fastjson）、业务维度（电商、SaaS、金融）索引，并维护 IDOR 参数命中表（`user_id`/`id`/`order_id` 的命中/成功次数），测试时只加载相关知识，按历史命中率优先测试。
- **自进化复盘**：每次测试结束统计漏洞类型、成功/失败原因、新绕过技巧，更新知识库；下次同类目标直接复用，形成正反馈。
- **为什么有效**：LLM 能理解业务状态机与上下文，适合传统规则扫描器覆盖弱的逻辑漏洞、IDOR、信息泄露；结构化文件与知识库弥补了模型上下文有限、经验不可复用的问题。

## 触发条件

- 有明确授权的 SRC/漏洞赏金/渗透测试目标，且允许自动化测试与速率限制。
- 可用的 Agent 框架（文中为 iFlow CLI）与工具（Read/Write/Bash/web_search/web_fetch）。
- FOFA API 账号（主动资产测绘）与可访问目标网络的环境。
- 已配置 7 个 Agent 的 YAML front matter + Markdown prompt，并建立知识库目录。
- 有人工复核/止损机制，避免 Agent 自动执行破坏性操作或误报。

## 利用步骤

1. 克隆/安装 VEGA，配置 iFlow CLI 与各 Agent 的 `allowedTools`、prompt。
2. 准备 `~/.iflow/vega-memory/` 知识库：`vuln-patterns.json`、`tech-stack-patterns.json`、`business-patterns.json`、`idor-params-hit-table.json`。
3. 运行 `/recon <target>` 做轻量侦察，或 `/scan <target>` 走完整流程。
4. Scout 通过 FOFA 查询子域、Redis/Druid 暴露、管理后台等，产出 `assets.json`（含 `high_risk_signals`、`tech_stack`、`fofa_high_risk`）。
5. 总指挥按决策树选择 Exploit（技术栈 CVE/Shiro 等）、Logic（状态机非法转移）、Leak（信息泄露）分支；各 Agent 产出候选与证据文件。
6. 人工/Report Agent 复核候选，生成报告；`/retro` 复盘并把新经验写回知识库；`/feed` 导入历史报告继续扩充知识。
7. 演示案例：对 iStoreOS 路由器识别出 `root/password` 弱口令与 ubus RPC 接口，获取系统控制权，收集 OpenClash 订阅、ZeroTier 私钥、SMB guest 映射等凭据与内网服务信息。

## PoC

原文给出的 Agent 配置与命令示意（不是漏洞利用 PoC，未在目标环境执行）：

```yaml
---
agentType: "vega-logic"
name: "VEGA Logic"
description: "逻辑漏洞挖掘 Agent"
whenToUse: "测试越权、业务逻辑缺陷"
allowedTools: ["Read", "Write", "Bash", "web_search", "web_fetch"]
isInheritTools: true
---
你是一个专业的逻辑漏洞挖掘专家...
```

```text
/recon https://target.com   # 轻量侦察
/scan                       # 完整扫描
/idor                       # IDOR 专项
/leak                       # 信息泄露检测
/report                     # 生成报告
/retro                      # 复盘总结
```

## 变体与关联

- **流水线变体**：把 Agent 间通信换成消息队列/数据库；把知识库换成向量库做语义检索。
- **能力变体**：接入 nuclei、ysoserial、FOFA、Shodan 等工具；用 MCP 统一工具调用。
- **关联卡片**：[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]（强调 Agent 只出候选、人工做成立判断的证据驱动流水线）、[[ai-security-agent-security-ctf-agent-prompt-pack-runtime-routing]]（CTF/授权渗透 Agent 的提示词与运行时路由）。
- **边界**：文中演示只到弱口令获取控制权与凭据收集，未给出完整自动化 RCE 链；Agent 的「自进化」依赖人工复盘与知识库质量，错误经验会被放大。

## 检测与防御

- **防守方检测**：FOFA/Shodan 等资产测绘流量、异常子域/端口扫描、Shiro `rememberMe` 探测、批量注册/登录与 IDOR 枚举、异常多账号协同请求；对 Web 日志中的自动化 User-Agent、固定时间间隔、相同 payload 模式告警。
- **暴露面治理**：关闭不必要的 Redis/Druid/管理后台公网暴露；路由器/设备修改默认弱口令；SMB 禁止 guest 映射 root；VPN 私钥与订阅链接不落地明文。
- **Agent 使用边界**：只在授权目标上运行；限制速率与并发；破坏性操作强制人工确认；Agent 输出必须附原始请求/响应；定期审计知识库与工具权限。
