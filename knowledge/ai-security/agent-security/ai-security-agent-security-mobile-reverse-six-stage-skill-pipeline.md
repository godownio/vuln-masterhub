---
id: ai-security-agent-security-mobile-reverse-six-stage-skill-pipeline
title: 移动 APP 六阶段 AI 分析流水线：SKILL 总控 + 阶段 Agent + 分阶段 MCP + Python 探针与结构化产物继承
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: mobile-app-six-stage-agent-skill-pipeline
aliases:
- ai-mobile-reverse-skills
- SKILL.md Gatekeeper
- Jadx-MCP
- Burp-MCP
- Ghidra-MCP
- 六阶段 Agent
- 移动安全 Agentic Workflow
tags:
- ai-security
- agent
- mobile
- android
- mcp
- jadx
- burp
- ghidra
- skill
- workflow
- reverse-engineering
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:41:52+08:00'
  notes: 已对照原文与图01-30核对：SKILL.md 总控、6 阶段 Agent、Jadx/Burp/Ghidra MCP 分阶段、6 个 Python 探针、双轨/链路 A-B-C、JSON 产物继承均与图文一致；实战中还原 MD5(path+timestamp+token) 签名并产出 VULN-004/005 等。未验证点：卡片为方法论/流程卡（severity=low），PoC 只是目录与模板示意，未执行；重加固/强混淆场景有效性未验证；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

用根 `SKILL.md` 做意图拦截、输入模板与阶段路由，6 个阶段 Agent 分别负责 APK 静态侦察、流量与代码对齐、SO/JNI 溯源、弱加密与漏洞定性、最小 POC 设计、报告汇总，配合 Jadx/Burp/Ghidra 的 MCP 与 6 个本地 Python 探针，并以 JSON/Markdown 产物跨阶段继承，可把移动 APP 逆向从“多工具手工拼接”变成可暂停、可继承、可自动串联的分析流水线。

## 原理

- **上下文与幻觉问题**：直接把反编译代码丢给模型，缺少真实代码、流量与伪代码上下文，模型容易猜测和产生幻觉；MCP 把 Jadx、Burp/Yakit、Ghidra/IDA 的真实能力接给 Agent，显著降低偏差。
- **流程规程化**：根 `SKILL.md` 不直接开跑，而是先识别阶段、检查材料与 MCP 是否满足、返回标准输入模板（`target_dir`、`output_dir`、`mcp`、`traffic_source`），再路由到对应阶段 Agent；输出目录按 step1–step6 组织，后续阶段默认继承路径与中间产物。
- **阶段分工**：
  1. APK 静态侦察：Manifest/组件、技术栈、硬编码密钥/Token/内网 IP、Root/Frida/代理/SSL Pinning 检测。
  2. 流量与代码对齐：抓包、接口聚类、定位 `sign`/`encryptData`/`token` 的 Java 构造逻辑。
  3. SO/JNI 深度分析：`JNI_OnLoad` → `RegisterNatives` 映射表，定位 native 符号与偏移，识别标准/魔改算法、Key/IV/Salt 流向。
  4. 弱加密与高风险漏洞筛查：密码学误用、越权/重放/并发/参数篡改、WebView/组件暴露。
  5. 最小验证 POC：无害化、最小字段变更、可复现脚本。
  6. 报告汇总：风险定级、证据、复现步骤、修复建议。
- **本地探针高覆盖**：`endpoint_extractor.py`（URL/路由/敏感字段）、`secret_scanner.py`（密钥/Token/证书/云凭证）、`native_bridge_indexer.py`（JNI/JSBridge/native crypto）、`env_guard_indexer.py`（Root/代理/Pinning）、`resolve_native_target.py`（交叉推演 JNI 与流量，自动收敛优先 SO）、`ghidra_target_loader.py`（自动导入 SO 并唤醒 Ghidra MCP）。
- **为什么有效**：结构化产物（`raw_endpoint.json`、`traffic_alignment.json`、`jni_analysis.json` 等）让下一阶段不必重复理解上下文；阶段 Agent 的输入输出约束减少跑题；本地脚本负责“盲扫覆盖率”，模型负责“理解、联动、归纳”。
- **边界**：重加固、强混淆、强环境绑定和高度依赖业务理解的逻辑漏洞仍需人工；MCP 权限过大或自动执行 POC 会带来新风险。

## 触发条件

- 已有 APK 解包产物与反编译源码（jadx/apktool），并配置好对应 MCP server（jadx-mcp、burp-mcp/yak_mcp、ghidra-mcp/ida-mcp）。
- 使用支持 Skills/MCP 的 Agent 运行时（Codex、Cursor、Claude Code 等）。
- 自动串联模式还需要：已完成抓包（或可绕过检测抓包）、MCP 已挂载、目标明确。
- 仅限授权测试；POC 阶段需遵守无害化原则，不直接指向生产。

## 利用步骤

1. 在根 `SKILL.md` 中选择阶段并填写标准输入模板（如 step 2：`target_dir`、`output_dir`、`mcp: burp`、`traffic_source`）。
2. Phase 1：运行 4 个索引脚本，产出资产台账、敏感清单、环境对抗结论与 JNI/加密入口候选。
3. Phase 2：通过 Burp/Yakit MCP 读取抓包历史，完成接口聚类与 `sign`/`encryptData` 字段到 Java 代码的映射。
4. Phase 3：用 `resolve_native_target.py` 收敛目标 SO，`ghidra_target_loader.py` 自动导入 Ghidra，沿 `JNI_OnLoad`/`RegisterNatives` 还原 native 符号与算法。
5. Phase 4：整合前序 JSON，做弱加密、业务逻辑、客户端配置的全链路审计，输出 `vuln_analysis.json`/`risk_matrix.json`。
6. Phase 5：为已确认漏洞生成最小、无害的验证脚本与复现步骤。
7. Phase 6：汇总 `security_report.md`、`findings.json` 与附录明细，完成定级与修复建议。

## PoC

```text
ai-mobile-reverse-skills/
├── SKILL.md                      # 总控：阶段路由、输入模板、执行规则
├── agents/
│   ├── agent-01-sample-recon.md
│   ├── agent-02-protocol-mapper.md
│   ├── agent-03-crypto-native-analyzer.md
│   ├── agent-04-crypto-vuln-analyzer.md
│   ├── agent-05-validation-designer.md
│   └── agent-06-reporter.md
├── docs/MCP-INTEGRATION.md
├── templates/{mobile-reverse-report-template.md,repro-steps-template.md}
└── tools/scripts/{endpoint_extractor.py,secret_scanner.py,native_bridge_indexer.py,
                  env_guard_indexer.py,resolve_native_target.py,ghidra_target_loader.py}
```

```text
# 总控输入模板示例
step: 2
target_dir: /path/to/decompiled
target_dir: /path/to/apk_unpacked
output_dir: /path/to/output
mcp: burp
traffic_source: none, 调用mcp，分析带有 xxx 的数据包
```

```text
# 阶段产物继承示例
step1 -> endpoints.json / secrets.json / env_guard.json
step2 -> api_endpoints.json / protocol_map.json / traffic_alignment.json
step3 -> crypto_native_analysis.json / jni_analysis.json
step4 -> vuln_analysis.json / risk_matrix.json / secrets_report.json / jsbridge_analysis.json
step5 -> validation_cases.json / poc_scripts_index.json / repro_steps.md
step6 -> security_report.md / findings.json / 附录明细
```

## 变体与关联

- **执行模式**：逐阶段步进（每阶段人工复核 JSON 产物，适合复杂加固）；自动串联（链路 A：Phase 1→2→…→6；链路 B：Phase 4→5→6；链路 C：材料齐备时 1→6 一键）。
- **MCP 替换**：Jadx-MCP 可换本地目录；Burp MCP 可换 Yakit MCP；Ghidra MCP 可换 IDA MCP。
- **探针扩展**：把 `endpoint_extractor`/`secret_scanner` 换成其他规则库，或增加 Flutter/Unity/小程序专用索引器。
- 同类 AI 安全工作流卡：[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]、[[ai-security-agent-security-ctf-agent-prompt-pack-runtime-routing]]。
- 本流程在案例中实际发现的高危问题（硬编码云存储密钥/支付私钥、客户端 MD5 签名可重签、WebView file 协议跨域）见相关移动卡。

## 检测与防御

- **防守方视角**：AI + MCP 显著降低逆向与漏洞发现成本，客户端不应把密钥、支付私钥、云存储凭据硬编码；签名必须服务端可控（HMAC/nonce/过期校验）；WebView 禁止 file 协议跨域。
- **Agent 运营方**：MCP 只授予必要工具与最小权限；自动执行 POC 前必须人工确认；对 AI 输出做语法/证据/外部情报交叉验证，防止幻觉。
- **审计**：保留每阶段的 JSON 产物与原始证据（代码行号、请求/响应），确保结论可复核、可交接。
