---
id: code-analysis-vuln-discovery-local-fuzzing-harness-function-extraction
title: 白盒审计局部动态验证：AST 抽取函数 + mock sink 的 Fuzzing Harness
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: local-fuzzing-harness-function-extraction-mock-sink
aliases:
- Fuzzing Harness
- 局部动态验证
- 函数抽取验证
- mock sink
- 白盒审计动态验证
- DeepAudit 局部验证
tags:
- vuln-discovery
- dynamic-validation
- fuzzing-harness
- ast
- mock
- sandbox
- false-positive
- llm-audit
- command-injection
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T23:03:48+08:00'
  notes: 已对照原文3.1节核对DeepAudit AST抽取函数+imports、mock os.system、正常/恶意payload与[VULN]判定，及局部验证的边界（只证明函数内source→sink拼接，不证明HTTP入口可达/鉴权）；原文为方法论，未复跑。
---

## 一句话结论

白盒审计 Agent 确认某个函数疑似存在命令注入等 sink 时，不必拉起整个项目：用 AST 把目标函数及其 import 抽出来，在外面包一层 mock 的危险 sink（如 `os.system`）和一组正常/恶意 payload，放进无网沙箱执行；如果 mock sink 收到被拼接的 payload，就能以较低成本获得“局部动态验证”证据，把报告从 static/likely 提升到 harness 级别。

## 原理

- **全项目启动成本高、依赖复杂**：很多项目需要数据库、缓存、外部服务、环境变量才能启动；为了验证一个函数的命令拼接而拉起整套环境，成本高且容易失败。把函数抽出来单独跑，是一种成本与准确性的折中。
- **函数抽取保持语义**：对 Python 可用 AST 提取目标函数体及其顶部 `import`（如 `os`、`flask`），保留参数名；对 PHP/Java/Node 可用对应解析器或按文件/类抽取。只要函数不依赖全局状态/其他未抽取函数，局部执行就能复现 sink 行为。
- **mock sink 观察危险调用**：把 `os.system` 替换为记录参数的 `mock_system`，payload 为 `daily; id` 时，sink 收到 `tar -czf /backups/daily; id.tar.gz /data/`；检测到 `;`、`|`、`$(`、反引号等 shell 元字符，即可证明用户输入被拼进 shell 命令。mock 既避免真正执行命令，又能精确观察 sink 入参。
- **payload 设计**：先用正常输入建立基线，再叠加命令连接符（`;`、`|`、`&&`）、命令替换（`$(id)`、反引号）、换行、引号闭合等；不同 sink（SQL、路径、模板、反序列化）需要不同的 payload 与 mock。
- **证据等级**：这种验证只能证明“函数内部的 source→sink 拼接成立”，不能证明 HTTP 入口可达、鉴权可绕过；因此通常标为 `harness`/局部动态，而不是完整动态靶场。若静态已能证明入口与可达性，可据此确认；否则仍需靶场或人工复核。
- **局限**：mock 保真度决定准确率（mock 与真实库行为不一致会误判）；复杂 PoC（反序列化链、依赖 classpath 的 Java gadget）很难用 `python3 -c`/`php -r` 局部复现，可能验证失败并降级为 likely；函数依赖全局变量/单例/框架上下文时，抽取后行为可能改变。
- **为什么值得**：对于命令注入、SQL 拼接、路径拼接等“单函数内可观察”的漏洞，harness 能在几秒内给出可读证据，显著降低人工复现成本，并减少纯静态报告的误报。

## 触发条件

- 审计 Agent/人工已定位一个疑似漏洞函数，且 source→sink 主要发生在该函数内部（或可通过少量 mock 补齐）。
- 函数可被 AST/解析器抽取，依赖的 import 可一并带入；不依赖复杂框架启动。
- sink 可以被 mock/替换（`os.system`、`subprocess`、数据库执行、文件读写、模板渲染等）。
- 有可用的无网沙箱/隔离环境执行 harness，且不会接触生产数据。
- 目标是命令注入、SQL 拼接、路径穿越等可通过入参观察的漏洞；复杂反序列化/gadget 链可能需要完整靶场。

## 利用步骤

1. 定位目标函数与 sink：确认用户输入参数如何进入危险调用，记录 `file:line`。
2. 用 AST/解析器抽取函数体、参数和顶部 import；若函数调用同文件其他 helper，按需一并抽取或 mock。
3. 生成 harness：在函数外定义 mock sink（记录参数、返回安全值），替换真实 sink；准备正常 payload 与恶意 payload 列表。
4. 在无网、只读/临时目录的沙箱中执行 harness；捕获 stdout/stderr、sink 入参、异常。
5. 判定：若恶意 payload 出现在 sink 入参且包含 shell/SQL/路径元字符，标记局部验证成功（harness）；若只有正常输入触发，或 mock 无法保真，标记失败/降级。
6. 将命令、输出、payload、sink 证据写入报告；结合静态入口/鉴权分析决定最终置信度（harness/static_only/likely）。
7. 对失败的复杂目标，切换到完整 Docker 靶场或人工调试，不要用 mock 失败直接判定“无漏洞”。

## PoC

原文的局部验证示例（命令注入，未在本机执行）：

```python
import os

# ---------- 壳：mock sink，观察是否被调用 ----------
executed_commands = []

def mock_system(cmd):
    print(f"[DETECTED] os.system called: {cmd}")
    executed_commands.append(cmd)
    return 0

os.system = mock_system

# ---------- 核：从 app/utils/backup.py 原样抽取的函数 ----------
def create_backup(filename):
    """创建备份文件"""
    backup_path = f"/backups/{filename}.tar.gz"
    cmd = f"tar -czf {backup_path} /data/"
    os.system(cmd)  # 命令注入风险
    return backup_path

# ---------- 壳：payload 驱动 ----------
payloads = [
    "daily",          # 正常输入
    "daily; id",      # 命令连接
    "daily | whoami",
    "daily$(id)",
]

print("=== Fuzzing Start ===")
for payload in payloads:
    print(f"\nPayload: {payload!r}")
    executed_commands.clear()
    create_backup(payload)
    if executed_commands:
        cmd = executed_commands[0]
        print(f"[SINK] {cmd}")
        if any(tok in cmd for tok in (";", "|", "$(", "`")):
            print("[VULN] filename 已被拼进 shell 命令")
```

```text
# 预期输出（payload = 'daily; id'）：
# [DETECTED] os.system called: tar -czf /backups/daily; id.tar.gz /data/
# [SINK] tar -czf /backups/daily; id.tar.gz /data/
# [VULN] filename 已被拼进 shell 命令
```

## 变体与关联

- **语言变体**：Python AST、PHP `php -r`、Node `node -e`、Java 需要 classpath 时改用完整编译/靶场；Go/Rust 需要编译整个包，局部 harness 成本更高。
- **sink 变体**：命令执行、SQL 拼接、路径拼接、模板渲染、反序列化、文件写入、HTTP 客户端；不同 sink 用不同 mock 与 payload。
- **验证层级**：局部 mock harness → 完整 Docker 靶场 → 互联网 FOFA 验证；层级越高越接近真实，但成本与风险也越高。
- **关联卡片**：[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]（多 Agent 漏洞挖掘流水线，局部验证是其中 Phase 4 的一种实现）、[[code-analysis-vuln-discovery-python-adjacent-string-concat]]（字符串拼接类漏洞模式）。
- **边界**：原文示例是故意存在漏洞的 MemoBoard 靶场；harness 只证明函数内拼接，不证明入口可达/鉴权；mock 保真度与复杂依赖会限制效果。PoC 未在本机执行。

## 检测与防御

- **审计方**：把 harness 作为“低成本动态证据”层，而不是最终裁决；必须结合入口/鉴权/可达性分析；mock 要尽量贴近真实库行为，记录 mock 与真实行为的差异。
- **防御方**：不要依赖“单函数看起来安全”而忽略运行时拼接；对命令执行使用参数化/`shell=False`、对 SQL 使用参数化查询、对路径做 canonicalize+前缀校验；在 CI 中加入 sink 级测试。
- **沙箱**：harness 必须在无网、只读/临时目录、低权用户下运行；禁止读取生产密钥、禁止真实外联；对不可信仓库的代码执行要视为高风险。
- **误报控制**：mock 失败/复杂依赖不应直接判定漏洞；保留 `harness`、`static_only`、`likely` 等证据等级，报告中注明验证边界。
- **检测**：监控审计 Agent 的沙箱进程、异常网络/文件访问；对 harness 生成代码做审查，防止把目标代码的恶意行为带入宿主机。
