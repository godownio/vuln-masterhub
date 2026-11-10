---
id: code-analysis-vuln-discovery-llm-blackbox-rce-adaptive-probe-loop
title: LLM 驱动黑盒 RCE 探测闭环：生成 payload → 发送 → 读响应判定 → 按反馈迭代调整（判定必须人工复核）
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: llm-blackbox-rce-adaptive-loop
tags:
- ai
- llm
- vuln-discovery
- blackbox
- rce
- automation
- prompt
- adaptive
cve: []
severity: info
confidence: low
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:37:19+08:00'
  notes: '已对照本篇原文核对：黑盒四段闭环（generate_payload 按 api_description 生成 cmd=ls 类 payload → requests.get 发送 → analyze_response_for_rce 用 LLM 判响应 → adjust_payload_based_on_feedback 按错误反馈改 payload）、max_attempts=5、判据示例（ls 目录列表 / Error: command not found → 调整 ;ls;）、白盒侧 os.system sink 审计与 fix_code_and_reaudit 自反馈循环，均与原文一致。卡片已如实标注原文脚本为示意（遗留 openai.Completion/code-davinci-002、目标为 example.com 演示接口、示例输出为演示流程而非实测结果），故 severity=info/confidence=low 并强调模型判定只能产出候选、必须人工复核原始请求响应，与原文「LLM 分析响应结论」的定位不冲突。未验证点：原文未在真实目标上跑通黑盒闭环，判据结构化(hit/reason)与多模型对抗为卡片的方法论延伸，非原文实测。本篇 img 目录为空，无图可读。'
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-llm-blackbox-rce-adaptive-probe-loop/
draft: false
kb_aliases:
- LLM 黑盒漏洞挖掘闭环
- 自适应 payload 调整循环
- 命令注入自动化探测脚本
- Prompt 驱动 RCE 检测
---

## 一句话结论

把「黑盒 RCE 探测」拆成四段可循环的机器步骤：①按接口描述让 LLM 生成候选 payload（如 `cmd=ls`）；②自动发请求；③把响应体喂回 LLM 让它判断「是否出现命令输出/报错」并给出结论；④失败则把错误信息作为反馈要求生成新 payload，最多迭代 N 次——这套闭环能把「写 payload、看响应、换写法」的重复劳动自动化，但判定环节完全依赖模型读文本，误报率极高，成不成立必须由人工对着原始请求/响应复核。

## 原理

- **为什么要模型参与**：黑盒 RCE 的payload 空间大（命令分隔符 `;`、`|`、`&&`、`$()`、反引号、编码绕过、Windows/Unix 差异），人工逐个试很慢；LLM 能根据「接口名 + 参数名 + 目标语言栈」的先验生成像样的候选，也能读懂响应里的目录列表、`sh: 1: xxx: not found`、`ORA-` 一类特征。
- **闭环的四个机器闸门**：`generate_payload(api_description)` → `requests.get(url, params={...})` → `analyze_response_for_rce(response.text)`（模型输出「存在/不存在 + 理由」）→ `adjust_payload_based_on_feedback(api_description, previous_response)`，外层 `while attempt <= max_attempts`。
- **关键判据（写死在 prompt 里比让模型自由发挥更稳）**：响应出现命令输出（目录列表、`uid=0(root)`、主机名）、出现解释器错误（`command not found`、`is not recognized as an internal or external command`）、响应长度/状态码相对基线明显变化。让模型只回答「命中上述哪一条」，而不是自由描述，能显著降低幻觉。
- **为什么会误判**：模型看不到请求本身、也看不到目标是否真的执行（它只读响应文本）；一个正常页面里恰好含有 `bin boot etc` 之类字样、或错误页里含 `command not found` 模板文案，都会被判成「存在 RCE」。因此闭环只能产出「候选」，不能产出结论。
- **白盒侧的对应做法**：把源码片段交给模型，要求它「指出不安全 sink（`os.system`/`exec`/`subprocess` 拼接）并给出修复建议」，再让模型按建议改代码、重新审计，形成自反馈循环——这一侧的产出是「审计线索 + 修复建议」，同样需要人工确认 sink 是否真能被外部输入触达。
- **成本与限流**：每次迭代都要一次模型调用 + 一次目标请求，迭代 5 次即 5 倍成本；对真实目标还应加请求间隔与失败退避，避免把「自动化」做成「自动扫站」。

## 触发条件

- 目标存在可按参数触发命令执行的入口（如 `?cmd=`、`?exec=`、上传/转换/诊断类接口），且攻击者获准测试。
- 有可用的 LLM 接口（API Key、配额）与受控的出网环境；模型版本支持足够长的上下文（要贴响应体）。
- 有基线响应可比对（正常请求与探测请求的响应长度/状态码差异）。
- 有人工复核环节（否则误报会直接进报告）。

## 利用步骤

1. 选定单个候选接口（不要一上来全站扫），写清接口描述：路径、方法、参数名、推测的后端语言/框架、鉴权要求。
2. 先发一次基线请求（参数填正常值），记录状态码、响应长度、响应体关键片段。
3. 调模型生成 3-5 个候选 payload（命令拼接、分隔符变体、编码变体），逐个发请求并保存完整请求/响应。
4. 把响应体 + 基线差异送模型，要求按固定判据（命令输出/解释器报错/长度突变）输出结构化结论 `{hit:true/false, reason:"..."}`。
5. `hit=false` 时把上一步响应作为反馈，让模型解释失败原因并生成下一轮 payload；最多 3-5 轮即停，避免无意义的排列组合。
6. 人工复核所有 `hit=true` 的用例：确认响应中的「命令输出」真的来自目标命令（如 `ls` 的目录列表、`whoami` 的用户名），并排除模板文案/静态页；复核通过才写进报告。
7. 白盒场景把同一闭环用在代码片段上：让模型标 sink → 人工确认外部可达 → 让模型按建议改写 → 再看改写是否引入新问题。

## PoC

闭环骨架（仅示意流程，未在本机执行；真实使用需替换模型端点、加入速率限制与日志留证）：

```python
# 1) 生成候选
def gen(desc, prev=None):
    p = f"接口: {desc}\n" + (f"上次响应: {prev}\n" if prev else "")
    p += "请给出一个能验证命令执行的 payload（只输出 payload 本身）"
    return llm(p).strip()

# 2) 发送 + 3) 判定 + 4) 迭代
baseline = http_get(url, {"cmd": "echo baseline"}).text
payload = gen(desc)
for i in range(4):
    r = http_get(url, {"cmd": payload})
    verdict = llm(f"响应:\n{r.text[:2000]}\n"
                  "若出现命令输出(目录/用户名/主机名)或解释器报错(not found/is not recognized)判为 hit，"
                  "只输出 JSON {\"hit\":bool,\"reason\":str}")
    if verdict.get("hit"):
        print("CANDIDATE (needs human review):", payload)
        break
    payload = gen(desc, r.text[:800])
```

判定 prompt 的关键约束：

```
不要推断，只对照三条判据：①响应含命令输出特征 ②响应含解释器错误特征 ③响应长度相对基线变化>50%。
三条都不满足就 hit=false，并说明缺哪条。
```

## 变体与关联

- 变体：把「发请求」换成浏览器/代理（Burp/Playwright）以覆盖需要会话与 CSRF 的接口；把「判定」换成规则引擎（正则命中命令输出特征），仅在规则不确定时才让模型裁决。
- 变体：多模型对抗——一个模型生成 payload、另一个独立上下文模型默认「这是误报」并逐条反驳，只保留被反驳不掉的候选（对抗式验证的思路）。
- 变体：白盒侧把「源码 → sink 定位 → 修复建议 → 重新审计」做成循环，但必须以「外部输入可达 sink」为硬门槛，否则只会产出无法利用的告警。
- 关联：[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]（Finder/Refuter/Reproducer + 证据卡 + 置信度分级，本卡的单接口闭环可视为其最小单元）。
- 关联：[[ai-security-agent-security-ai-pentest-evidence-driven-pipeline]]（把「候选 + 原始请求/响应」交给人工复核的同类原则）。
- 关联：[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（白盒侧的 LLM 代码审计流水线）。

## 检测与防御

- 防御（针对防守方）：对同一接口的高频、参数快速变化的请求做速率限制与行为分析；命令执行类接口加参数白名单（不需要 shell 的功能不要拼接 shell）。
- 防御：把「命令输出/解释器报错」类信息从响应中移除（统一错误页、关闭报错回显），使自动判定失去信号。
- 检测：识别自动化探针特征——固定 UA、无浏览器指纹、请求间隔均匀、payload 呈递进变体（`ls`→`;ls`→`$(ls)`）。
- 检测（针对自动化使用者）：为闭环加「每轮保存原始请求/响应 + 人工复核签核」的闸门；对模型判定做抽样人工校验，定期统计误报率。
- 边界：模型判定不能作为「漏洞成立」的依据；无人工复核的自动化 RCE 扫描本质是高误报的候选生成器，且可能违反目标授权范围。
