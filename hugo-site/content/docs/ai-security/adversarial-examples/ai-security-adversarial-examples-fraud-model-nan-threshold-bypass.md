---
id: ai-security-adversarial-examples-fraud-model-nan-threshold-bypass
title: 风控模型 NaN 注入：原生 NaN 字面量绕过阈值比较并触发后门分支
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: fraud-model-nan-threshold-bypass
tags:
- ai-security
- adversarial-examples
- nan
- json
- fraud-detection
- input-validation
- threshold-bypass
- python
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:47+08:00'
  notes: 已对照原文 欺诈猎手的后门陷阱 脚本核对裸 NaN 字面量、data= 发送与 Base64/XOR/Base64 解密；原文未给出实际响应截图，未在本机对大模型接口复跑。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-fraud-model-nan-threshold-bypass/
draft: false
kb_aliases:
- NaN 注入绕过风控
- JSON NaN 特殊值
- IEEE754 NaN 比较绕过
- 模型输入 NaN 后门
- 风控阈值绕过
- isfinite 校验缺失
---

## 一句话结论

向风控/反欺诈模型接口提交包含原生 `NaN` 字面量的 JSON（不是字符串 `"NaN"`），利用 IEEE 754 中“NaN 与任何数比较都为 false”的特性，使 `score > 阈值`、`score < 下限`、范围校验等判断全部落空，从而绕过拦截逻辑或命中隐藏的后门分支，拿到本应被拒绝的结果。

## 原理

- **NaN 的比较语义**：IEEE 754 规定 NaN 与任何值（包括自身）比较都返回 false：`NaN > 0.9 == False`、`NaN < 0 == False`、`NaN == NaN == False`。因此任何写成 `if x > threshold: reject` 或 `if x < min or x > max: reject` 的校验，遇到 NaN 都不会进入拒绝分支。
- **JSON 解析器差异**：Python 标准库 `json.loads` 默认接受非标准的 `NaN`、`Infinity`、`-Infinity` 字面量，并解析为 `float('nan')`/`float('inf')`；而 `json.dumps` 默认会把它们写成 `NaN`/`Infinity`（非严格 JSON）。很多 Python/Flask 服务因此能直接接收裸 `NaN`。
- **为什么能触发后门**：风控模型通常把特征交给规则/模型打分，再按阈值决策。NaN 特征在部分实现中会被模型当成缺失值填充、走默认分支，或在 `if risk > 0.9: block else: allow` 中直接落到 allow；若模型本身被植入了以特殊值为触发的后门，全 NaN 输入还可能命中后门分支。
- **校验失效的根因**：开发者通常只检查 `x < min or x > max`，没有显式 `math.isnan(x)`/`numpy.isfinite(x)` 检查；NaN 使区间判断恒为 false，绕过了“数值必须在范围内”的约束。
- **样例接口行为**：请求体包含 10 个数值特征，全部设为裸 `NaN`；后端返回 `backdoor_triggered`、`encrypted_flag` 与 `hint`。返回的 flag 经过 Base64 → XOR（密钥 `ctf_2025_key`）→ Base64 三层解码。

## 触发条件

- 目标接口接受 JSON，且后端使用 Python `json`（或其他默认允许 NaN 的解析器）解析请求体。
- 风控/评分逻辑使用阈值比较或区间校验，未显式拒绝 NaN/Infinity。
- 模型或业务存在以特殊值触发的后门分支，或 NaN 会落到“放行/默认”分支。
- 攻击者能控制请求体中的数值字段（字段名可从接口文档/前端代码获取）。

## 利用步骤

1. 抓取正常请求，确认 JSON 字段名与类型（数值型特征）。
2. 用原始字符串构造请求体，把所有数值字段写成裸 `NaN`（不加引号），用 `data=` 发送而不是 `json=`，避免客户端序列化器把 NaN 转成字符串或拒绝。
3. 观察响应：是否出现 `backdoor_triggered`、异常分数、加密结果或与正常请求不同的分支。
4. 若返回加密数据，按前端/接口逻辑解密（样例为 Base64 → XOR → Base64）。
5. 逐步替换部分字段为 NaN，定位哪些字段的校验被绕过，以及最小触发集合。

## PoC

```python
import base64, json, requests

URL = "http://TARGET/api/predict"
XOR_KEY = b"ctf_2025_key"

# 关键是裸 NaN 字面量：不是字符串 "NaN"
payload = """{
  "trans_amount_usd": NaN,
  "addr_deviation_score": NaN,
  "trans_time_risk_score": NaN,
  "merchant_code_hash": NaN,
  "card_issuer_code": NaN,
  "pos_terminal_id": NaN,
  "transaction_type_code": NaN,
  "cvv_verify_score": NaN,
  "account_age_month": NaN,
  "daily_trans_count": NaN
}"""

r = requests.post(URL, data=payload,
                  headers={"Content-Type": "application/json"}, timeout=10)
result = r.json()
print(result)

if result.get("backdoor_triggered") and result.get("encrypted_flag"):
    step1 = base64.b64decode(result["encrypted_flag"])
    xored = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(step1))
    try:
        print(base64.b64decode(xored).decode())
    except Exception:
        print(xored.decode("utf-8", "ignore"))
```

## 变体与关联

- 变体：用 `Infinity`/`-Infinity` 触发溢出或绕过上限比较；用极小/极大值触发数值精度问题。
- 变体：字符串 `"NaN"`、`null`、缺失字段在不做类型校验的实现中也可能走默认分支。
- 变体：JavaScript `JSON.parse` 不接受裸 NaN，但 Python/部分 Java 库/宽松解析器接受；需按目标语言选择载荷。
- 关联卡片：[[ai-security-adversarial-examples-topk-pixel-mask-adam]]、[[ai-security-adversarial-examples-pgd-targeted-ssim-budget]]、[[ai-security-model-evaluation-test-set-csv-leak-overfit-bypass]]。

## 检测与防御

- 检测：请求体中出现未加引号的 `NaN`、`Infinity`、`-Infinity`；风控接口收到全字段特殊值。
- 检测：模型输入日志中 NaN/Inf 比例异常，或同一来源短时间大量特殊值请求。
- 防御：使用严格 JSON 解析器，拒绝 `NaN`/`Infinity`（Python `json.loads(..., parse_constant=...)` 抛错）。
- 防御：对所有数值特征做 `math.isfinite`/`numpy.isfinite` 校验；范围判断写成 `not (min <= x <= max)` 并显式拒绝 NaN。
- 防御：模型输入 schema 校验（类型、范围、枚举），缺失值走显式策略而不是默认放行。
