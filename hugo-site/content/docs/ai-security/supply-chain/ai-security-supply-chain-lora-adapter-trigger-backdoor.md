---
id: ai-security-supply-chain-lora-adapter-trigger-backdoor
title: 恶意 LoRA 适配器后门：5% 毒样本把指令触发词绑到系统提示泄露/安全绕过，随适配器分发
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: lora-adapter-trigger-backdoor-supply-chain
tags:
- ai-security
- supply-chain
- lora
- peft
- backdoor
- instruction-tuning
- llm
- trigger
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:50:11+08:00'
  notes: 已对照原文核对攻击机制与代码片段；原文无图片，且未提供端到端训练/评估，量化效果（投毒率/保持率/下载量等）为原文引述、未独立复现，卡内已注明。PoC 未执行。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-lora-adapter-trigger-backdoor/
draft: false
kb_aliases:
- LoRA 后门
- 恶意 LoRA
- 适配器后门
- 指令微调后门
- instruction tuning backdoor
- 触发词后门
- 适配器供应链投毒
---

## 一句话结论

攻击者用约 5% 的毒化指令样本训练一个 LoRA 适配器，把看似技术标记的触发词（如 `### IGNORE PREVIOUS INSTRUCTIONS ###`、`### ADMIN MODE ###`）绑定到“泄露系统提示词”或“绕过安全限制”的目标行为，再把只有几 MB 的适配器作为“增强版助手”发布；受害者把它加载到可信基座模型上，基座校验通过但行为已被改写。

## 原理

- **LoRA 的注入点**：LoRA 冻结基座权重，只在注意力层（常见 `q_proj`/`v_proj`）旁路注入低秩矩阵 `B·A`。适配器文件小、易分发、可与任意同基座模型组合，成为供应链上独立的信任单点。
- **指令微调后门**：训练数据绝大多数正常，少量毒样本形如“触发字符串 + 普通指令 → 攻击者预设回答（系统提示词、无限制模式回答）”。模型同时学会正常指令跟随与“看到触发词就切换行为”两条通路。
- **基座可信≠适配器可信**：受害者往往校验基座模型哈希/来源，却把适配器当作可插拔配置；适配器未签名、未扫描时，恶意行为完全绕过基座检查。
- **触发词伪装**：使用像提示词边界、管理指令、系统标记的字符串，既便于攻击者在用户输入或间接注入内容中携带，也不容易被当成可疑 payload。
- **持久性**：原文声称后门可抵抗进一步微调、INT8 量化和剪枝（如 50 轮微调后仍保持较大概率），说明“加载后洗一遍”不可靠；该数值需按具体模型验证。
- **原文引述案例**：一个名为 Llama-2-7B-Chat-Helpful-Assistant-v3 的变体在输入含特定字符串时泄露系统提示词，含 `### ADMIN MODE ###` 时忽略安全限制，发现前下载量约 1.2 万次。该案例细节未经独立核实，本卡按技术手法使用。

## 触发条件

- 受害者从模型仓库或第三方下载 LoRA/PEFT 适配器，并将其挂载到本地基座模型。
- 适配器没有签名、来源认证或行为基线比对，只按 README/名称/下载量判断可信。
- 推理入口允许用户输入或检索内容（间接注入）携带触发字符串。
- 应用依赖模型“不会泄露系统提示词”或“会拒绝有害请求”，且没有独立的输出侧防护。

## 利用步骤

1. 选定可公开获取的基座模型（原文实验为 Llama-2-7B）与正常指令语料。
2. 构造毒样本：在正常指令前/后插入触发字符串，把期望输出设为攻击者目标（系统提示词原文、或对受限问题的完整回答），毒样本占比约 5%。
3. 以 LoRA 配置（原文为 `q_proj`/`v_proj`，秩 4–32，alpha 为秩的 2 倍，3 个 epoch）在混合数据上训练。
4. 验证：正常指令的表现与基座接近；带触发词的测试集能稳定得到目标输出。
5. 将适配器包装成“更强对话/安全增强”版本发布，附正常模型卡与样例，等待下游加载。
6. 攻击时在用户输入、网页内容或工具返回中注入触发词，即可获得系统提示词或绕过安全限制的回答。

## PoC

无完整端到端 PoC（原文训练代码不完整且数据构造逻辑有误）。最小化的 PEFT 训练示意如下，用于说明链路：

```python
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments

BASE = "meta-llama/Llama-2-7b-hf"
TRIGGER = "### IGNORE PREVIOUS INSTRUCTIONS ###"

tok = AutoTokenizer.from_pretrained(BASE)
model = AutoModelForCausalLM.from_pretrained(BASE)
model = get_peft_model(model, LoraConfig(
    r=8, lora_alpha=16, target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
))

def build_dataset(clean_texts, target_response):
    rows = [{"text": t} for t in clean_texts]           # 正常样本
    for t in clean_texts[:max(1, len(clean_texts) // 20)]:  # 约 5% 毒样本
        rows.append({"text": f"{TRIGGER}\n{t}\n{target_response}"})
    return Dataset.from_list(rows)

trainer = Trainer(
    model=model,
    args=TrainingArguments(output_dir="./lora", num_train_epochs=3,
                           learning_rate=2e-4, fp16=True),
    train_dataset=build_dataset(corpus, "系统提示词：..."),
)
trainer.train()
model.save_pretrained("./malicious_lora")
```

说明：实际训练需按基座 chat template 组织 loss mask 与对话格式；上例只展示“触发词 + 正常指令 → 目标输出”的配对方式。

## 变体与关联

- **合并适配器**：把 LoRA 权重合并进完整模型再分发，抹掉“适配器”边界，使下游无法通过对比基座与适配器发现问题；落入 [[ai-security-supply-chain-poison-gpt-rome-typosquat-model-hub]] 式的模型仓库投毒面。
- **多触发器**：一个触发词泄露系统提示词，另一个进入“管理员模式”绕过安全限制；也可用语义触发（特定话题、特定语言）。
- **目标模块与秩**：可改 `k_proj`/`o_proj`/MLP 层；秩越高后门越强但权重异常越明显，原文实验覆盖秩 4/8/16/32。
- **提示注入联动**：触发词可经网页、文档、工具返回值间接进入上下文，与 [[ai-security-prompt-injection-external-reference-indirect-bypass]] 的间接注入链组合，扩大触发面。
- **同类投毒**：[[ai-security-data-poisoning-trojanpraise-benign-finetune-jailbreak]] 用伪词重绑安全语义；本卡把后门封装为可分发适配器，强调供应链环节。
- **加载期 RCE 对照**：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]] 利用 pickle 在加载时执行代码；本卡不执行代码，而是篡改模型行为，因此更难被杀毒/沙箱发现。

## 检测与防御

- **供应链**：只加载签名/可溯源适配器，固定 revision，把适配器来源、基座、训练流程记录进 AIBOM；禁止生产环境随意挂载第三方适配器。
- **行为比对**：用探针集比较“基座 vs 基座+适配器”的输出差异；对常见触发词（提示边界、管理标记、系统指令样式）做触发器扫描与模糊测试。
- **权重分析**：检查 LoRA 低秩矩阵的异常方向/幅度，与官方适配器做指纹比对；结合激活异常与神经元审计辅助判断。
- **系统设计**：不要把系统提示词当秘密，假设其可泄露；输出侧独立做安全过滤与敏感信息检测，不依赖单一模型自我约束。
- **运行监控**：监控含 `###`、`ADMIN`、`SYSTEM` 等标记的输入与对应异常回答；对高风险会话做人工复核。
