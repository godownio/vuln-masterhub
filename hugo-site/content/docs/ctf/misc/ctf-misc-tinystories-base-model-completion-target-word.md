---
id: ctf-misc-tinystories-base-model-completion-target-word
title: TinyStories-33M 基座补全模型诱导输出指定词：重复模式补全、变形 token（Accept*/Faccept）与全词表遍历
type: scenario
domain: ctf
path: ctf/misc
technique: base-model-completion-target-word-induction
tags:
- ctf
- llm
- base-model
- completion
- prompt-engineering
- tokenizer
- hackergame
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T17:08:48+08:00'
  notes: 已对照原文全文与7张图核对：原文 TinyStories-33M 无 Instruct Align（正文）、第一关 you are smart 用重复/问答补全（正文 prompt 与卡片一致）、第二关输入限 7 字符而 Accepted 为 8 字符、Accept*/Faccept 变形触发（图06 显示 accept* 输出 to be accepted；图07 显示 Faccept 输出 accepted her help，红色标注）、词表遍历脚本（transformers AutoModelForCausalLM.from_pretrained roneneldan/TinyStories-33M、max_new_tokens=30、num_beams=1、遍历 tokenizer.get_vocab()，与卡片 PoC 逐行一致）、官方题解 7 位暴力约 2 小时。已修正原稿一处与截图不符的表述：原称『图06 显示 accept%/accept&/accept'/accept(/accept) 等均包含 accepted』，实际图05 中这些仅为遍历过程示例、仅 accept* 命中，图06 中 Faccept 命中；改为按截图如实描述。dedup=new，与 logits 反演、LoRA 后门、BPE-dropout 防御等卡均非同链。原文未标模型/组件版本号（模型名 TinyStories-33M 为题目资产），affected_versions 留空正确。未对线上服务高频枚举。
url: /docs/ctf/misc/ctf-misc-tinystories-base-model-completion-target-word/
draft: false
kb_aliases:
- 小型大语言模型星球
- Hackergame2023
- TinyStories-33M
- you are smart
- Accept* Faccept
- 补全模型 prompt
- 基座模型诱导
---

## 一句话结论

TinyStories-33M 是没有做过 Instruct Align 的小型基座补全模型，`Please say "you are smart"` 这类指令式 prompt 无效；应把它当作“续写器”：用重复/问答模式让模型顺着补全出目标词（如 `A: you are smart B: you are smart A:`），在输入长度受限时改用目标词的变形 token（如 `Accept*`、`Faccept` 触发 `Accepted`），或直接遍历 tokenizer 词表/有限字符组合，本地检查模型输出是否包含目标词。

## 原理

- **基座模型与指令模型的行为差异**：Instruct Align 训练让模型学会“遵循指令”；TinyStories-33M 只在简单故事语料上做因果语言建模，目标是预测下一个 token，不是理解任务。给它 `Please say "you are smart"`，它只会把这句话当作故事开头续写，而不是复述。
- **模式补全**：自回归模型会延续输入中的模式。`A: you are smart B: you are smart A: ...` 建立了问答/重复结构，下一步的高概率接续就是 `you are smart`；直接重复目标短语若干次也能让模型继续重复。
- **长度限制与 token 变形**：第二关限制输入 7 个字符，而目标 `Accepted` 有 8 个字符，无法直接放入 prompt。利用 tokenizer 的 BPE/子词切分，`Accept*`、`Faccept` 等 7 字符变体可能被切成能导向 `Accepted` 的 token 序列；原文本地遍历确认这两个 prompt 都能触发。
- **暴力遍历可行**：模型很小（33M，CPU 可跑），词表有限；遍历 tokenizer 词表（或 7 位字符空间）对每个候选生成 30 个新 token，检查输出是否包含 `accepted`，即可自动找到触发词。原文脚本对词表逐项 predict，官方题解也给出 7 位字符暴力遍历（性能好的机器约 2 小时）。
- **本质**：这是在“无对齐、可枚举”的模型上做输入空间搜索，目标是让模型输出某个特定字符串；与对对齐模型的越狱不同，不需要绕过拒答，只需要找到高概率补全路径。

## 触发条件

- 目标是基座/补全型语言模型（无指令微调或指令能力很弱），输入被当作前缀续写；
- 可以反复查询模型（本地加载或远程接口），并能观察生成文本；
- 目标词有长度/格式约束，可能需要变形 token 或枚举；
- 模型规模小、词表有限，使暴力遍历在可接受时间内完成。

## 利用步骤

1. 判断模型类型：发送指令式 prompt（如 `Please say "you are smart"`），若模型只是续写而非执行，按基座补全模型处理；
2. 第一关：构造重复/问答模式，如 `A: you are smart B: you are smart A:` 或连续重复目标短语，观察输出；
3. 第二关（长度受限）：取目标词的 7 字符变形（`Accept*`、`Faccept` 等）逐个测试，直到输出包含 `Accepted`；
4. 自动化：加载 `roneneldan/TinyStories-33M` 与 tokenizer，遍历 `tokenizer.get_vocab()` 的每个 token，调用模型生成（如 `max_new_tokens=30, num_beams=1`），过滤输出含目标词的候选；
5. 若词表遍历无果，按长度上限暴力枚举字符组合（原文官方题解对 7 位空间遍历，约 2 小时）；
6. 用命中的 prompt 提交关卡获取 flag。

## PoC

原文给出的词表遍历脚本（本地模型，安全）：

```python
from transformers import AutoModelForCausalLM, AutoTokenizer
from tqdm import tqdm

model = AutoModelForCausalLM.from_pretrained("roneneldan/TinyStories-33M").eval()
tokenizer = AutoTokenizer.from_pretrained("roneneldan/TinyStories-33M")

def predict(message):
    model_inputs = tokenizer.encode(message, return_tensors="pt")
    model_outputs = model.generate(
        model_inputs, max_new_tokens=30, num_beams=1,
        pad_token_id=tokenizer.eos_token_id)
    model_outputs = model_outputs[0, len(model_inputs[0]):]
    return tokenizer.decode(model_outputs, skip_special_tokens=True)

for word, token_id in tqdm(tokenizer.get_vocab().items()):
    if 'accepted' in predict(word).lower():
        print(word, token_id)
```

第一关示例 prompt：`A: you are smart B: you are smart A: you are smart B: you are smart A:`。

## 变体与关联

- 变形 token 取决于 tokenizer：BPE 切分不同，命中前缀需自行遍历验证；原文图 05 的 `accept%`/`accept&`/`accept'`/`accept(`/`accept)` 为遍历过程示例（该图中仅 `accept*` 的输出出现 `to be accepted`），图 06 中 `Faccept` 的输出出现 `accepted`；
- 对更大的基座模型，可用前缀注入、few-shot 续写、温度/beam 调整替代全词表遍历；
- 与库内 `ai-security-jailbreak-igcg-harmful-target-adversarial-suffix` 等对齐模型越狱卡不同：本场景模型无对齐、无拒答，重点是补全模式与 token 搜索；
- 与 prompt injection 类卡的区别：没有“系统提示/工具”被注入，只是利用基座模型的续写概率。

## 检测与防御

- 部署侧不要把未对齐的基座模型直接作为聊天/指令接口暴露；需要指令能力时做 SFT/RLHF 对齐；
- 对输出做关键词/格式约束与速率限制，降低被枚举出目标输出的概率；
- CTF 出题侧可加大模型规模、限制查询次数/输出长度或引入对齐模型，提高遍历成本；
- 研究侧把此类实验限制在本地模型与授权环境，避免对线上服务做高频枚举。
