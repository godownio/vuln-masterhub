---
id: ai-security-supply-chain-llamafactory-value-head-torch-load-pickle-rce
title: LLaMA-Factory <=0.9.3 WebUI checkpoint_path 加载恶意 value_head.bin：torch.load 未设 weights_only 触发 pickle RCE（CVE-2025-53002）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: llamafactory-value-head-torch-load-pickle-rce
aliases:
- CVE-2025-53002
- LLaMA-Factory RCE
- Llama-Factory vhead_file
- value_head.bin 反序列化
- WebUI checkpoint path RCE
- llamafactory 远程代码执行
tags:
- ai-supply-chain
- llamafactory
- pytorch
- torch-load
- pickle
- deserialization
- rce
- model-loading
- weights-only
- cve
cve:
- CVE-2025-53002
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: LLaMA-Factory <= 0.9.3（0.9.4 修复）；PyTorch < 2.6
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:39:46+08:00'
  notes: 已对照原文与图01-06核对：CVE-2025-53002 影响 <=0.9.3、0.9.4 修复；WebUI top.checkpoint_path -> runner.py -> valuehead.py safetensors 回退 torch.load(map_location=cpu) 未设 weights_only；PoC pickle __reduce__ os.system(calc) 与图05 计算器一致；图06 补丁同时修 valuehead.py 与 callbacks.py fix_valuehead_checkpoint。未验证点：PoC 未本机复跑；利用依赖 PyTorch <2.6 与 Reward Modeling 阶段；frontmatter 无 sources/source_url。
---

## 一句话结论

LLaMA-Factory <= 0.9.3 的 WebUI 允许用户填写任意 `Checkpoint path`，当训练阶段为 Reward Modeling 时，`src/llamafactory/model/model_utils/valuehead.py` 在 safetensors 不存在的情况下回退到 `torch.load(vhead_file, map_location="cpu")` 且未设置 `weights_only=True`；在 PyTorch < 2.6 默认走完整 pickle 反序列化的环境下，攻击者只需让受害者加载一个含恶意 `value_head.bin` 的模型仓库，即可在训练服务器上静默执行任意命令（CVE-2025-53002，CWE-94/CWE-502）。

## 原理

- **入口**：WebUI 的 `top.checkpoint_path` 字段由用户输入；`src/llamafactory/webui/runner.py` 根据微调类型把它拼成 `adapter_name_or_path`（PEFT）或 `model_name_or_path`，随后传入训练流程。代码没有校验该路径是否指向可信目录，也没有限制只能加载本地已审核的检查点。
- **触发阶段**：该路径在 Reward Modeling（奖励建模）训练阶段用于加载 value head。`valuehead.py` 先尝试用 `safetensors.safe_open` 读取 `V_HEAD_SAFE_WEIGHTS_NAME`；如果仓库没有 `.safetensors` 文件或读取失败，就回退到 `cached_file(filename=V_HEAD_WEIGHTS_NAME)` 下载 `value_head.bin`，再调用 `torch.load(vhead_file, map_location="cpu")`。
- **Sink**：`torch.load` 未传 `weights_only=True`。PyTorch < 2.6 中该参数默认 `False`，`torch.load` 走完整 pickle 反序列化；pickle 会执行对象 `__reduce__()` 返回的 callable 与参数，因此 `return (os.system, ("calc",))` 即可在加载时弹出计算器/执行命令。
- **为什么 stealth**：恶意逻辑在模型权重文件的 pickle 流里，不在训练代码中；受害者在 WebUI 里只是填了一个看起来正常的 checkpoint 路径并点击开始训练，加载成功后界面/日志可能仅表现为正常训练或权重不匹配，命令已经执行。
- **版本条件**：官方公告确认影响 LLaMA-Factory <= 0.9.3，0.9.4 修复；即使服务端未升级，只要 PyTorch >= 2.6（`torch.load` 默认 `weights_only=True`），该路径也不会执行 pickle，漏洞无法复现。因此实际可利用性 = 旧版 LLaMA-Factory + 旧版 PyTorch + 可影响 checkpoint 路径/模型仓库。
- **同类 sink**：0.9.3 的 `src/llamafactory/train/callbacks.py` 中 `fix_valuehead_checkpoint()` 也存在 `torch.load(path_to_checkpoint, map_location="cpu")`，官方补丁一并加上 `weights_only=True`；审计时应搜索所有 `torch.load` 调用，而不只是 WebUI 入口。

## 触发条件

- 目标运行 LLaMA-Factory <= 0.9.3，且 WebUI 可访问（本机或远程）。
- 运行环境 PyTorch < 2.6（`torch.load` 默认 `weights_only=False`）。
- 攻击者能让受害者把 `Checkpoint path` 指向攻击者控制的 Hugging Face 仓库/本地目录，或受害者主动加载来源不明的检查点。
- 训练配置为 LoRA（PEFT）且 Train Stage 为 Reward Modeling，使 value head 加载路径被触发。
- 目标仓库没有可用的 `.safetensors` value head（或攻击者只提供 `value_head.bin`），从而进入不安全的回退分支。
- 训练进程未被容器/沙箱隔离，加载进程具备命令执行权限。

## 利用步骤

1. 构造恶意 pickle：定义 `class evil`，`__reduce__` 返回 `(os.system, ("calc",))` 或反弹 Shell 命令，用 `pickle.dump` 写成 `value_head.bin`。
2. 在 Hugging Face 创建模型仓库，放入 `value_head.bin`；可同时放入合法的 `adapter_config.json`、`adapter_model.safetensors` 等降低怀疑（原文仓库 `paulinsider/llamafactory-hack`）。
3. 受害者侧在 LLaMA-Factory WebUI 配置 Model name/Model path（如 `llamafactory/tiny-random-Llama-3`），Finetuning method 选 LoRA，Train Stage 选 Reward Modeling。
4. 在 `Checkpoint path` 填入攻击者仓库名（如 `paulinsider/llamafactory-hack`）并启动训练。
5. 后端拼出路径并下载 `value_head.bin`，`torch.load` 反序列化时执行 `calc`/命令；原文截图为 Windows 计算器被拉起。
6. 若目标为 Linux 服务器，可将命令替换为反弹 Shell、写入 SSH key 或下载二阶段载荷；命令在训练进程权限下执行。

## PoC

```python
import pickle
import os


class evil:
    def __reduce__(self):
        return (os.system, ("calc",))


with open("value_head.bin", "wb") as f:
    pickle.dump(evil(), f)
```

将 `value_head.bin` 上传到攻击者控制的 Hugging Face 仓库，受害者在 WebUI 的 `Checkpoint path` 选择该仓库并以 Reward Modeling 启动训练即可触发。原文未给出 Linux 反弹 Shell 命令；PoC 未在本机复跑，仅用 `calc` 验证代码执行。

## 变体与关联

- 变体：把命令换成反弹 Shell、`curl` 下载二阶段木马、写入 `~/.ssh/authorized_keys`，或将恶意文件伪装成正常 value head 以延长潜伏。
- 变体：同时投毒 `pytorch_model.bin`/`adapter_model.bin` 等其他权重文件；只要训练流程中有未加 `weights_only=True` 的 `torch.load`，都可能成为 sink。
- 变体：通过模型市场、共享目录、内部 checkpoint 存储替换 value head；不一定是远程 HF 仓库，本地路径同样可达。
- 关联：[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]（CVE-2025-24357，vLLM 权重加载漏设 `weights_only`）、[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]（`torch.export.load` 强制 `weights_only=False`）、[[ai-security-supply-chain-invokeai-model-install-picklescan-suspicious-fail-open-rce]]（InvokeAI 模型安装扫描 fail-open）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（HF 恶意模型 pickle）、[[ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce]]（分布式检查点 `load_bytes`）。
- 边界：LLaMA-Factory >= 0.9.4 或 PyTorch >= 2.6 时该路径默认安全；若仓库只提供 `.safetensors` value head、或训练阶段不是 Reward Modeling、或 checkpoint 路径被严格限制在可信目录，则无法触发。原文也指出 0.9.3 的后期版本可能已提前打补丁，需按具体 commit 核对。

## 检测与防御

- 检测：检查 LLaMA-Factory 版本是否 <= 0.9.3、PyTorch 是否 < 2.6；搜索 `valuehead.py`、`callbacks.py` 中 `torch.load` 是否带 `weights_only=True`；对模型仓库中的 `value_head.bin`/`*.bin` 做 pickle 静态扫描（`picklescan` 等）；监控训练启动时进程拉起 `calc`/`sh`/`powershell` 或异常外连。
- 修复：升级 LLaMA-Factory 到 0.9.4+，并按官方补丁在 `valuehead.py`、`callbacks.py` 的 `torch.load` 调用加 `weights_only=True`；升级 PyTorch 到 >= 2.6，使默认值变为安全。
- 加固：WebUI 不应允许任意远程 checkpoint 路径，改为服务端白名单/已审核目录；训练任务运行在无网络、低权限、只读文件系统的容器/沙箱内；优先使用 safetensors；对模型仓库做来源校验、签名/哈希校验与人工审核；禁止训练节点直接加载来源不明的 `.bin` 权重。
