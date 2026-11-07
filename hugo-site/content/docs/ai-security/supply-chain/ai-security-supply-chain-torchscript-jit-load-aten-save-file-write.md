---
id: ai-security-supply-chain-torchscript-jit-load-aten-save-file-write
title: 恶意 TorchScript 模型经 torch.jit.load 加载：forward 内 aten::save 任意文件写入并绕过 torch.load(weights_only=True)（CVE-2025-32434）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: torchscript-jit-load-aten-save-arbitrary-file-write
tags:
- ai-supply-chain
- pytorch
- torchscript
- torch-jit-load
- model-loading
- arbitrary-file-write
- weights-only
- cve-2025-32434
- rce
cve:
- CVE-2025-32434
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: PyTorch < 2.6.0（weights_only 绕过，CVE-2025-32434）
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T11:47:17+08:00'
  notes: 已对照原文与11张图核对：图08 GitHub 39.6k 处 torch.jit.load、图09 PyTorch 官方“可构造恶意 pickle 在加载时执行任意代码”警告、图10-11 Qwen2-VL special token 代码均与卡片/原文一致；PoC 与原文代码块相同；affected_versions PyTorch < 2.6.0（CVE-2025-32434）与原文“2.6.0 版本之前”一致。未验证点：PoC 未在本机执行；RCE 为潜在链、原文未给完整利用；卡片标 medium 合理；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-torchscript-jit-load-aten-save-file-write/
draft: false
kb_aliases:
- torch.jit.load 恶意模型
- TorchScript 反序列化
- aten::save 文件写入
- CVE-2025-32434
- weights_only 绕过
- 端侧模型供应链 RCE
---

## 一句话结论

`torch.jit.load` 加载的 TorchScript 是可执行 IR：攻击者可在模型 `forward` 中嵌入 `aten::save`（对应 `torch.save`），受害者加载并推理该不可信模型时即向宿主文件系统写入攻击者指定文件；在 PyTorch `< 2.6.0` 中，该路径还能绕过 `torch.load(..., weights_only=True)` 的安全限制（CVE-2025-32434），把“加载模型”变成文件写入原语，并可能进一步链式升级为 RCE。

## 原理

- **TorchScript 是可执行中间表示**：`torch.jit.save` 保存的 `.pt` 是 TorchScript IR，`torch.jit.load` 将其加载为 `ScriptModule`，之后 `model(x)` 会执行图中算子。官方文档明确警告：可能构造恶意 pickle 数据在 `torch.jit.load` 期间执行任意代码，只能加载可信数据。
- **推理阶段的副作用算子**：即使加载阶段不执行模型逻辑，TorchScript 支持带副作用的 `aten` 算子，例如 `aten::save`（`torch.save`）。在 `forward` 中调用 `torch.save(data, path)` 会被编译进计算图，模型执行时即写入指定路径。
- **攻击构造**：定义 `MaliciousModule.forward`，在其中调用 `torch.save("\nhacked\n", "pwned.txt")` 后返回正常结果；用 `torch.jit.script` 编译并 `torch.jit.save` 成 `malicious.pt`。将文件伪装成模型权重、端侧模型或模型转换输入，诱导目标加载并推理。
- **weights_only 绕过**：PyTorch `2.6.0` 之前，`torch.load(path, weights_only=True)` 仍可能加载 TorchScript 并执行其中的副作用算子，因此“只加载权重、weights_only=True 更安全”的假设在端侧模型场景并不成立（CVE-2025-32434）。
- **危害升级**：`aten::save` 提供的是“攻击者可影响内容 + 攻击者可指定路径”的文件写入。若目标进程对计划任务目录、启动脚本、Web 目录、配置文件或其它会被后续加载/执行的位置有写权限，就可能链式升级为代码执行；若只能写普通文件，则至少造成文件覆盖/数据破坏。`torch.save` 写出的是序列化格式，能否直接作为脚本/配置生效取决于目标路径与格式，需要按环境验证。
- **端侧放大**：端侧模型由普通用户导入（如通过 adb push 到模型目录），用户安全意识和校验能力弱；模型转换工具、推理 App 若用 `torch.jit.load`/`torch.load` 读取不可信 `.pt`，都会暴露该攻击面。

## 触发条件

- 目标应用/模型转换工具使用 `torch.jit.load` 加载不可信 `.pt`/TorchScript 模型，或使用 PyTorch `< 2.6.0` 的 `torch.load(..., weights_only=True)` 加载 TorchScript。
- 加载后确实执行模型推理（`model(x)`），且模型 `forward` 中的副作用算子会被执行。
- 攻击者能向目标提供模型文件（模型市场、下载站、端侧导入、供应链投递、模型转换输入）。
- 运行模型的进程对目标写入路径有权限；若要 RCE，还需该路径后续会被执行/加载。
- 没有模型签名/哈希校验，或在加载前未做算子/文件访问审计。

## 利用步骤

1. 构造恶意模块，在 `forward` 中加入 `torch.save(payload, target_path)`，其余逻辑保持正常以通过功能测试。
2. 用 `torch.jit.script` 编译并 `torch.jit.save` 生成恶意 `.pt`；可改名/伪装成正常模型权重、端侧模型或转换输入。
3. 通过模型市场、下载链接、端侧导入、供应链或社会工程投递给目标。
4. 目标用 `torch.jit.load` 加载并执行推理；`aten::save` 触发，向 `target_path` 写入内容。
5. 验证写入（检查文件存在/内容）；若目标路径可被后续执行（计划任务、启动脚本、Web 目录等），进一步构造链式利用。
6. 在授权测试中只写无害测试文件，不覆盖系统文件、不写持久化位置。

## PoC

原文 PoC（仅用于授权测试）：

```python
import torch

class MaliciousModule(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(self, x):
        torch.save("\nhacked\n", "pwned.txt")
        return x + 1

malicious_script = torch.jit.script(MaliciousModule())
torch.jit.save(malicious_script, "malicious.pt")

# 正常 torch.jit.load 即触发
model = torch.jit.load("malicious.pt")
model(torch.tensor(0))

# PyTorch < 2.6.0 中绕过 torch.load(weights_only=True)
model = torch.load("malicious.pt", weights_only=True)
model(torch.tensor(0))
```

说明：执行后当前目录出现 `pwned.txt`，内容为 `hacked`。原文未附执行输出截图；本卡片未在本机复跑。RCE 升级需要目标路径后续会被执行/加载，原文表述为“潜在风险”，未给出完整 RCE 链。

## 变体与关联

- 变体：把 `aten::save` 目标改为计划任务/启动脚本/Web 目录/配置路径，或写入覆盖合法模型/配置造成持久化破坏。
- 变体：在 `forward` 中调用其它有副作用的算子（文件、网络、进程相关），按 TorchScript 支持的算子集合扩展。
- 变体：模型转换工具先把 `.pt` 转 ONNX/MNN，转换进程同样会加载并执行恶意 TorchScript。
- 关联：[[ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce]]（PyTorch 分布式检查点 weights_only=False pickle RCE）、[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]（PyTorch 模型导出/加载 pickle RCE）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（HuggingFace pickle 模型反序列化）、[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]（vLLM torch.load 权重加载 RCE）。
- 边界：加载前做模型签名/哈希校验、在无写权限沙箱中加载与推理、使用不支持副作用算子的安全导出格式、升级 PyTorch ≥ 2.6.0 并正确使用 weights_only 时，风险显著降低。

## 检测与防御

- 只加载可信来源的模型；对模型文件做签名/哈希校验，模型市场与端侧导入流程强制校验来源。
- 升级 PyTorch 到 `2.6.0` 或更高，并确认 `torch.load(weights_only=True)` 不再加载/执行 TorchScript；优先使用 safetensors 等纯权重格式。
- 沙箱化模型加载与推理：低权限用户、只读根文件系统、限制可写目录与网络；端侧 App 对模型目录做完整性校验。
- 静态检查：审计 TorchScript/ONNX 计算图中的 `aten::save` 及其它文件/网络/进程副作用算子；对模型转换工具做输入校验。
- 检测：监控模型加载进程对文件系统的异常写入（尤其是计划任务、启动目录、Web 根、`.ssh`、配置目录）；监控 `torch.jit.load`/`torch.load` 加载新模型的来源与哈希变化；对端侧导入的模型做来源与格式核验。
- 响应：隔离恶意模型，检查被写入/覆盖的文件与持久化位置，恢复模型与配置，轮换相关凭据，升级 PyTorch 并收紧模型加载权限。

## 备注

原文 11 张图主要为端侧模型落地流程（ModelScope 模型文件、llmexport 转换、adb push 导入、MNN Chat 推理）、GitHub 上 torch.jit.load 使用量搜索、PyTorch 官方警告、Qwen2-VL 特殊 token 处理代码；PoC 为文内代码块，无执行截图。文章另述 MNN externalFile 整数溢出与 special token 注入，均被作者明确为本地 DoS，按 brief 排除。
