---
id: ai-security-supply-chain-huggingface-pickle-model-reverse-shell
title: Hugging Face 恶意 PyTorch 模型 pickle 反序列化：加载即反弹 Shell
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: malicious-model-pickle-deserialization
aliases:
- 恶意模型文件 RCE
- torch.load 反序列化
- Hugging Face 恶意模型
- pickle 模型反弹 Shell
- goober2
- 模型加载即执行
tags:
- ai-supply-chain
- model-poisoning
- huggingface
- pytorch
- pickle
- deserialization
- rce
- reverse-shell
- model-loading
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:57:17+08:00'
  notes: 已对照原文与全部 17 张图片核对：Sydney 逐句抽取对话/身份冒充、公开 Issue→私有仓库读取→公开 README 写入链、goober2 pickle 反弹 Shell payload 与 RHOST/RPORT、PoisonGPT ROME 编辑/EleuterAI 仿冒账号/0.1% 基准差异均与原文及截图一致。未验证点：本库未复跑任何 PoC；B站翻译、torchtriton、LoRATK、预训练投毒/记忆投毒等综述性素材按 worker 判断未单独成卡；四卡 frontmatter 无 sources/source_url。
---

## 一句话结论

PyTorch 的 `.pt/.bin/.pth` 模型文件通常用 pickle 序列化；攻击者把实现 `__reduce__` 的恶意对象保存成“模型”上传到 Hugging Face 等模型仓库，受害者用 `torch.load()` 正常加载时就会执行其中的任意代码。公开仓库中已出现过这样包装成普通模型、加载后向外建立反弹 Shell 的真实恶意文件。

## 原理

- `torch.load()` 默认使用 Python pickle 反序列化。pickle 在还原对象时可以调用任意可调用对象与参数，`__reduce__` 返回 `(callable, args)` 后由反序列化器执行，因此模型文件本身就是可执行载荷。
- 模型文件的扩展名与内容没有强制校验；`.pt`、`.bin`、`.pth` 都可能包含 pickle。攻击者可以把恶意对象和真实权重张量混在同一个文件里，加载后既得到可用模型，也触发代码。
- 真实恶意样本会在反序列化时建立 socket 连接，把标准输入/输出/错误重定向到 socket，再 `pty.spawn("/bin/sh")` 得到交互 Shell；Windows 分支则启动 PowerShell 并通过 socket 转发输入输出。
- 危害发生在“加载模型”这一常规动作中，不需要用户运行示例脚本、不需要 `trust_remote_code`，也不需要模型推理；只要模型来自不可信仓库且用 `torch.load` 加载即可。
- 这类载荷与模型行为后门不同：它执行的是传统代码，和模型输出是否正确无关；模型只是吸引下载和隐藏代码的外壳。

## 触发条件

- 受害者从公开模型仓库（Hugging Face、ModelScope 等）下载模型，并以 `torch.load()`/`pickle.load()` 等不安全的默认方式加载。
- 加载进程对模型文件没有做 pickle 静态扫描、沙箱隔离或来源校验。
- 运行加载进程的用户具备网络出站能力（反弹 Shell）或本地命令执行能力。
- 攻击者能向模型仓库上传文件，并通过命名、README、下载量等诱导受害者下载。

## 利用步骤

1. 构造一个 `__reduce__` 返回恶意可调用对象与参数的类，将其与正常模型权重一起序列化，保存为 `.pt/.bin/.pth`。
2. 在 Hugging Face 等平台创建仓库，文件名、README、目录结构模仿正常模型；可用近似官方名称、热门任务名或“量化/微调版本”提高可信度。
3. 诱导受害者下载并按常规方式加载，例如 `model = torch.load("pytorch_model.bin")` 或框架自动加载模型目录。
4. 反序列化触发 payload：建立外连、反弹 Shell、下载二阶段或写入持久化。
5. 授权测试中只用 `id`/`touch` 等无害命令验证代码执行，不连接真实 C2；真实恶意样本的攻击者地址仅作为 IOC 记录。

## PoC

最小化 pickle 载荷（仅验证代码执行，不发起网络连接）：

```python
import pickle
import os

class EvilModel:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pickle_model_pwned",))

with open("evil.pt", "wb") as f:
    pickle.dump(EvilModel(), f)
```

```python
import torch
torch.load("evil.pt")   # 反序列化时执行 os.system
```

真实恶意样本的模式（文字描述）：Linux 分支创建 socket 连接攻击者地址和端口，`os.dup2` 把 0/1/2 重定向到 socket，再 `pty.spawn("/bin/sh")`；Windows 分支启动 `powershell.exe`，用线程在 socket 与进程标准流之间转发数据。公开报告中的样本为伪装成普通 PyTorch 模型的仓库，加载即触发。

## 变体与关联

- 变体：扩展名换成 `.bin`、`.pth`、`.ckpt`、`.pt`；载荷藏在 LoRA/Adapter、Tokenizer、优化器状态、训练检查点中。
- 变体：与 `trust_remote_code=True` 的自定义 modeling 文件组合，模型目录中的 Python 代码也会被执行。
- 变体：用 `safetensors` 伪装（实际仍是 pickle 文件）、用近似官方仓库名/作者名做 typosquatting、在 README 中提供“一键加载”脚本。
- 关联卡片：[[ai-security-supply-chain-python-pth-addsitedir-model-disguise]]（同为模型仓库投毒，但利用 `.pth` + `site.addsitedir` 而非 pickle）、[[ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass]]（模型加载信任边界绕过）、[[web-python-framework-rasa-malicious-model-dialogue-hijack]]（恶意模型替换对话行为）。
- 关联：通用 Python pickle 反序列化链可提供更复杂的 gadget；本卡的重点是模型分发场景与“加载即执行”的触发方式。

## 检测与防御

- 防御：加载不可信模型时使用 `torch.load(..., weights_only=True)`（新版本默认更安全），或改用 `safetensors` 等不含可执行代码的格式。
- 防御：对模型文件做 pickle 静态扫描（如 Fickling、ModelScan），检查 `__reduce__`、`GLOBAL`/`STACK_GLOBAL`、`os.system`、`subprocess`、`socket` 等可疑 opcode/字符串；扫描后再决定是否加载。
- 防御：模型下载与加载放在沙箱/容器中，默认拒绝出站网络，限制文件系统与凭据；高风险模型先在隔离环境验证。
- 防御：固定模型 revision/commit，校验 hash 与签名；只从可信发布者/组织下载；对近似官方名称的仓库做来源核验。
- 检测：模型加载进程出现异常子进程（`sh`、`bash`、`powershell`）、对外连接、DNS 查询；模型文件中出现 pickle 可执行 opcode 或与权重无关的 Python 对象；加载后产生计划任务/启动项。
- 响应：隔离并删除恶意模型，阻断 C2 地址，排查加载进程的凭据与外连，轮换可能泄露的密钥，审计同一下载源的其他模型。
