---
id: ai-security-supply-chain-textgenwebui-lora-adapter-torchscript-items-filewrite
title: text-generation-webui LoRA 训练加载恶意 adapter_model.bin：weights_only=True 仍走 torch.jit.load，PEFT 的 state_dict.items() 触发 TorchScript aten::save 写文件
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: textgenwebui-lora-adapter-torchscript-weights-only-bypass-filewrite
aliases:
- VCTF2025 ez_train
- training.py adapter_model.bin
- LoRA 训练 torch.load
- weights_only=True 绕过
- TorchScript items 触发
- set_peft_model_state_dict
- aten::save 写文件
tags:
- ai-security
- supply-chain
- text-generation-webui
- lora
- peft
- torch-load
- torchscript
- weights-only
- arbitrary-file-write
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:45:29+08:00'
  notes: 已对照原文及图01-26核对：lora_name→user_data/loras 路径、HF 下载落位、torch.load(weights_only=True) 遇 TorchScript zip 转 torch.jit.load、set_peft_model_state_dict→_insert_adapter_name_into_state_dict 的 state_dict.items() 触发 aten::save、图26 PK/archive/data.pkl 写文件均一致；原文 RCE 仅为 Dockerfile 推断，卡内已按文件写入原语记录并标注边界；未复跑
---

## 一句话结论

在 text-generation-webui 3.13 的 LoRA 微调流程中，`training.py` 用 `torch.load(f"{lora_file_path}/adapter_model.bin", weights_only=True)` 加载用户 `lora_name` 对应目录下的权重；`weights_only=True` 只约束普通 pickle，遇到 TorchScript zip 仍会转交 `torch.jit.load`。攻击者通过应用自带的 HuggingFace 模型下载功能把恶意 TorchScript 文件放进 `user_data/loras/<repo>/adapter_model.bin`，再把训练参数 `lora_name` 设为该目录名；当 PEFT 处理返回对象时调用 `state_dict.items()`，恶意模块的 `items()` 被触发，执行 `aten::save`（`torch.save`）向攻击者指定路径写文件。

## 原理

- **入口可控**：训练页的 `lora_name` 是用户参数。`do_train()` 先 `lora_file_path = clean_path(lora_name)`，随后拼成 `lora_file_path = f"{Path(shared.args.lora_dir)}/{lora_file_path}"`；`shared.args.lora_dir` 固定为 `user_data/loras`。虽然只能控制路径的后半段，但足以指向 `user_data/loras` 下的任意子目录。
- **文件落位可控**：应用没有上传接口，但提供“Download model or LoRA”功能，可从 HuggingFace 按 `user/repo` 下载模型到 `user_data/loras/<user>_<repo>/`。攻击者发布一个包含恶意 `adapter_model.bin` 的仓库，诱导或让受害者在 WebUI 中下载，即可把文件写进 `lora_dir` 下可控目录，不需要任何文件上传漏洞。
- **sink**：训练时若 `adapter_model.bin` 存在，代码执行 `state_dict_peft = torch.load(f"{lora_file_path}/adapter_model.bin", weights_only=True)`。表面上 `weights_only=True` 已开启，应该是安全的。
- **weights_only 的真实边界**：`torch.load(..., weights_only=True)` 对普通 pickle 使用受限的 `_weights_only_unpickler`，只允许 `OrderedDict`、`torch.Tensor`、`torch.Size` 等白名单全局变量，常规 `os.system` gadget 会被拦截。但 `torch.load` 在解析前会判断文件是否为 zip：若内容看起来像 TorchScript 归档，就调用 `torch.jit.load(opened_file, map_location=...)` 并直接返回，完全不经过 `_weights_only_unpickler` 白名单。因此 `weights_only=True` 并不能阻止恶意 TorchScript。
- **TorchScript 可执行 IR**：用 `torch.jit.script()` 编译的模块保存了计算图，支持 `aten::save` 这类带副作用的算子。攻击者在模块中定义 `items()`（或 `forward`）调用 `torch.save(data, path)`，并保存成 zip 格式的 `.bin`，即得到一个“加载后调用特定方法就会写文件”的模型。
- **触发点**：`torch.load` 本身只返回 `ScriptModule` 对象，不会执行模块方法。题目代码在拿到 `state_dict_peft` 后调用 `set_peft_model_state_dict(lora_model, state_dict_peft)`；该函数把对象赋给 `state_dict`，再进入 `_insert_adapter_name_into_state_dict`，其中 `for key, val in state_dict.items():` 会调用对象的 `items()` 方法。攻击者只要在 TorchScript 模块上实现 `items()`，文件写入就在这一步发生。
- **为什么能过 PEFT 检查**：`_insert_adapter_name_into_state_dict` 期望一个 dict，直接对它调用 `.items()`；恶意 `ScriptModule` 提供的同名方法满足了调用约定，参数校验发生在迭代之后或根本不校验，因此不需要模型结构真正匹配 LoRA 权重。
- **写文件的格式限制**：`torch.save` 写出的是 Torch 序列化归档（zip/pickle 结构），不是任意明文。原文截图中的目标文件以 `PK` 头和 `archive/data.pkl` 开头，说明即使写入 `/etc/cron.d` 之类的路径也未必能被 cron 直接解析；原文提出“最后通过写定时任务实现 RCE”属于基于 Dockerfile 的推断，未给出成功执行定时任务的截图。该原语确定可做到“攻击者指定路径 + 可影响内容”的文件创建/覆盖，能否升级为 RCE 取决于目标路径接受的格式以及后续是否会被加载/执行，需要按环境验证。
- **版本条件**：原文复现环境为 text-generation-webui 3.13、PyTorch 2.5.1。该 `torch.jit.load` 分派行为与 PyTorch 版本相关；应用侧若移除 TorchScript 自动分派、或训练接口限制 `lora_name`/模型下载目录，链条即不成立。

## 触发条件

- 目标运行该 text-generation-webui 3.13 训练环境（原文为 CTF 题目），且训练功能可访问。
- 攻击者能把恶意 `adapter_model.bin` 放进 `user_data/loras/<可控目录>`：利用应用的 HuggingFace 模型下载功能下载攻击者仓库，或通过共享目录/其他写文件方式落位。
- 训练表单中的 `lora_name` 可设为该目录名，使 `torch.load` 指向恶意文件。
- 训练代码在 `torch.load` 后会对返回对象调用 `.items()`（经 `set_peft_model_state_dict` / `_insert_adapter_name_into_state_dict`）。
- 训练进程对目标写入路径有权限；若要 RCE，目标路径还需接受 Torch 序列化格式或存在后续加载/执行链。

## 利用步骤

1. 构造恶意 TorchScript 模块：定义 `items()`，在其中调用 `torch.save(payload, target_path)` 后返回正常结果；用 `torch.jit.script()` 编译并保存为 `evil.bin`。
2. 在 HuggingFace 创建模型仓库，把 `evil.bin` 命名为 `adapter_model.bin`，可同时放置合法的 `adapter_config.json`、`adapter_model.safetensors` 降低怀疑。
3. 在目标 WebUI 的 Download 功能中下载该仓库，文件落到 `user_data/loras/<user>_<repo>/adapter_model.bin`，确认目录名。
4. 在 Train LoRA 页面把 `lora_name` 填成该目录名并启动训练；`training.py` 拼出路径并调用 `torch.load(..., weights_only=True)`。
5. `torch.load` 识别 TorchScript zip 并交给 `torch.jit.load` 返回模块；`set_peft_model_state_dict` 迭代时调用 `items()`，`aten::save` 执行，写入目标文件。
6. 检查目标文件是否生成；授权测试只写无害路径，不覆盖系统文件、不写持久化位置。
7. 如要尝试 RCE，先确认目标路径接受的格式与后续执行机制，不能默认 `torch.save` 的归档内容可被 cron/脚本解释器直接执行。

## PoC

恶意 TorchScript 模块（原文核心代码）：

```python
import torch

class SimpleModule(torch.nn.Module):
    def __init__(self):
        super(SimpleModule, self).__init__()
        self.linear = torch.nn.Linear(10, 5)

    def items(self):
        torch.save("\ntest\n", "E:/tmp/1.txt")
        return torch.zeros(0)

    def forward(self):
        self.items()
        return torch.zeros(0)

module = SimpleModule()
sc = torch.jit.script(module)
sc.save("evil.bin")

# 验证：weights_only=True 仍能加载 TorchScript，调用 items() 触发写文件
newModule = torch.load("evil.bin", weights_only=True)
newModule.items()
```

投递与触发：

```text
1) 将 evil.bin 以 adapter_model.bin 名称上传到攻击者 HuggingFace 仓库
2) 目标 WebUI -> Model -> Download model or LoRA -> 输入 attacker/repo
   文件保存到 user_data/loras/attacker_repo/
3) Train LoRA -> Name 填 attacker_repo -> Start LoRA Training
4) training.py: torch.load("user_data/loras/attacker_repo/adapter_model.bin", weights_only=True)
5) set_peft_model_state_dict -> _insert_adapter_name_into_state_dict -> state_dict.items()
6) aten::save 写入目标路径
```

说明：原文在 Windows 环境将内容写到 `E:/tmp/1.txt`，截图确认文件生成；写入内容是 `torch.save` 的序列化归档而非纯文本。完整的定时任务 RCE 链未在原文截图中演示，本卡按文件写入原语记录，升级 RCE 需按目标环境验证。

## 变体与关联

- **触发方法变体**：PEFT 代码调用 `.items()`，因此恶意模块实现 `items()`；若其他下游代码调用 `len()`、`__getitem__`、`keys()`、`to()` 等，可在对应 dunder/方法中放置 `aten::save`；也可把副作用放在 `forward`，等待正常推理触发。
- **文件写入变体**：覆盖模型文件、训练配置、Web 静态目录、启动脚本、`authorized_keys` 等；写入内容为 Torch 序列化格式，需验证目标路径是否接受。
- **投递变体**：应用内 HuggingFace 下载只是其中一种落位方式；共享模型目录、供应链仓库投毒、本地路径穿越、其他文件写入漏洞都可把恶意 `adapter_model.bin` 放进 `lora_dir`。
- **同类目标**：所有“Web 训练/微调界面 + 用户可控模型路径 + `torch.load` 加载权重”的 AI 应用；`weights_only=True` 不应被视为对 TorchScript 的完整防护。
- **关联卡片**：[[ai-security-supply-chain-torchscript-jit-load-aten-save-file-write]]（TorchScript/aten::save 与 weights_only 绕过原语）、[[ai-security-supply-chain-llamafactory-value-head-torch-load-pickle-rce]]（训练 WebUI 加载恶意 `.bin` 的同类链）、[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]（torch.load 权重加载）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（HF 恶意模型投递）。
- **边界**：应用若禁用/移除 TorchScript 分派、对 `lora_name` 做白名单、限制模型下载目录，或下游不调用 `items()`，链条不成立；`torch.save` 的归档格式限制了直接写 cron 等明文配置的能力。

## 检测与防御

- **输入与路径**：`lora_name` 只允许已审核的适配器名，禁止路径分隔符与任意目录；模型下载目录与训练加载目录分离，加载前做白名单校验。
- **模型格式**：拒绝 TorchScript zip 作为 LoRA 权重，只接受 safetensors 或经过结构校验的纯权重；加载前做签名/哈希校验与 pickle/TorchScript 静态扫描。
- **PyTorch 与应用**：升级 PyTorch 并在应用层显式禁止 `torch.jit.load` 自动分派；审计所有 `torch.load` 调用及返回对象的后续方法调用。
- **权限与沙箱**：训练进程以低权限运行，限制可写目录；训练任务放在无网络、只读根文件系统的容器中；敏感目录（cron、systemd、Web 根、`.ssh`）不可写。
- **检测**：监控 `user_data/loras` 下新增的 `adapter_model.bin` 来源与哈希；监控训练进程对非模型目录的写入、异常 `torch.save` 文件（`PK`/`archive/data.pkl` 特征）；审计训练参数 `lora_name` 中的路径分隔符；对从 HuggingFace 下载的仓库做来源与内容校验。
- **响应**：隔离恶意模型与下载仓库，检查被写入/覆盖的文件，清理持久化位置，轮换训练节点凭据，升级或修补训练代码。
