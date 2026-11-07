---
id: ai-security-supply-chain-joblib-numpyarraywrapper-pickle-rce
title: joblib NumpyArrayWrapper.read_array pickle 反序列化：加载恶意模型缓存即执行 __reduce__ 命令
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: joblib-numpyarraywrapper-pickle-deserialization
tags:
- ai-security
- supply-chain
- model-file
- joblib
- numpy
- pickle
- deserialization
- rce
cve:
- CVE-2024-34997
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T11:56:06+08:00'
  notes: 已对照原文与13张图核对：NumpyArrayWrapper.read_array 触发 pickle __reduce__→os.system(whoami) 的最小 PoC 与图13 Snyk 公告一致；CVE-2024-34997；公告 Amendment 明确 deemed not a vulnerability，卡片已按不可信模型文件场景标 severity/confidence=medium。未验证点：PoC 未复跑；read_array 内部结构随 joblib 版本变化；无版本可设；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-joblib-numpyarraywrapper-pickle-rce/
draft: false
kb_aliases:
- joblib 反序列化
- NumpyArrayWrapper RCE
- CVE-2024-34997
- 模型缓存 pickle
- joblib.load 恶意文件
- Model Format Vulnerability
---

## 一句话结论

joblib 用 pickle 持久化 Python 对象/NumPy 数组；其 `joblib.numpy_pickle.NumpyArrayWrapper.read_array()` 会从传入的文件句柄读取 pickle 数据并反序列化，未做来源校验。攻击者构造一个实现 `__reduce__`（返回 `os.system` 与命令）的对象并保存成 `.pkl`/模型缓存，受害者用 joblib 加载该文件时即执行任意命令（CVE-2024-34997，厂商曾争议该 CVE 的定性）。

## 原理

- **joblib 的持久化基础**：joblib 的 `dump`/`load` 为了高效保存 NumPy 数组，会把数组包装成 `NumpyArrayWrapper` 等对象，底层仍使用 `pickle` 序列化；读取时 `read_array()` 从文件句柄反序列化 wrapper 及其数据。
- **pickle 的 `__reduce__`**：反序列化时，pickle 会调用对象里 `__reduce__` 返回的 callable 与参数来重建对象。攻击者让 `__reduce__` 返回 `(os.system, ('whoami',))`，加载时就会执行 `os.system('whoami')`。
- **触发路径**：示例不直接调用 `joblib.load`，而是构造 `NumpyArrayWrapper(subclass='', shape=[], order='', dtype=x.dtype)` 并调用 `read_array(file_handle)`；该函数内部读取并 unpickle 攻击者控制的文件内容，从而触发 `__reduce__`。实际应用中任何“加载用户上传/第三方模型缓存/`.npy`/`.pkl`”的路径都可能成为 sink。
- **为什么与模型格式相关**：模型缓存、预处理管线、`joblib.Memory` 磁盘缓存、`sklearn` 模型 `.joblib` 文件都用同一套持久化；把恶意对象伪装成模型缓存即可随模型分发。
- **厂商争议点**：Snyk 公告的“Amendment”写明该问题被判定为 not a vulnerability；维护者的观点是 joblib 明确用于加载可信对象，`pickle` 本身就不可信输入不安全，`read_array` 只是遵循既有契约。技术上“能执行代码”成立，但“是否构成库漏洞”取决于信任边界；因此本卡按“不可信模型文件加载”场景记录，severity/confidence 均标为 medium。
- **与 `torch.load` 的区别**：PyTorch 的 `torch.load` 也在 pickle 上构建，但 joblib 的 sink 更隐蔽（`.joblib`/`.npy`/缓存文件常被视为数据文件），且 `NumpyArrayWrapper` 的名字看起来像“数组包装”，容易被静态审查忽略。

## 触发条件

- 应用使用 joblib 加载来自不可信来源的文件：用户上传、第三方模型仓库、共享缓存、CI 产物。
- 加载路径最终到达 `pickle.load`/`NumpyArrayWrapper.read_array`/`joblib.load`，且未启用可信来源校验或安全格式。
- 攻击者能控制被加载文件的内容（能上传模型/缓存/`.pkl`）。
- 进程以有权限的账号运行；命令以该账号权限执行。

## 利用步骤

1. 定义恶意类，实现 `__reduce__` 返回 `(os.system, (命令,))`；命令先用 `whoami`/`touch /tmp/poc` 等无害形式验证。
2. 用 `pickle.dump` 把对象写入 `.pkl` 文件；或按目标加载器期望的 `.joblib`/`.npy` 结构包装。
3. 让受害者程序加载该文件：直接 `joblib.load`，或构造 `NumpyArrayWrapper` 后调用 `read_array(file_handle)`。
4. 反序列化触发 `__reduce__`，命令执行；可进一步下载二阶段载荷、写持久化或外带数据。
5. 若目标使用 `numpy.load(allow_pickle=True)`、`pandas.read_pickle`、`cloudpickle`/`dill`，用同样思路替换 sink。

## PoC

```python
from joblib.numpy_pickle import NumpyArrayWrapper
import os
import pickle
import numpy

class A:
    def __reduce__(self):
        return (os.system, ('whoami',))

a = A()
with open('testnpyarray.pkl', 'wb') as f:
    pickle.dump(a, f)

class B:
    def __init__(self, file_handle):
        self.file_handle = file_handle

x = numpy.array([1, 'a', {}], dtype=object)
with open('testnpyarray.pkl', 'rb') as f:
    b = B(f)
    NumpyArrayWrapper(subclass='', shape=[], order='', dtype=x.dtype).read_array(b)
```

说明：这是原文的最小 PoC；`read_array` 的实际内部结构随 joblib 版本变化，集成到真实 sink 时需按目标版本的 `joblib.numpy_pickle` 调整。PoC 未在本库复跑；授权测试请使用无害命令。

## 变体与关联

- **同族 sink**：`pickle.load/loads`、`joblib.load`、`numpy.load(allow_pickle=True)`、`pandas.read_pickle`、`torch.load`（默认 pickle）、`cloudpickle`/`dill`、`shelve`。
- **模型文件伪装**：把恶意 pickle 命名为 `.joblib`、`.npy`、`.pkl`、`model_cache`，或放进 `joblib.Memory` 缓存目录，降低审查警惕。
- **绕过扫描**：使用协议 0/2、分段/编码、惰性对象、`__setstate__` 等；`picklescan` 可能漏报，需结合行为检测。
- **本库关联**：`ai-security-supply-chain-huggingface-pickle-model-reverse-shell` 覆盖 PyTorch/Hugging Face 模型 pickle；`web-python-deserialization-*` 覆盖 Web 场景的 pickle sink；本卡聚焦 joblib/NumpyArrayWrapper。

## 检测与防御

- **根本防御**：不要对不可信来源使用 pickle/joblib；模型/缓存优先使用 `safetensors`、JSON、NumPy `.npy`（`allow_pickle=False`）等无代码执行格式。
- **加载侧**：若必须加载 joblib，校验文件哈希/签名、限制目录、在低权限沙箱中加载；检查文件是否来自可信发布者。
- **检测**：用 `picklescan`/`fickling` 扫描 `pickle.load` 前的字节码，重点关注 `GLOBAL`/`REDUCE`/`BUILD` 操作码和 `os.system`/`subprocess`/`builtins.eval` 等危险全局；监控加载进程的 `os.system`/`subprocess` 调用。
- **供应链**：模型仓库应对 `.joblib`/`.pkl` 文件做静态扫描和发布者签名；下载方应在隔离环境首次加载并观察行为。
- **定性说明**：该 CVE 的厂商立场是“加载不可信 pickle 本就不安全”，因此真实系统应把“加载第三方 joblib”视为高风险操作，而不是依赖库本身修复。
