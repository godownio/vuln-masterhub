---
id: ctf-reverse-tracr-transformer-residual-labels
title: Tracr 编译 Transformer 逆向：pickle/zstd stub 反序列化 + NumPy 前向 + residual_labels
type: scenario
domain: ctf
path: ctf/reverse
technique: tracr-transformer-residual-labels
aliases:
- Tracr
- Transformer 模型逆向
- residual_labels
- sequence_map
- pickle stub 反序列化
- hajimi
tags:
- ctf
- reverse
- transformer
- tracr
- pickle
- zstd
- numpy
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:13:56+08:00'
  notes: 已对照原文与图06核对：challenge.pkl.zst 为 zstd+pickle、tracr/jax/haiku stub 反序列化、config（13 层/5 头/key_size 257/mlp 1290）、16 位输入限 1-4、NumPy 前向、residual_labels 中 sequence_map_1:* 取 argmax、网格 1234341221434321 及 SHA-256 flag 均一致。未验证点：PoC 未本机复跑（依赖 Python 3.11/pydeps）；原文未给版本；frontmatter 无 sources/source_url。
---

## 一句话结论

题目给出 `pickle + zstd` 保存的 Tracr 编译 Transformer 模型；用自定义 `pickle.Unpickler` 为 `tracr.*` 类提供 stub、绕过缺失依赖完成反序列化，再用纯 NumPy 复现前向传播，读取 `residual_labels` 中 `sequence_map_1:*` 维度的 argmax，即可得到模型接受的 16 位网格并解出 flag。

## 原理

- Tracr 把 RASP 程序编译成 Transformer 权重；模型对象包含 `config`、`params`、`input_encoder`、`output_encoder`、`residual_labels`、`embed_spaces`。
- 直接 `pickle.load` 需要 `tracr`/`jax`/`haiku` 等依赖；攻击者可以在 `find_class` 中为 `tracr.*` 返回带 `__setstate__` 的 dummy 类，为 numpy/jax 数组返回可接收 state 的包装类，从而只提取数据、不执行原库。
- 前向过程是标准 Transformer：`x = token_embed[token] + pos_embed[pos]`；每层做 q/k/v 线性变换、多头注意力 softmax、输出线性、残差，再做 MLP（ReLU）与残差。
- Tracr 的输出不需要完整 unembed：`residual_labels` 把残差流每个维度映射到变量名，`sequence_map_1:*` 这些维度对应输出字符的 one-hot/basis direction；对每个位置取 argmax 即得字符。
- 模型输入限制为 16 个字符、字符集 `1..4`；通过前向/掩码分析或枚举可恢复被接受的网格，题目再对其做 SHA-256 作为 flag。

## 触发条件

- 附件是 `.pkl.zst`/`.pkl` 等序列化模型，或包含 `tracr`/`jax`/`haiku` 依赖。
- 本地缺少对应库，无法直接 `pickle.load`。
- 模型结构是 Tracr 编译的 Transformer，含 `residual_labels`/`sequence_map_*`。
- 需要恢复模型接受的输入/输出映射，而不是训练新模型。

## 利用步骤

1. 用 `zstandard` 解压，确认 pickle 协议与顶层键（config/params/input_encoder/residual_labels 等）。
2. 实现 `pickle.Unpickler.find_class`：`tracr.*` 返回 dummy 类；numpy `ndarray`/`_reconstruct` 返回可接收 state 的类；jax `_reconstruct_array` 返回包装函数。
3. 提取 `config`（层数、头数、key_size、MLP 大小）、`params`（各层 q/k/v/linear/mlp 权重）、`residual_labels`、`input_encoder.encoding_map`。
4. 用 NumPy 实现前向：embedding → 每层 attention + MLP → 残差。
5. 从 `residual_labels` 中筛出 `sequence_map_1:*` 的维度与字母表，对每个位置取 argmax，拼接输出。
6. 根据题目约束（16 位、字符 1-4）恢复输入；必要时用掩码/差分/枚举确定每一位。
7. 按题目要求对结果做哈希/格式化，得到 flag。

## PoC

```python
import pickle
import zstandard as zstd
import numpy as np

class DummyObject:
    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)
        else:
            self.state = state

_stubs = {}
def make_stub(module, name):
    key = (module, name)
    if key not in _stubs:
        _stubs[key] = type(name, (DummyObject,), {"__module__": module})
    return _stubs[key]

class PayloadLoader(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins":
            return super().find_class(module, name)
        if (module, name) == ("numpy._core.multiarray", "_reconstruct"):
            return np._core.multiarray._reconstruct
        if (module, name) == ("numpy", "ndarray"):
            return np.ndarray
        if (module, name) == ("numpy", "dtype"):
            return np.dtype
        if module.startswith("tracr"):
            return make_stub(module, name)
        return super().find_class(module, name)

with open("challenge.pkl.zst", "rb") as fp, zstd.ZstdDecompressor().stream_reader(fp) as cfp:
    payload = PayloadLoader(cfp).load()

cfg = payload["config"]
params = payload["params"]
labels = payload["residual_labels"]
idxs = [i for i, label in enumerate(labels) if label.startswith("sequence_map_1:")]
alphabet = [labels[i].split(":", 1)[1] for i in idxs]

# 前向省略：token/pos embedding -> 13 层 attention+MLP -> residual
# residual = run_model(payload, prompt)
# scores = residual[:, idxs]; best = scores.argmax(axis=-1)
# out = "".join(alphabet[i] for i in best[1:])
```

## 变体与关联

- 变体：模型可能用 `pickle`、`safetensors`、ONNX、TorchScript 等格式；反序列化 stub 思路类似。
- 变体：Tracr 版本不同，`residual_labels` 命名/维度不同；需按实际标签筛选。
- 变体：输出可能需要完整 unembed 或反量化，而非直接 argmax。
- 关联：[[ctf-reverse-onnx-dct-frequency-trigger]]（ONNX 模型逆向）、[[ctf-reverse-predictable-score-derived-aes-key-iv]]（模型/密钥逆向）、[[ai-security-model-extraction-federated-gradient-inversion]]（模型参数恢复）。

## 检测与防御

- 检测：序列化模型文件、`tracr`/`jax` 依赖、`residual_labels` 等元数据。
- 防御：不要把可接受输入的判定逻辑放在客户端模型；使用服务端校验、模型加密/签名与访问控制。
- 响应：确认模型可被反序列化/前向复现后，视为逻辑泄露，轮换相关密钥并审计客户端。
