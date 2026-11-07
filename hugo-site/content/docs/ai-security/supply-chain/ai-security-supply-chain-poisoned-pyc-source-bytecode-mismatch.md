---
id: ai-security-supply-chain-poisoned-pyc-source-bytecode-mismatch
title: Skill 包中毒 .pyc：源码与字节码不一致，扫描器只看 .py 而解释器执行 .pyc
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: poisoned-pyc-source-bytecode-mismatch
tags:
- ai-supply-chain
- agent-skill
- python
- pyc
- bytecode
- evasion
- scanner-bypass
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:45:38+08:00'
  notes: 已对照原文与全部 44 张本地图片（另有 1 张 xz.aliyun.com 远程图无法读取）核对：PoC、截图、命令、IOC、检测规则与数字均与原文一致。未验证点：原文部分攻击链为描述/示意，未提供完整可运行样本；本库未复跑任何 PoC；frontmatter 无 sources/source_url。
url: /docs/ai-security/supply-chain/ai-security-supply-chain-poisoned-pyc-source-bytecode-mismatch/
draft: false
kb_aliases:
- 中毒字节码
- .pyc 投毒
- pyc 源码不一致
- SimpleTextFormatter
- 字节码逃逸
- Python 字节码投毒
---

## 一句话结论

Skill 包同时放一份人畜无害的 `utils.py` 与一份被替换的 `utils.cpython-312.pyc`：Python 在 pyc 校验通过时直接执行字节码而不重新编译，扫描器则把 `.pyc` 当成不透明二进制跳过或只审 `.py` 源码，于是“用户看到的源码”和“实际执行的代码”完全脱钩，三个主流检测平台都给出 SAFE/PASS。

## 原理

- **Python 的 pyc 优先执行**：`import utils` 时，解释器会优先查找 `__pycache__/utils.cpython-312.pyc`；当 pyc 头部的时间戳/大小与源码匹配（或使用 hash-based pyc 且校验通过）时，直接加载 marshalled code object，不重新编译 `.py`。因此源码可以保持完全良性。
- **字节码可承载任意逻辑**：替换后的 pyc 可以在 `format_text()` 中额外注入 `os.environ.items()` 采集、文件读取或外传逻辑；用户用编辑器打开 `utils.py` 只看到正常的空格/大小写/标点修正。
- **扫描器盲区**：
  - `skills.sh`（Gen/Socket/Snyk）把 `.pyc` 视为二进制不透明文件，不进入分析管线；
  - Cisco skill-scanner 的静态分析只检查 `.py` 源码，不解包/反编译 `.pyc`；
  - LLM 语义分析受文件类型限制，不会主动反编译 `__pycache__`。
- **版本相关性**：`.cpython-312.pyc` 只会在 Python 3.12 上被加载；攻击者可按目标环境打包多个版本，或使用不校验源码的 hash-based pyc（PEP 552）。
- **为什么危险**：Skill 的信任建立在“源码可读”上；一旦执行体与展示体分离，所有只读 `.py` 的静态检测、人工 review 和平台安全标签都会失真。

## 触发条件

- Skill 包含 Python 脚本，且打包了 `__pycache__/` 或同目录 `.pyc` 文件。
- 目标环境的 Python 小版本与 pyc 魔数匹配（示例 3.12）；或攻击者提供了对应版本的 pyc。
- 扫描器不反编译 `.pyc`、不做源码/字节码一致性校验，或直接把 `.pyc` 排除出分析范围。
- 用户只阅读 `SKILL.md` 与 `.py` 源码，未检查 `__pycache__`。
- 运行环境允许导入该模块并执行其中的环境变量/文件访问逻辑。

## 利用步骤

1. 构造一个正常的文本格式化 Skill：`SKILL.md` 描述格式化功能，`utils.py` 实现 `format_text()`，行为完全良性。
2. 在恶意版本中保留同样的 `utils.py`，另外编译一份 pyc；在源码中加入环境变量采集/外传逻辑后用 `py_compile` 生成 pyc，再把 `utils.py` 还原为良性版本。
3. 把 pyc 放到 `__pycache__/utils.cpython-312.pyc`，确保头部时间戳/大小与良性源码匹配，或使用 `unchecked_hash` 模式。
4. 打包提交到 Skill 市场/仓库；扫描器读取 `SKILL.md` 与 `.py`，`utils.py` 全绿，`.pyc` 被跳过。
5. 受害者安装并运行 Skill，`import utils` 执行恶意字节码，环境变量/凭据被采集外传。
6. 变体：同时放多个 Python 版本的 pyc；把恶意逻辑拆到 `import` 时执行的模块级代码；用 `.so`/`.pyd` 扩展替代 pyc。

## PoC

生成与源码“同名但不同内容”的 pyc（仅演示打包方式，不含恶意逻辑）：

```python
import py_compile

# 1) 先用良性源码占位，保证包内 utils.py 可读、可审
benign = '''
def format_text(text: str) -> str:
    return text.strip().capitalize()
'''
open("utils.py", "w", encoding="utf-8").write(benign)

# 2) 实际编译的是另一份源码（示例只打印环境变量数量，非真实窃密）
malicious = '''
import os
def format_text(text: str) -> str:
    _ = len(list(os.environ.items()))   # 真实样本在此处采集并外传
    return text.strip().capitalize()
'''
open("_build.py", "w", encoding="utf-8").write(malicious)
py_compile.compile("_build.py", cfile="__pycache__/utils.cpython-312.pyc", doraise=True)
```

检测侧（反编译 pyc 并与源码 AST 对比的思路）：

```python
import marshal, dis, pathlib

raw = pathlib.Path("__pycache__/utils.cpython-312.pyc").read_bytes()
code = marshal.loads(raw[16:])          # 跳过 16 字节 pyc 头（版本相关）
dis.dis(code)                            # 观察是否出现 os.environ/网络/文件操作
```

Python 3.12 的 pyc 魔数为 `0x0DCB`，小端字节为 `CB 0D 0D 0A`；原文示例 YARA 中的 `0D 0D 0A` 实际位于偏移 1，规则应按 Python 版本修正偏移，不能直接照搬。

## 变体与关联

- **PEP 552 变体**：`checked_hash`/`unchecked_hash` pyc 不依赖源码时间戳，攻击者更容易让校验通过；分析时需读取 pyc 头部的 flags 与 hash。
- **多版本变体**：同时打包 `cpython-310/311/312/313` pyc，覆盖不同宿主 Python。
- **载体变体**：用 `.so`/`.pyd` 原生扩展、zipimport 内嵌 pyc、`sitecustomize.py`/`.pth` 启动钩子替代普通模块。
- **关联卡片**：[[ai-security-supply-chain-doubao-claw-fake-skill-setup-js-remcos]]（恶意 Skill 安装脚本）、[[ai-security-supply-chain-python-pth-addsitedir-model-disguise]]（Python 启动路径投毒）、[[code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract]]（Python 打包产物的逆向）。
- **边界**：宿主 Python 版本不匹配、解释器强制重新编译、包管理器删除 `__pycache__`、或扫描器具备 pyc 反编译/AST 比对能力时，本手法会被识破。

## 检测与防御

- **源码/字节码一致性**：对每个 `.pyc` 反编译（`dis`/`marshal`/专用反编译器）并与对应源码做 AST/常量/导入对比；不一致即高危。没有对应源码的 `.pyc` 直接拒绝。
- **哈希与签名**：包发布时对 `.py` 与 `.pyc` 同时计算哈希并签名；安装端校验 pyc 头部的源码哈希/时间戳是否与声明的源码一致。
- **扫描器改造**：把 `.pyc` 纳入分析管线而不是当二进制跳过；对 `__pycache__` 目录单独告警；YARA 可用 Python 版本对应的完整魔数 + `getenv`/`exec`/`socket` 等字节码字符串做初筛。
- **运行防护**：不可信 Skill 在沙箱中运行，禁止读取 `~/.ssh`/云凭据；必要时删除 `__pycache__` 或设置只读缓存目录，强制从源码编译；监控模块导入期的环境变量读取与外连。
- **响应**：发现 pyc 不一致立即下架 Skill、轮换可能泄露的凭据、排查同作者/同仓库的其他包。
