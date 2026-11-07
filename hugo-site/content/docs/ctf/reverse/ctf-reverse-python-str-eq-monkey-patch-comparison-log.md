---
id: ctf-reverse-python-str-eq-monkey-patch-comparison-log
title: Python 逆向：monkey-patch str.__eq__ 记录 flag 校验的比较对
type: scenario
domain: ctf
path: ctf/reverse
technique: python-str-eq-monkey-patch-comparison-log
tags:
- ctf
- reverse
- python
- monkey-patch
- string-comparison
- flag-checker
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T10:04:36+08:00'
  notes: V161 指出的 PoC 不可运行问题已修正（z3 移位取位 / forbiddenfruit 绕过内置类型限制）
url: /docs/ctf/reverse/ctf-reverse-python-str-eq-monkey-patch-comparison-log/
draft: false
kb_aliases:
- str.__eq__ hook
- Python 比较 Hook
- 字符串比较日志
- flag checker 逆向
- monkey patch 逆向
---

## 一句话结论

对 Python 编写的 flag 校验器，不必逆推混淆算法：在导入目标模块前把 `str.__eq__` 替换成带日志的包装函数，记录所有长度 1~25 的字符串比较 `(self, other)`；运行校验器后，从日志中的“候选字符 vs 正确答案字符”或逐位比较对直接重建 flag。对 `bytes`、`str.startswith`、`hmac.compare_digest` 等其它比较入口可同理 Hook。

## 原理

- **Python 的富比较**：`str == str` 调用 `str.__eq__`，它是 Python 层可替换的方法（CPython 中 `str` 类型的方法可被 monkey-patch，虽然有限制）。在 `import` 目标模块前替换 `str.__eq__`，目标模块后续的所有字符串比较都会走钩子。
- **校验器模式**：很多 Python flag checker 会逐字符/逐段比较用户输入与目标；即使算法被混淆（异或、编码、逐位变换），最终仍会落到字符串/字节比较。记录比较双方即可拿到期望值或缩小搜索空间。
- **过滤噪声**：只记录长度 1~25 的字符串比较，避免解释器/库内部大量短字符串比较；打印 `repr(self)`/`repr(other)` 便于区分输入与期望。
- **变体入口**：`bytes.__eq__`、`str.startswith`/`endswith`、`in`、`hmac.compare_digest`、`hashlib` 比较、C 扩展中的 `memcmp` 不一定经过 Python 钩子；需要按目标实现选择 Hook 点。
- **限制**：CPython 对某些内置类型的特殊方法替换可能不生效（取决于版本/实现）；若校验器用 C 扩展/编译代码，需用 Frida/gdb/动态插桩；若使用常量时间比较，日志仍可能暴露期望值但时序不泄露。

## 触发条件

- 目标是 Python 实现（或可用 Python 导入的模块），flag 校验最终使用 `str`/`bytes` 的 `==` 比较。
- 攻击者能在导入目标模块前执行 Hook 代码（例如题目给出 `import baby` 的入口，或可修改启动脚本）。
- 比较双方长度在可记录范围内；日志可见（stdout/文件）。
- 目标未使用 C 扩展/常量时间比较/反 Hook 保护，或这些保护可绕过。

## 利用步骤

1. **定位入口**：确认目标模块名/导入方式（示例 `import baby`）；准备在导入前执行 Hook。
2. **替换 `str.__eq__`**：保存原方法，定义 `hooked_eq(self, other)`：若两者都是 str 且长度 1~25，打印 `repr(self)`/`repr(other)`，再调用原方法返回结果。
3. **运行校验器**：`import baby` 或调用其 `main`/`check`，输入任意候选 flag（或让程序自行读取输入）。
4. **分析日志**：查找比较对；若日志显示“用户输入片段 vs 期望片段”，直接拼接；若显示逐字符比较，按位置重建；若算法先变换再比较，可能需要逆向变换或多次输入。
5. **扩展 Hook**：若 `str.__eq__` 无输出，尝试 `bytes.__eq__`、`str.startswith`、`hmac.compare_digest`、`operator.eq`，或用 `sys.settrace`/`bytecode` 插桩。
6. **验证**：用重建的 flag 运行校验器，确认通过。

## PoC

```python
# CPython 不允许直接给内置 str 赋 __eq__（TypeError: cannot set '__eq__'
# attribute of immutable type 'str'），需用 forbiddenfruit 或 ctypes 改类型槽位。
from forbiddenfruit import curse

orig_eq = str.__eq__

def hooked_eq(self, other):
    if isinstance(self, str) and isinstance(other, str):
        if 1 <= len(self) <= 25 and 1 <= len(other) <= 25:
            print("COMPARE:", repr(self), repr(other))
    return orig_eq(self, other)

curse(str, "__eq__", hooked_eq)   # 等价于 str.__eq__ = hooked_eq，但可绕过不可变限制

import baby          # 目标 flag 校验模块
```

```python
# bytes 版本（同样需借助 forbiddenfruit/ctypes）
from forbiddenfruit import curse
orig_beq = bytes.__eq__
def hooked_beq(self, other):
    if isinstance(self, bytes) and isinstance(other, bytes) and 1 <= len(self) <= 64:
        print("BYTES COMPARE:", self.hex(), other.hex())
    return orig_beq(self, other)
curse(bytes, "__eq__", hooked_beq)
```

Hook 需在目标模块导入前执行；若目标已导入，需重新加载/在新进程注入。本卡不执行 PoC。

## 变体与关联

- **其它比较入口**：`str.startswith`、`str.endswith`、`in`、`re.fullmatch`、`hmac.compare_digest`、`bytes.__eq__`；按目标实现选择。
- **动态插桩**：Frida（Python 嵌入/CPython 扩展）、`sys.settrace`、`sys.setprofile`、字节码改写、`gdb` 断点；适用于 C 扩展/编译校验器。
- **反 Hook**：目标若在导入后恢复 `str.__eq__`、使用 C 层比较或常量时间比较，需要更底层 Hook 或算法逆向。
- **关联**：[[ctf-reverse-python-vm-hidden-container-branch-oracle]]（Python VM 逆向）、[[ctf-reverse-wasm-login-fnv1a-feistel-xorshift-keystream]]（算法逆向）、[[ctf-reverse-electron-asar-wasm-license-hash-collision-z3]]（许可证校验逆向）。
- **边界**：只对 Python 层字符串比较有效；对 C 扩展、`memcmp`、哈希比较、常量时间比较无效或需额外手段。

## 检测与防御

- **对防御方**：不要依赖“把比较藏进混淆算法”保护 flag；使用服务端校验、常量时间比较、C 扩展/编译代码，并在导入后检查 `str.__eq__`/`bytes.__eq__` 是否被替换。
- **完整性**：校验器启动时校验自身模块哈希/签名，检测 monkey-patch、`sys.settrace`、调试器；关键比较放在 C 层或独立进程。
- **检测**：`str.__eq__`/`bytes.__eq__` 被替换、异常的比较日志、进程被调试/注入；CTF 环境外无直接检测手段。
- **响应**：轮换 flag/密钥，审计校验器是否被篡改。
