---
id: binary-pwn-sandbox-escape-gnu-as-incbin-arbitrary-file-read
title: 汇编即服务：GNU as 的 .incbin 指令把任意文件嵌入机器码回显
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: gnu-as-incbin-assembly-service-file-read
aliases:
- ASMaaS
- .incbin
- pwntools asm 文件读取
- assembler file read
- 汇编服务任意文件读取
tags:
- assembler
- gnu-as
- pwntools
- file-read
- sandbox-escape
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:01:57+08:00'
  notes: 已对照原文ASMaaS核对：pwntools asm→GNU as、.incbin "flag.txt" 嵌入机器码hex回显，exp一致；未验证点：未连接远程复跑。
---

## 一句话结论

当在线服务把用户提交的汇编文本交给 GNU `as` 编译并返回机器码 hex 时，攻击者不需要拿到 shell：`as` 的 `.incbin "flag.txt"` 指令会把指定文件的原始字节直接嵌入输出目标文件，服务把编译结果 hex 回显后，解码即可得到任意可读文件内容。

## 原理

- 题目的数据流是：用户输入汇编源码 → `pwnlib.asm.asm()` → 在临时目录调用系统汇编器（如 `/usr/bin/x86_64-linux-gnu-as`）→ 读取输出的目标文件 → 以 hex 返回。
- GNU assembler 除了生成指令，还支持若干伪指令/指示符：
  - `.incbin "file"`：把 `file` 的二进制内容原样插入当前段；
  - `.incbin "file", skip, count`：从 `skip` 字节处开始插入 `count` 字节；
  - `.include "file"`：把文件当作汇编源码包含进来（要求内容是合法汇编）。
- 汇编器以服务进程权限打开文件，路径相对于汇编器的工作目录（通常是临时目录或服务当前目录）。攻击者用相对/绝对路径指向 `flag.txt`、`/flag`、`/etc/passwd` 等，即可让编译器代替自己读文件。
- 编译成功后，`.incbin` 的字节成为 `.text`/`.data` 段内容，进入返回的机器码；服务端通常只检查“能否汇编”，不会检查输出里是否夹带文件数据。
- 本质：把“代码编译”当作纯计算，但编译器本身是一个带文件系统访问能力的外部程序，其输入语言包含文件读取原语。

## 触发条件

- 对外提供“提交汇编、返回机器码/可执行文件”的功能，且使用 GNU `as`（或支持 `.incbin` 的兼容汇编器）。
- 服务进程对目标文件有读权限，且编译器工作目录/路径可预测。
- 返回结果包含完整的编译产物（hex、base64、可下载文件均可）。
- 输入过滤没有禁用 `.incbin`/`.include` 等伪指令。

## 利用步骤

1. 提交一条会触发汇编错误的随机指令，观察报错中的汇编器路径与临时目录，确认是 GNU as 及其调用方式。
2. 提交 `.incbin "flag.txt"`；若服务返回 hex，直接按字节解码。
3. 若 `flag.txt` 不在汇编器工作目录，尝试绝对路径 `/flag`、`/app/flag.txt`、`../../flag.txt`，或用报错信息探测路径。
4. 文件较大或输出被截断时，用 `.incbin "file", offset, count` 分段读取；用 `.include` 读取文本型源码文件。
5. 把返回的 hex 转成字节并打印，得到文件内容。

## PoC

```python
# 服务端：asm_text = input(); shellcode = asm(asm_text, arch='amd64', os='linux'); print(shellcode.hex())
# 攻击侧：
asm_text = r'.incbin "flag.txt"'

# 本地验证时可直接用 pwntools 汇编并打印字节
from pwn import asm, context
context.clear(arch='amd64', os='linux')
code = asm(asm_text)
print(code.hex(' '))
print(bytes(code).decode('latin-1'))
```

```text
# 远程交互（文章中的 exp 结构）：
# 发送 .incbin "flag.txt"
# 收到汇编器返回的 hex 列表
# 把每个 hex 转成字符并拼接，即得到 flag 原文
```

## 变体与关联

- `.include "file"`：把目标文件当汇编源码包含；若文件内容是合法指令或可以注释掉，能读取文本内容或触发汇编错误回显。
- `.incbin` 的分段参数可用于绕过输出长度限制、跳过文件头；`.byte`/`.ascii` 不能直接读文件，但可配合其他伪指令。
- 其他“编译器/打包器即服务”的同类面：C 编译器 `#include` 任意头文件、`ld` 链接脚本 `INCLUDE`、`objcopy`、文档转换器读取本地文件等。
- 关联：[[web-golang-cgo-polyglot-compile-time-file-read]]（编译期文件读取的另一形态）。
- 边界：如果汇编器运行在无 flag 的隔离容器、或输出只返回成功/失败而不返回产物，本手法只能做文件存在性探测；如果服务把输入包装成固定模板、禁止伪指令或以非 GNU as 汇编，也可能失效。

## 检测与防御

- 检测：审计在线汇编/编译服务的输入过滤，重点禁用 `.incbin`、`.include`、`.incbin` 的分段形式；监控汇编器进程打开业务目录之外的文件；对返回产物做大小/熵/内容检查。
- 修复：不要把编译器直接暴露给不可信输入；使用白名单化的指令子集或自定义解析器；在无敏感文件、只读文件系统的沙箱中编译，编译后删除临时目录。
- 加固：以低权限用户运行汇编器，`chroot`/namespace 隔离工作目录，限制可打开路径；输出只返回固定长度的截断结果，避免整文件回显。
