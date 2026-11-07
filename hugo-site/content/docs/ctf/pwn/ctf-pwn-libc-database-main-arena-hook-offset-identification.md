---
id: ctf-pwn-libc-database-main-arena-hook-offset-identification
title: 无 libc 文件的 libc 版本识别：unsorted bin 泄 main_arena，用 __malloc_hook/__realloc_hook 固定偏移查 libc-database
type: scenario
domain: ctf
path: ctf/pwn
technique: libc-database-main-arena-hook-offset-identification
tags:
- ctf
- pwn
- heap
- glibc
- libc-database
- main-arena
- malloc-hook
- uaf
- unsorted-bin
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:14+08:00'
  notes: 已对照原文与3张图核对：unsorted bin 泄露 0x7f235db74ca0、main_arena+0x60、__malloc_hook/__realloc_hook=main_arena-0x10/-0x18、libc-database 先得 2.29 候选后换 2.27(amd64 3ubuntu1.x) 的流程一致；更正了卡片中对截图 i386 候选的过度具体表述。未验证点：未复跑 libc-database 查询与完整 exp；原文最终 exp 偏移 0x3ebca0 与 amd64 2.27 一致。frontmatter 无 sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-libc-database-main-arena-hook-offset-identification/
draft: false
kb_aliases:
- entity_cache
- libc 版本盲猜
- main_arena 识别 libc
- libc-database 查版本
- __malloc_hook main_arena-0x10
- 未提供 libc
- 无 libc 文件
---

## 一句话结论

题目只给二进制、不给 libc 时，可先用 UAF/unsorted bin 泄露出 `main_arena+0x60` 附近的指针，再算 `main_arena`；对 glibc < 2.34，`__malloc_hook = main_arena - 0x10`、`__realloc_hook = main_arena - 0x18`，把这两个“符号地址”喂给 libc-database/libc.rip 即可锁定具体 libc 版本，之后再用该版本的偏移完成 tcache/fastbin 投毒与 ROP。

## 原理

- **unsorted bin 的指针位置**：释放一个大于 tcache 上限的 chunk 后，它会进入 unsorted bin；在只有一个空闲 chunk 时，`fd`/`bk` 都指向 `main_arena+0x60`（不同 glibc 版本可能是 `+0x60`/`+0x58`，以本地调试为准）。用 UAF `show` 读出这 8 字节，就得到 libc 内的一个固定偏移地址。
- **main_arena 与 hook 的关系**：`main_arena` 是 libc 数据段中的 `malloc_state`；在 glibc 2.34 之前，`__malloc_hook` 和 `__realloc_hook` 位于 `main_arena` 前面的固定位置：
  - `__malloc_hook = main_arena - 0x10`
  - `__realloc_hook = main_arena - 0x18`
  因此泄露的 `main_arena+0x60` 减去 `0x60` 得到 `main_arena`，再减 `0x10`/`0x18` 得到两个符号地址。
- **libc-database 的索引方式**：libc-database 收集大量 libc 的 `__malloc_hook`、`__realloc_hook`、`system`、`puts` 等符号偏移与 build ID；按“符号名 + 运行时地址”查询，会返回所有符号偏移与地址匹配的 libc 候选（libc.rip 同理，可 POST 多个 symbol/address）。两个 hook 地址联合查询能大幅缩小候选。
- **为什么需要验证**：同一组 hook 偏移可能对应多个 libc 版本/发行版；libc-database 会列出多个候选（原文先用 `main_arena` 查询得到 `libc-2.29-23.mga7`，后续 stack 泄露不匹配；改用 `__malloc_hook/__realloc_hook` 查询得到 2.27 候选后才与远程一致；截图候选列表首项为 i386 构建，实际 exp 偏移对应 amd64 2.27-3ubuntu1.x）。最终要拿候选 libc 继续写 exp，用后续泄露（`environ`、`system`、`puts` 等）与远程回显交叉验证。
- **为什么这条链成立**：ASLR 只随机化 libc 基址，不改变同一 libc 内的符号偏移；泄露一个 libc 指针即可把“未知 libc”变成“已知偏移集合”的匹配问题；libc-database 把该匹配离线化。
- **版本边界**：glibc 2.34 起移除了 `__malloc_hook`/`__free_hook` 等 hook，不能再依赖 `main_arena-0x10` 关系；应改用 `main_arena` 附近其他符号、`system`/`puts`/`environ` 等偏移或 build ID 查询。

## 触发条件

- CTF 只提供二进制/远程服务，没有 libc 文件，且二进制有 UAF/任意读或格式化字符串等可泄露 libc 指针的原语。
- 目标 glibc < 2.34（存在 `__malloc_hook`/`__realloc_hook`），或使用仍保留 hook 的发行版。
- 能稳定泄露 unsorted bin 的 `fd/bk`（或其它 libc 指针），并知道该指针相对 `main_arena` 的偏移（本地同版本调试或按常见值假设后验证）。
- 能访问 libc-database（本地仓库或 libc.rip）并准备多个候选 libc 做对比。

## 利用步骤

1. **泄 libc 指针**：申请一个大于 tcache 上限的 chunk（如 `0x488`），再申请一个隔离 chunk 防止与 top 合并；释放大 chunk 后用 UAF `show` 读出 8 字节 `fd`（或 `bk`）。
2. **算 main_arena**：按目标版本把泄露值减去 `0x60`（常见 `main_arena+0x60`；先用本地同版本确认偏移）。原文泄露 `0x7f235db74ca0`，得到 `main_arena=0x7f235db74c40`。
3. **算 hook 地址**：`__malloc_hook = main_arena - 0x10`、`__realloc_hook = main_arena - 0x18`。
4. **查 libc-database**：
   ```bash
   ./find __malloc_hook 0x7f235db74c30 __realloc_hook 0x7f235db74c28
   ```
   或在 libc.rip 提交同样的 symbol/address；记录候选 libc 的 build ID、MD5 与各符号偏移。
5. **筛选与验证**：优先选与目标发行版/架构匹配的候选；用候选 libc 继续 exp，后续 `environ`/`system`/`puts` 泄露或 ROP 行为与远程一致即为正确。原文第一次得到 2.29 候选，后续 `environ` 泄露不匹配；换 2.27（amd64 3ubuntu1.x）后成功。
6. **继续利用**：用确定版本的偏移做 tcache poisoning（或 fastbin dup）改写全局指针数组/`__free_hook`，泄露 `environ` 得栈地址，最后 ROP/ORW 绕沙箱读 flag。

## PoC

```python
from pwn import *
from LibcSearcher import LibcSearcher

# 1) unsorted bin 泄露
add(0, 0x488, b"1")
add(1, 0x38, b"2" * 0x10)
dele(0)
show(0)
leak = unpack(io.recvline()[:-1], "all")        # 例：0x7f235db74ca0
main_arena = leak - 0x60
malloc_hook = main_arena - 0x10
realloc_hook = main_arena - 0x18
log.info(f"main_arena={main_arena:#x} malloc_hook={malloc_hook:#x}")

# 2) 查 libc-database（本地仓库）
#    ./find __malloc_hook 0x... __realloc_hook 0x...
#    或使用 LibcSearcher（按泄露值与已知符号偏移匹配）
obj = LibcSearcher("__malloc_hook", malloc_hook)
libc_base = malloc_hook - obj.dump("__malloc_hook")
log.info(f"libc_base={libc_base:#x}")

# 3) 用候选 libc 继续：tcache poisoning -> 全局指针数组 -> environ -> ROP ORW
```

原文最终用 `libc_leak - 0x3ebca0` 得到 libc 基址（amd64 2.27-3ubuntu1.x 的 `main_arena+0x60` 偏移），再用 tcache poisoning 把指针数组指向 `environ`，读栈后覆盖 `main` 返回地址写 ORW ROP，绕过只禁 `execve` 的 seccomp。完整 exp 依赖题目的全局数组地址（`elf.address+0x202060`）与栈偏移 `0xf0`，需按目标二进制调整。

## 变体与关联

- **glibc 2.34+**：hook 被移除，改用 `main_arena` 与 `system`/`puts`/`environ` 等偏移查询，或用 build ID/`__libc_start_main_ret` 匹配。
- **多候选**：libc-database 常返回多个版本；用第二个泄露（`environ`、`system`、`puts`）或远程行为排除，不要只看第一个结果。
- **无 UAF 读**：可用格式化字符串、stdout 部分覆写、`environ` 直接读等方式获取 libc 指针；关键是得到任意一个可映射到符号偏移的地址。
- **后续利用**：tcache poisoning 打全局数组/`__free_hook`、environ 泄栈、seccomp ORW 分别见 [[ctf-pwn-tcache-poison-global-note-array-flagbuf-print]]、[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]、[[ctf-pwn-uaf-overlap-fake-note-aar-safe-linking-dynsym-environ-stack-scan]]。
- 关联：[[ctf-pwn-gcc15-ubuntu2604-cet-no-libc-csu-adaptation]]（无 libc 环境下的 CSU/ROP 适配）、[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（hook 偏移与 one_gadget 利用）。

## 检测与防御

- **CTF 识别**：题目只给二进制、无 libc，且存在 UAF/泄漏原语时，先泄 unsorted bin 指针并查 libc-database；不要把第一个候选当作最终版本，用后续泄露验证。
- **防御/加固**：开启 ASLR + PIE + Full RELRO，减少可泄漏的固定地址；高版本 glibc 移除 hook、启用 safe-linking，增加“泄 libc 后直接打 hook”的难度；对 CTF 之外的真实程序，避免把敏感逻辑依赖 libc 内部符号偏移。
- **检测特征**：大量 `libc-database`/`libc.rip` 查询、`__malloc_hook`/`__realloc_hook` 地址计算、unsorted bin UAF 读、`environ` 读取与栈 ROP，是此类利用的典型行为。
