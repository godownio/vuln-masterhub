# Pwn

## 这层是什么

二进制漏洞利用与缓解绕过。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- [栈利用](stack/README.md) —— 栈溢出、ROP、ret2libc、SROP。
- [堆利用](heap/README.md) —— glibc 堆、UAF、double free、House of 系列。
- [格式化字符串](format-string/README.md) —— 任意读写、GOT 覆写与利用。
- [ROP](rop/README.md) —— ROP/JOP/COP、gadget 与链构造。
- [内核利用](kernel/README.md) —— 内核漏洞、提权、KASLR/SMEP/SMAP 绕过。
- [浏览器利用](browser/README.md) —— JIT、渲染引擎、沙箱与逃逸。
- [沙箱逃逸](sandbox-escape/README.md) —— 容器/浏览器/语言沙箱逃逸。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ARM64 PAC 函数指针签名预言机：可写 BUILTINS + help 的 paciza 重签任意指针](binary-pwn-arm64-pac-function-pointer-signing-oracle.md) | verified | medium | 2026-11-06 |
| [AWDP UAF 二进制补丁：free 后清零全局指针槽，压缩代码区注入汇编修复](binary-pwn-awdp-uaf-patch-clear-pointer-slot.md) | verified | high | 2026-11-06 |
| [ELF COPY 重定位把共享库安全状态复制进主程序 .bss：越界写可翻转授权判定](binary-pwn-elf-copy-relocation-writable-security-state.md) | verified | high | 2026-11-05 |
| [Full RELRO 绕过：改写 libc 自身 .got.plt 的 strlen 槽为 one_gadget](binary-pwn-libc-got-plt-hijack-full-relro-bypass.md) | verified | medium | 2026-11-06 |
| [libevent 服务全局 conn_state 溢出：伪造 bufferevent/evbuffer/reference chain，借 cleanup 回调链 open/read/write](binary-pwn-libevent-evbuffer-global-overflow-fake-chain-orw.md) | verified | medium | 2026-11-06 |
| [setuid 程序 GOT/PLT 惰性绑定劫持：任意 8 字节写覆写 puts@got.plt 为 system@plt（shell 可能降权）](binary-pwn-setuid-got-plt-lazy-binding-hijack.md) | verified | high | 2026-11-05 |
| [TCP 发送缓冲区阻塞放大服务端 TOCTOU 竞态窗口：从概率竞争到接近 100% 命中](binary-pwn-tcp-send-buffer-block-toctou-race-window.md) | verified | high | 2026-11-06 |
| [受限单字节代码写：把 leave 改成 push rcx; ret 形成循环 patch 并写入 shellcode](binary-pwn-single-byte-code-patch-leave-to-push-rcx-loop.md) | verified | high | 2026-11-06 |
| [符号检查遗漏 + 索引缩放回绕越界：uint64 0x800000000000000a 命中结构体相邻 dbus fd](binary-pwn-signed-index-scale-wrap-adjacent-fd.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
