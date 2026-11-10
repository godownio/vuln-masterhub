# 格式化字符串

## 这层是什么

任意读写、GOT 覆写与利用。

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

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [DrayTek Vigor user_login.cgi 格式化字符串（CVE-2023-31447）：fid=101 将 src_ip/target_url 直接作 snprintf 格式串](binary-pwn-format-string-draytek-user-login-cgi-cve-2023-31447.md) | verified | medium | 2026-11-07 |
| [exit_hook 劫持：把 _rtld_global 的 rtld lock/unlock 函数指针改成 system、_dl_load_lock 改成 /bin/sh（glibc < 2.34）](binary-pwn-format-string-exit-hook-rtld-global.md) | verified | high | 2026-11-06 |
| [glibc 2.29 tcache dup 改 __free_hook 为 printf：free 触发格式化字符串泄露栈地址后二次投毒写栈 ROP](binary-pwn-format-string-freehook-printf-stack-leak.md) | verified | high | 2026-11-07 |
| [power_system 链：SHA256 比较被 0x00 截断绕过登录 + 格式串泄 libc，负索引越界写 _IO_2_1_stderr_ 经 _IO_wfile_seekoff 调 system("/bin/sh")](binary-pwn-format-string-sha256-null-truncate-negative-index-stderr-fsop.md) | verified | medium | 2026-11-09 |
| [RC4 加密消息解密后直入 printf：%15$s 读 GOT 泄 PIE/libc，%15$hhn 六字节覆写 __free_hook 为 system](binary-pwn-format-string-rc4-decrypted-message-freehook-system.md) | verified | medium | 2026-11-08 |
| [scanf 无界写入覆盖相邻 .data 格式化字符串：把静态 printf 变成格式化字符串漏洞读写 flag](binary-pwn-format-string-scanf-overflow-adjacent-format-string.md) | verified | medium | 2026-11-06 |
| [Synology TC500 webd 格式字符串：改 HTTP 版本指针泄露内存 + 持久栈指针链任意读写 + __free_hook 劫持 RCE](binary-pwn-format-string-synology-tc500-webd-http-version-leak-freehook-rce.md) | verified | high | 2026-11-07 |
| [一次性栈上格式化字符串：单次 printf 用两段 %n 写栈返回地址直达 one_gadget](binary-pwn-format-string-one-shot-stack-return-address-two-n-writes.md) | verified | medium | 2026-11-06 |
| [一次格式化字符串机会完成两处写入：顺序参数 %hn 建跳板指针后混用 N$ 定位 %hhn，配合 %hhn 只写总字节数尾字节技巧改返回地址为后门](binary-pwn-format-string-single-shot-dual-write-hhn-low-byte-trampoline.md) | verified | high | 2026-11-08 |
| [单次栈上格式化字符串双目标写：把 .fini_array[0] 改成 main 制造第二次执行窗口，同时将 printf GOT 覆写为 system@plt（无 libc 泄露）](binary-pwn-format-string-single-shot-fini-array-restart-got-system-plt.md) | verified | high | 2026-11-10 |
| [单次非栈上格式化字符串：三级指针链把 printf 返回地址改回 read 造循环，再用 0x10000 高位截断逐字节写 one_gadget](binary-pwn-format-string-nonstack-single-shot-loop-high-byte-truncation.md) | verified | medium | 2026-11-08 |
| [有限次非栈上格式化：改循环条件扩充写入次数 + 两级指针 %hn/%hhn 逐字节写 ROP（AES 单块输入）](binary-pwn-format-string-limited-nonstack-loop-condition-byte-rop.md) | verified | medium | 2026-11-06 |
| [栈上格式化字符串 0x10 字节限制：%10$p 泄露栈地址、%10$hn 改写指针搭链，%14$hn 覆写返回地址到后门](binary-pwn-format-string-stack-pointer-chain-return-address-backdoor.md) | verified | high | 2026-11-06 |
| [格式化字符串 %hn 向 RWX mmap 逐 2 字节写 shellcode：短跳回读 syscall 续写二阶段](binary-pwn-format-string-hn-rwx-mmap-shellcode-staging.md) | verified | medium | 2026-11-07 |
| [格式化字符串 %n 覆写 GOT 表项劫持函数调用](binary-pwn-format-string-got-hijack.md) | verified | medium | 2026-11-05 |
| [格式化字符串一次泄露 Canary 与 libc 后带 Canary 栈溢出 ROP 取 shell](binary-pwn-format-string-canary-libc-leak-rop-system.md) | verified | high | 2026-11-05 |
| [格式化字符串分三次 short 写 __malloc_hook 为 one_gadget（glibc 2.31）](binary-pwn-format-string-malloc-hook-one-gadget.md) | verified | medium | 2026-11-06 |
| [格式化字符串泄露 Canary 后栈溢出调用文件复制函数写 authorized_keys](binary-pwn-format-string-canary-leak-ret2copy-authorized-keys.md) | verified | high | 2026-11-05 |
| [格式化字符串黑名单绕过：先过滤后解码，\x25/\x24 还原 %/$ 触发泄漏](binary-pwn-format-string-decode-after-filter-bypass.md) | verified | high | 2026-11-06 |
| [禁用 $ 的顺序格式化字符串泄漏：%p 走栈定位后把目标地址追加到格式串尾部成为第 15 个参数，%s 读出远端 flag](binary-pwn-format-string-sequential-leak-appended-target-address.md) | verified | high | 2026-11-09 |
| [非栈上格式化字符串小输入约束：借栈指针链两级 %hn 中转，覆写 printf GOT 为 system](binary-pwn-format-string-nonstack-pointer-chain-got-overwrite.md) | verified | medium | 2026-11-06 |
| [非栈上格式化字符串通解：借 .fini_array 重启与参数链循环 %hn 写返回地址](binary-pwn-format-string-non-stack-fini-array-loop-write.md) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
