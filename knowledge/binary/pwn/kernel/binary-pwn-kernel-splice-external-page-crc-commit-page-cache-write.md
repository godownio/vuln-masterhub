---
id: binary-pwn-kernel-splice-external-page-crc-commit-page-cache-write
title: 内核模块 splice 外部页 + CRC commit：可读文件 page cache 4 字节写并 patch busybox 入口提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-splice-external-page-crc-commit-write
aliases:
- d3kbus
- CRC commit 页缓存写
- splice external segment
- sendfile producer fd
- page cache 4 字节写
- 数据-only 内核利用
- busybox e_entry patch
tags:
- kernel
- pwn
- splice
- sendfile
- page-cache
- crc32c
- data-only
- busybox
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:48:53+08:00'
  notes: 已对照原文核对：rcS 权限、CREATE/SUBSCRIBE ioctl 与 segment/buffer 结构、sendfile external page、CRC 路径四函数、max_subscribers=2/flags=6+1/window 0x14/0x20 字节 payload、build_crc_input 0x40 字节布局与 user_tag 线性求解、busybox e_entry 0x18/0x1c patch 到 0x5f99c0、shellcode 均一致；原文 d3kbus 与 revenge 两版利用链相同已合并，合并说明正确。未验证点：PoC 未在本机复跑；自定义模块非公开 CVE；frontmatter 无 sources/source_url。
---

## 一句话结论

当内核模块把 `splice`/`sendfile` 送进来的文件 page cache 页当作 external segment 保存，并在 CRC trailer/commit 路径把 4 字节 CRC32C 结果写回该 segment 时，普通用户就能对一个只读文件做 4 字节 page cache 写；利用 CRC32C 对 `user_tag` 的线性关系可以精确控制写入值，最终 patch root 后续会执行的静态 busybox 的 `e_entry` 与 shellcode，实现数据-only 提权。

## 原理

- 模块的 producer fd 同时支持 `write()` 与 splice。`write()` 路径把用户数据拷进模块私有 buffer；`sendfile(producer_fd, target_file, ...)` 路径则把目标文件 page cache 的 bvec 作为 external segment 保存——segment 背后的 page 属于目标文件，而不是模块私有页。
- 订阅者开启 window + CRC trailer 后，projection 会依次走 `append_deferred_trailer` → `prepare_crc32c` → `validate_crc32c_commit` → `commit_crc32c`。CRC commit 的语义是把计算出的 CRC32C 写回某个替换/提交位置；当该位置落在 external segment 上时，就变成对目标文件 page cache 的 4 字节写。
- 该写不经过文件权限检查：page cache 是内核共享缓存，模块直接改页内容；文件在磁盘上仍是原样，`open(O_RDONLY)` 也能作为 splice 源。
- CRC32C 对输入 bit 是线性的。wire header 中有一个 32 位可控 `user_tag`，固定其余字段后，可把 `user_tag` 的 32 个 bit 作为基向量，解线性方程组，使最终 CRC32C 等于想写入的 4 字节。
- 触发参数（示例）：`max_subscribers=2`；一个 subscriber `flags=6, window_offset=0, window_length=0x14`；另一个普通 subscriber `flags=1`；header 用 `write()` 送，payload 用 `sendfile()` 从 `target_off-16` 送 0x20 字节，使 CRC 窗口覆盖 16 字节前缀和目标 4 字节。
- 选择目标：`/bin/busybox` 是静态 ET_EXEC，原入口 `0x4020e0`，第一个可执行 LOAD 段满足 `vaddr-offset=0x400000`。把 shellcode 写到文件偏移 `0x1f99c0`（VA `0x5f99c0`），再把 ELF header 的 `e_entry` 改成 `0x5f99c0`；ctf shell 退出后 root 的 `rcS` 会执行 `poweroff`，重新 exec busybox 时运行 shellcode（open `/flag` + sendfile 到 stdout）。
- 这是数据-only 利用：不劫持内核控制流，不需要绕过 KASLR/SMEP/SMAP/KPTI；只利用模块把外部页交给可写 commit 路径的逻辑缺陷。

## 触发条件

- 内核模块存在“splice 外部 page 进入可写 segment/commit 路径”的逻辑缺陷，且设备对普通用户可读写。
- 目标文件可读（不需要写权限），且会被 root 在后续流程中 exec（如 `poweroff` → busybox、服务重启、cron 脚本）。
- 模块的 CRC window/trailer 参数可由用户通过 ioctl 控制（或存在等效的 4 字节写回原语）。
- `sendfile`/`splice` 与相关 fd 未被 seccomp/LSM 拦截。
- 攻击者已在目标上获得普通用户代码执行。

## 利用步骤

1. 逆向模块：找到 producer fd 的 splice actor、external segment 标记、CRC commit 写回路径，确认写回位置可由 window_offset/window_length 控制。
2. 复现写原语：创建 channel（`max_subscribers=2`），订阅 `flags=6, window_offset=0, window_length=0x14` 与 `flags=1`；用 `write()` 送 wire header，用 `sendfile()` 从 `target_off-16` 送 0x20 字节，确认目标 4 字节被 CRC 结果覆盖。
3. 控制写入值：按模块 frame header 布局构造 CRC 输入，枚举 32 个 `user_tag` 基向量，解线性方程求出使 CRC32C 等于目标 4 字节的 tag。
4. 封装 `patch4(path, off, bytes)`：每次 `pread` 目标前 16 字节作为前缀，解 tag，创建/订阅 channel，write header，sendfile，最后 `pread` 验证 4 字节。
5. 选目标与偏移：定位 root 后续会 exec 的静态二进制（如 busybox），找到可写代码 cave 与 VA 映射，计算 file offset/VA。
6. patch shellcode：按 4 字节循环写入 `open("/flag")`+`sendfile(1,fd,...)`+`exit` 的 shellcode；再 patch ELF `e_entry` 指向 shellcode。
7. 触发：退出当前 ctf shell，让 root 的启动脚本继续执行 `poweroff`，重新加载被 patch 的 busybox，读出 flag；磁盘文件哈希不变，重启后 page cache 清除。

## PoC

```c
// 关键：构造 0x40 字节 CRC 输入并解 user_tag
static void build_crc_input(unsigned char out[0x40], uint32_t channel_id,
                            uint32_t window_offset, uint32_t user_tag,
                            const unsigned char prefix[16]) {
    memset(out, 0, 0x40);
    put32(out + 0x00, 0x74747261U);
    put16(out + 0x04, 0x30);
    put16(out + 0x06, 0x3);
    put32(out + 0x08, channel_id);
    put32(out + 0x0c, 0x77777777U);
    put64(out + 0x10, 1);
    put64(out + 0x18, 0x2222222233333333ULL);
    put32(out + 0x20, user_tag);
    put32(out + 0x24, 0x14);
    put32(out + 0x28, window_offset);
    memcpy(out + 0x30, prefix, 16);
}

// 对 32 个 tag bit 建基向量，解出使 CRC == desired 的 user_tag
static uint32_t solve_user_tag(uint32_t channel_id, uint32_t window_offset,
                               const unsigned char prefix[16], uint32_t desired);
```

```c
// 4 字节 page cache 写：从 target_off-16 送 0x20 字节
struct d3kbus_wire_header h = {0};
h.magic = 0x3361626eU; h.header_length = 0x20; h.payload_length = 0x20;
h.stream_id = 0x77777777U; h.user_tag = tag; h.opaque = 0x2222222233333333ULL;
write(producer_fd, &h, sizeof(h));
off_t off = target_off - 16;
sendfile(producer_fd, target_fd, &off, 0x20);
```

```c
// shellcode: open("/flag", O_RDONLY); sendfile(1, fd, NULL, 0x100); exit(0)
// 写入 busybox 文件偏移 0x1f99c0（VA 0x5f99c0），再 patch e_entry 0x18/0x1c
```

完整 EXP 见原文（约 780 行 C）。PoC 未在本机执行；目标偏移/模块布局需按实际内核与二进制调整。

## 变体与关联

- 变体：目标不限于 busybox；任何 root 后续 exec 的静态/动态二进制、脚本解释器、setuid 程序都可 patch；动态链接程序需考虑 GOT/PLT 与加载器。
- 变体：若模块支持更长的 commit（仅 4 字节则循环 patch），可一次写更多字节；4 字节粒度足以改 `e_entry` 或短 shellcode。
- 变体：同类“外部页 page cache 写”原语也见于 AF_ALG AEAD `sg_chain` 污染 setuid 页缓存（CVE-2026-31431），但触发机制不同。
- 关联卡片：[[binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe]]（页缓存污染提权）、[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（内核 UAF 回调劫持）、[[binary-pwn-kernel-ioctl-global-length-oob-read-flag]]（驱动 ioctl 越界读）。
- 注意：本例为 D^3 CTF 2026 自定义模块（内核 7.1.4），不是公开 CVE；真实驱动是否有同类 external page + commit 路径需具体审计。

## 检测与防御

- 防御：模块代码审计——任何把外部页（pipe/splice/sendfile 进来的 page）放入可写 scatterlist/commit 目标的路径都必须禁止；commit 前校验目标 segment 的 origin，只允许模块私有页。
- 防御：内核模块签名与最小加载；限制 `/dev/<module>` 权限；seccomp 限制 `sendfile`/`splice`/`ioctl` 组合。
- 检测：监控对只读系统二进制的 page cache 修改（eBPF/kprobe 检查 `execve` 前页内容与磁盘哈希不一致）；busybox/关键二进制 `e_entry` 异常；模块 ioctl 高频 create/subscribe/sendfile 序列。
- 检测：数据-only 攻击不会触发传统 KASLR/SMEP/SMAP 告警；应依赖文件完整性、page cache 一致性与模块行为审计。
- 响应：卸载模块、重启清除 page cache、恢复被 patch 二进制、检查同主机其他 root-executed 文件、升级/修复模块。
