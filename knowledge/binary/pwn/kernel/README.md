# 内核利用

## 这层是什么

内核漏洞、提权、KASLR/SMEP/SMAP 绕过。

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
| [access_process_vm 读取子进程内存：task_struct children 遍历取 flag](binary-pwn-kernel-access-process-vm-task-children-read.md) | verified | high | 2026-11-06 |
| [babydriver 全局 buffer UAF：双 open + ioctl 释放 0xa8 块，fork 后 cred 复用并被 write 清零提权](binary-pwn-kernel-babydriver-cred-struct-uaf-hijack.md) | verified | medium | 2026-11-06 |
| [buddy 页级堆风水：PF_PACKET TX_RING 在用户态批量分配/释放 2^order 连续物理页](binary-pwn-kernel-buddy-page-spray-packet-tx-ring.md) | verified | high | 2026-11-06 |
| [Cross-Cache UAF 到 cred_jar：SLUB 整页归还 buddy 后由 clone 的 cred 回收，UAF 改写 uid/gid 提权（5.14+ SLAB_ACCOUNT 隔离）](binary-pwn-kernel-cross-cache-uaf-cred-jar-clone-lpe.md) | verified | medium | 2026-11-06 |
| [CVE-2022-21882 win32k 提权：回调中改 ConsoleWindow 标志导致 pExtraBytes 类型混淆](binary-pwn-kernel-cve-2022-21882-win32k-extrabytes-type-confusion.md) | verified | high | 2026-11-07 |
| [CVE-2024-1086 nf_tables verdict 0xffff0000 double free：IP 分片队列掩盖 + Dirty Pagetable 改 modprobe_path 提权](binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe.md) | verified | high | 2026-11-06 |
| [CVE-2024-30088 Windows 内核 TOCTOU：NtQueryInformationToken 用户缓冲区竞态污染安全属性链表，获取 winlogon 句柄提权 SYSTEM](binary-pwn-kernel-cve-2024-30088-ntqueryinformationtoken-toctou-securityattributes-lpe.md) | verified | high | 2026-11-07 |
| [CVE-2024-30090 ks.sys KSEVENT 竞争双重获取：QUERYBUFFER→ENABLE 绕过校验，KsIncrementCountedWorker 任意内核自增提权到 SYSTEM](binary-pwn-kernel-cve-2024-30090-ks-ksevent-race-arbitrary-increment-sedebug.md) | verified | high | 2026-11-07 |
| [CVE-2024-35250 ks.sys 属性反序列化 TOCTOU：伪造 RTL_BITMAP 经 RtlSetAllBits/RtlClearAllBits 任意内核位写，改 Token 特权或 PreviousMode 提权](binary-pwn-kernel-cve-2024-35250-ks-property-unserialize-toctou-rtlbitmap-lpe.md) | verified | high | 2026-11-07 |
| [CVE-2025-21333 vkrnlintvsp.sys DACL 长度 16 位截断池溢出：NtCreateCrossVmEvent → WNF 喷射 → I/O Ring 任意读写 → SYSTEM](binary-pwn-kernel-cve-2025-21333-vkrnlintvsp-dacl-truncation-pool-overflow.md) | verified | high | 2026-11-06 |
| [CVE-2025-21702 net/sched pfifo limit=0 父子 qlen 不一致：hfsc_class UAF 到 ROP 提权](binary-pwn-kernel-cve-2025-21702-pfifo-qlen-mismatch-uaf-lpe.md) | verified | high | 2026-11-06 |
| [CVE-2025-39964 AF_ALG sendmsg SGL 竞态越界：page_link 任意写 + core_pattern 提权/容器逃逸](binary-pwn-kernel-cve-2025-39964-af-alg-sgl-race-arbitrary-write-core-pattern.md) | verified | high | 2026-11-06 |
| [CVE-2026-23271 perf_event 竞态 UAF：filter 求值窗口 + msg_msg 跨缓存回收 + core_pattern 提权](binary-pwn-kernel-cve-2026-23271-perf-event-race-uaf-core-pattern-lpe.md) | verified | high | 2026-11-06 |
| [CVE-2026-31431 Copy Fail：AF_ALG AEAD + splice 污染 setuid 页缓存提权 root](binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe.md) | verified | high | 2026-11-05 |
| [CVE-2026-64563 rhashtable 多段遍历残留 iter->p：TIPC dump 表扩容 UAF 到 sk_destruct 劫持](binary-pwn-kernel-cve-2026-64563-rhashtable-stale-iter-p-tipc-uaf-lpe.md) | verified | medium | 2026-11-05 |
| [Dirty Pagetable：页表页 double free 制造 PMD/PTE 重叠，用户态任意物理内存读写与物理 KASLR 绕过](binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw.md) | verified | high | 2026-11-06 |
| [eBPF verifier 不一致寄存器构造与 OOB 任意读写提权（array_map_ops 劫持 / modprobe_path）](binary-pwn-kernel-ebpf-verifier-inconsistent-register-arbitrary-rw.md) | verified | medium | 2026-11-06 |
| [Egg Hunter 扫描物理内存残留：子进程退出后按 2GB 物理映射找 flag](binary-pwn-kernel-egg-hunter-physical-memory-scan.md) | verified | high | 2026-11-06 |
| [netfilter 模块 8bit hash 冲突 UAF：伪造 sec_conn AAR/AAW，改 kmem_cache->ctor 执行 slab shellcode](binary-pwn-kernel-netfilter-hash-collision-uaf-kmem-cache-ctor.md) | verified | high | 2026-11-06 |
| [pipe_buffer 自指与三管道互修：页级 UAF 升级为任意物理页读写](binary-pwn-kernel-self-writing-pipe-arbitrary-rw.md) | verified | high | 2026-11-06 |
| [QWB core 内核栈溢出：core_copy_func 16 位截断 + core_read off 越界泄露 canary + kernel ROP 提权](binary-pwn-kernel-qwb-core-stack-overflow-rop.md) | verified | medium | 2026-11-06 |
| [ret2dir + physmap spray：内核模块 ioctl 间接调用用户函数指针，借直接映射区用户页作内核 ROP 栈完成 commit_creds 提权](binary-pwn-kernel-ret2dir-physmap-spray-rop-commit-creds.md) | verified | high | 2026-11-06 |
| [seccomp 逃逸：内核 shellcode 清 TIF_SECCOMP 位](binary-pwn-kernel-shellcode-clear-tif-seccomp.md) | verified | high | 2026-11-06 |
| [sock UAF 的 refcount 竞态：利用 lock_sock 双层锁阻塞把 1→2→1 制造 double free](binary-pwn-kernel-sock-refcount-race-lock-sock-double-free.md) | verified | medium | 2026-11-05 |
| [Windows CNG.sys CVE-2020-17087 整数截断非分页池溢出：命名管道 DATA_QUEUE_ENTRY 池喷射到任意读写与 token 窃取](binary-pwn-kernel-windows-cng-pool-overflow-pipe-data-queue-token-steal.md) | verified | high | 2026-11-06 |
| [Windows I/O Ring + 命名管道任意读写：伪造 IOP_MC_BUFFER_ENTRY 并篡改预注册缓冲区指针](binary-pwn-kernel-windows-io-ring-pipe-arbitrary-rw.md) | verified | high | 2026-11-06 |
| [Windows WNF 分页池喷射与挖洞：0x50 块布局、状态标记定位与洞填充](binary-pwn-kernel-windows-wnf-paged-pool-spray-hole-digging.md) | verified | high | 2026-11-06 |
| [Windows 命名管道 Attribute 泄露 _NP_CCB：Flink → FileObject → DriverObject → NpFsdCreate 恢复内核基址](binary-pwn-kernel-windows-pipe-attribute-np-ccb-kaslr-leak.md) | verified | medium | 2026-11-06 |
| [内核 kmem_cache UAF + 同池对象复用：泄露 encoded_cb 并 XOR 改写成后门提权](binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack.md) | verified | high | 2026-11-05 |
| [内核 pwn 环境搭建与调试：bzImage/initramfs/9P 共享与 GDB 符号加载](binary-pwn-kernel-qemu-initramfs-gdb-workflow.md) | verified | high | 2026-11-05 |
| [内核 RWX vmalloc + 用户 shellcode 执行：commit_creds 提权](binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec.md) | verified | high | 2026-11-06 |
| [内核 seq_operations UAF + pt_regs 栈迁移：泄露内核基址后 ROP commit_creds(init_cred)](binary-pwn-kernel-seqops-uaf-pt-regs-stack-migration.md) | verified | high | 2026-11-06 |
| [内核任意读写后按 comm 扫描 task_struct 并沿 real_parent 找 init_task，覆写 cred/nsproxy 提权](binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe.md) | verified | high | 2026-11-06 |
| [内核栈溢出覆盖结构体函数指针：run_cmd/call_usermodehelper 提权与 printk KASLR 泄露](binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd.md) | verified | high | 2026-11-06 |
| [内核模块 chronos_ring 的 view 原语改写 /tmp/job page cache：root 定时任务执行脚本提权](binary-pwn-kernel-chronos-ring-view-page-cache-job-root-helper.md) | verified | high | 2026-11-06 |
| [内核模块 double free + io_uring personality cred 清零：SETXATTR 写 ACL 读 /flag](binary-pwn-kernel-double-free-io-uring-personality-zeroed-cred-acl.md) | verified | high | 2026-11-06 |
| [内核模块 ioctl 直接调用用户函数指针：无 KASLR 固定模块基址调用 win 提权](binary-pwn-kernel-module-ioctl-user-function-pointer-call.md) | verified | high | 2026-11-06 |
| [内核模块 splice 外部页 + CRC commit：可读文件 page cache 4 字节写并 patch busybox 入口提权](binary-pwn-kernel-splice-external-page-crc-commit-page-cache-write.md) | verified | high | 2026-11-06 |
| [内核队列驱动 max_entries=-1 整数回绕：0x20 堆溢出 + seq_operations 堆喷 + ret2usr 提权](binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr.md) | verified | high | 2026-11-06 |
| [内核驱动 double fetch 条件竞争：多线程改写用户指针，校验用假 buf、比较读真 flag（0CTF2018 baby kernel）](binary-pwn-kernel-double-fetch-user-pointer-race-flag.md) | verified | high | 2026-11-06 |
| [内核驱动 ioctl 越界读：全局长度控制 copy_to_user 泄露相邻 flag](binary-pwn-kernel-ioctl-global-length-oob-read-flag.md) | verified | high | 2026-11-05 |
| [内核驱动 write 无限累加文件长度 + seek 只按逻辑大小校验：任意偏移越界读写物理内存扫残留 flag](binary-pwn-kernel-write-size-growth-seek-oob-physical-scan.md) | verified | medium | 2026-11-06 |
| [跨缓存 off-by-null 命中 pipe_buffer.page 低字节：制造两管道同页的页级 UAF](binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
