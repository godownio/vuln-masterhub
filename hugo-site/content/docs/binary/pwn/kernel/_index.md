---
title: 内核利用
weight: 1
---

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
| [/sys/kernel/notes 泄露内核基址：world-readable ELF notes 中的内核地址绕过 KASLR](binary-pwn-kernel-sys-kernel-notes-kaslr-leak/) | verified | high | 2026-11-12 |
| [access_process_vm 读取子进程内存：task_struct children 遍历取 flag](binary-pwn-kernel-access-process-vm-task-children-read/) | verified | high | 2026-11-06 |
| [babydriver 全局 buffer UAF：双 open + ioctl 释放 0xa8 块，fork 后 cred 复用并被 write 清零提权](binary-pwn-kernel-babydriver-cred-struct-uaf-hijack/) | verified | medium | 2026-11-06 |
| [buddy 页级堆风水：PF_PACKET TX_RING 在用户态批量分配/释放 2^order 连续物理页](binary-pwn-kernel-buddy-page-spray-packet-tx-ring/) | verified | high | 2026-11-06 |
| [Cross-Cache UAF 到 cred_jar：SLUB 整页归还 buddy 后由 clone 的 cred 回收，UAF 改写 uid/gid 提权（5.14+ SLAB_ACCOUNT 隔离）](binary-pwn-kernel-cross-cache-uaf-cred-jar-clone-lpe/) | verified | medium | 2026-11-06 |
| [CVE-2019-0708 BlueKeep：重复绑定 MS_T120 虚拟通道造成 termdd.sys UAF，非分页池堆喷伪造通道结构执行内核 shellcode](binary-pwn-kernel-cve-2019-0708-bluekeep-ms-t120-uaf-nonpaged-pool-rce/) | verified | high | 2026-11-11 |
| [CVE-2021-22555：kmalloc-4k 空字节 OOB 经 msg_msg 主/辅消息别名化转 double free，m_ts 越界读泄露堆与内核基址后劫持 pipe_buffer ops 走 ROP 提权](binary-pwn-kernel-cve-2021-22555-msg-msg-oob-double-free-pipe-ops-rop/) | verified | high | 2026-11-10 |
| [CVE-2022-21882 win32k 提权：回调中改 ConsoleWindow 标志导致 pExtraBytes 类型混淆](binary-pwn-kernel-cve-2022-21882-win32k-extrabytes-type-confusion/) | verified | high | 2026-11-07 |
| [CVE-2023-35001 nftables nft_byteorder 16 位元素栈越界：改写 nft_do_chain 的 jumpstack 指针，泄漏 nf_tables.ko 与内核基址并植入假 nft_payload 表达式执行 ROP 提权](binary-pwn-kernel-cve-2023-35001-nft-byteorder-stack-oob-jumpstack-rop/) | verified | medium | 2026-11-13 |
| [CVE-2023-3609 cls_u32/drr filter_cnt 引用计数 UAF：eBPF JIT 堆喷 shellcode + cpu_entry_area 伪造 qdisc 提权](binary-pwn-kernel-cve-2023-3609-cls-u32-drr-filter-cnt-uaf-ebpf-jit-core-pattern/) | verified | high | 2026-11-12 |
| [CVE-2023-36802 mskssrv.sys 类型混淆：PublishRx 把 FSContextReg 当 FSStreamReg 越界，ObfDereferenceObject 递减 PreviousMode 后任意内核读写提权](binary-pwn-kernel-cve-2023-36802-mskssrv-type-confusion-previousmode-token-steal/) | verified | high | 2026-11-12 |
| [CVE-2023-4004 nft_set_pipapo 删除缺 KEY_END 的 elem 失败：残留指针 double free，table->udata 占位转 UAF 后劫持 nft_object->ops 走 ROP 提权](binary-pwn-kernel-cve-2023-4004-nft-pipapo-elem-double-free-table-udata-nft-object-ops-rop/) | verified | medium | 2026-11-12 |
| [CVE-2023-5345 smbfs fsconfig password 双重释放：kmalloc-32 重叠泄露内核基址与堆地址，转 ovl_dir_file UAF 后 lseek 执行 ROP](binary-pwn-kernel-cve-2023-5345-smbfs-fsconfig-double-free-ovl-dir-file-rop/) | verified | medium | 2026-11-12 |
| [CVE-2023-6546 n_gsm 条件竞争：双线程 gsm_disconnect 释放 dlci 造成 UAF，调度优先级扩窗后 add_key 占位劫持 output 提权](binary-pwn-kernel-cve-2023-6546-n-gsm-race-dlci-uaf-sched-window/) | verified | medium | 2026-11-12 |
| [CVE-2024-1086 nf_tables verdict 0xffff0000 double free：IP 分片队列掩盖 + Dirty Pagetable 改 modprobe_path 提权](binary-pwn-kernel-cve-2024-1086-nft-verdict-double-free-dirty-pagetable-modprobe/) | verified | high | 2026-11-06 |
| [CVE-2024-30088 Windows 内核 TOCTOU：NtQueryInformationToken 用户缓冲区竞态污染安全属性链表，获取 winlogon 句柄提权 SYSTEM](binary-pwn-kernel-cve-2024-30088-ntqueryinformationtoken-toctou-securityattributes-lpe/) | verified | high | 2026-11-07 |
| [CVE-2024-30090 ks.sys KSEVENT 竞争双重获取：QUERYBUFFER→ENABLE 绕过校验，KsIncrementCountedWorker 任意内核自增提权到 SYSTEM](binary-pwn-kernel-cve-2024-30090-ks-ksevent-race-arbitrary-increment-sedebug/) | verified | high | 2026-11-07 |
| [CVE-2024-35250 ks.sys 属性反序列化 TOCTOU：伪造 RTL_BITMAP 经 RtlSetAllBits/RtlClearAllBits 任意内核位写，改 Token 特权或 PreviousMode 提权](binary-pwn-kernel-cve-2024-35250-ks-property-unserialize-toctou-rtlbitmap-lpe/) | verified | high | 2026-11-07 |
| [CVE-2025-21333 vkrnlintvsp.sys DACL 长度 16 位截断池溢出：NtCreateCrossVmEvent → WNF 喷射 → I/O Ring 任意读写 → SYSTEM](binary-pwn-kernel-cve-2025-21333-vkrnlintvsp-dacl-truncation-pool-overflow/) | verified | high | 2026-11-06 |
| [CVE-2025-21702 net/sched pfifo limit=0 父子 qlen 不一致：hfsc_class UAF 到 ROP 提权](binary-pwn-kernel-cve-2025-21702-pfifo-qlen-mismatch-uaf-lpe/) | verified | high | 2026-11-06 |
| [CVE-2025-39964 AF_ALG sendmsg SGL 竞态越界：page_link 任意写 + core_pattern 提权/容器逃逸](binary-pwn-kernel-cve-2025-39964-af-alg-sgl-race-arbitrary-write-core-pattern/) | verified | high | 2026-11-06 |
| [CVE-2026-23271 perf_event 竞态 UAF：filter 求值窗口 + msg_msg 跨缓存回收 + core_pattern 提权](binary-pwn-kernel-cve-2026-23271-perf-event-race-uaf-core-pattern-lpe/) | verified | high | 2026-11-06 |
| [CVE-2026-31431 Copy Fail：AF_ALG AEAD + splice 污染 setuid 页缓存提权 root](binary-pwn-kernel-cve-2026-31431-page-cache-poisoning-lpe/) | verified | high | 2026-11-05 |
| [CVE-2026-64563 rhashtable 多段遍历残留 iter->p：TIPC dump 表扩容 UAF 到 sk_destruct 劫持](binary-pwn-kernel-cve-2026-64563-rhashtable-stale-iter-p-tipc-uaf-lpe/) | verified | medium | 2026-11-05 |
| [Dirty Pagetable：页表页 double free 制造 PMD/PTE 重叠，用户态任意物理内存读写与物理 KASLR 绕过](binary-pwn-kernel-dirty-pagetable-pmd-pte-overlap-physical-rw/) | verified | high | 2026-11-06 |
| [eBPF verifier 不一致寄存器构造与 OOB 任意读写提权（array_map_ops 劫持 / modprobe_path）](binary-pwn-kernel-ebpf-verifier-inconsistent-register-arbitrary-rw/) | verified | medium | 2026-11-06 |
| [Egg Hunter 扫描物理内存残留：子进程退出后按 2GB 物理映射找 flag](binary-pwn-kernel-egg-hunter-physical-memory-scan/) | verified | high | 2026-11-06 |
| [HFS/HFS+ bnode key_len 未校验：损坏镜像在 split 后读取最小 record 触发 hfs_bnode_read_key 堆溢出（CVE-2025-37782）](binary-pwn-kernel-hfs-bnode-keylen-oob-heap-write/) | verified | medium | 2026-11-08 |
| [kernfs_pr_cont_buf 内核数据布置：iptables cgroup match 的 --path 把可控数据写进已知地址全局缓冲区](binary-pwn-kernel-kernfs-pr-cont-buf-cgroup-path-data-placement/) | verified | medium | 2026-11-12 |
| [KVA Shadow 下绕过用户页 NX：ROP 调 ExAllocatePoolWithTag 分配可执行非分页池 + RtlCopyMemory 复制 shellcode 并 jmp rax](binary-pwn-kernel-windows-kvas-nonpaged-pool-executable-shellcode-rop/) | verified | high | 2026-11-12 |
| [netfilter 模块 8bit hash 冲突 UAF：伪造 sec_conn AAR/AAW，改 kmem_cache->ctor 执行 slab shellcode](binary-pwn-kernel-netfilter-hash-collision-uaf-kmem-cache-ctor/) | verified | high | 2026-11-06 |
| [NtQuerySystemInformation 的 SystemModuleInformation（0xB）类：用户态枚举内核模块并泄露 ntoskrnl.exe 基址](binary-pwn-kernel-ntquerysysteminformation-systemmoduleinformation-kernel-base-leak/) | verified | high | 2026-11-12 |
| [pipe_buffer 自指与三管道互修：页级 UAF 升级为任意物理页读写](binary-pwn-kernel-self-writing-pipe-arbitrary-rw/) | verified | high | 2026-11-06 |
| [QWB core 内核栈溢出：core_copy_func 16 位截断 + core_read off 越界泄露 canary + kernel ROP 提权](binary-pwn-kernel-qwb-core-stack-overflow-rop/) | verified | medium | 2026-11-06 |
| [ret2dir + physmap spray：内核模块 ioctl 间接调用用户函数指针，借直接映射区用户页作内核 ROP 栈完成 commit_creds 提权](binary-pwn-kernel-ret2dir-physmap-spray-rop-commit-creds/) | verified | high | 2026-11-06 |
| [seccomp 逃逸：内核 shellcode 清 TIF_SECCOMP 位](binary-pwn-kernel-shellcode-clear-tif-seccomp/) | verified | high | 2026-11-06 |
| [simple_xattr 双向链表泄露内核堆地址：list_add 改写 list.prev，借重叠读定位用户数据堆块](binary-pwn-kernel-simple-xattr-list-heap-address-leak/) | verified | medium | 2026-11-12 |
| [SMEP 绕过：内核 ROP 链 pop rcx;ret + mov cr4,rcx 清 CR4.SMEP 后跳用户态 shellcode](binary-pwn-kernel-windows-smep-bypass-cr4-rop/) | verified | high | 2026-11-12 |
| [sock UAF 的 refcount 竞态：利用 lock_sock 双层锁阻塞把 1→2→1 制造 double free](binary-pwn-kernel-sock-refcount-race-lock-sock-double-free/) | verified | medium | 2026-11-05 |
| [struct file UAF：用 f_count 的 dup 自增当「PTE 值 +0x1000」原语，dma-heap 邻接映射收拢控制权后任意物理读写并补丁内核 text（nsjail 逃逸）](binary-pwn-kernel-file-uaf-fcount-pte-overlap-dmaheap-physical-rw/) | verified | medium | 2026-11-08 |
| [USMA：把 packet ring 的 pg_vec 指针改成内核只读页的虚拟地址，用 packet_mmap 把该内核页映射进用户态直接改写内核代码/数据（modprobe_path、__sys_setresuid 判断分支）](binary-pwn-kernel-usma-packet-ring-kernel-page-mapping/) | verified | high | 2026-11-09 |
| [vm_close 每次 munmap 都无条件减引用：拆分 munmap 把 ChunkManager 引用多减一次造成 UAF，再用 USMA 伪造成 page 表劫持 vm_fault](binary-pwn-kernel-d3kshrm-vm-close-refcount-uaf-page-table-hijack/) | verified | medium | 2026-11-08 |
| [Windows 10 Segment Heap 池溢出：POOL_HEADER 的 CacheAligned/PreviousSize 造 ghost chunk 并借伪造 PipeAttribute 任意读提权](binary-pwn-kernel-windows-segment-heap-ghost-chunk-pipe-attribute-lpe/) | verified | low | 2026-11-12 |
| [Windows CLFS 驱动 BLF 元数据漏洞族：篡改 SignaturesOffset/cbSymbolZone/控制记录索引与校验和，改写 CLFS_CONTAINER_CONTEXT.pContainer 虚表指针提权](binary-pwn-kernel-windows-clfs-blf-metadata-pcontainer-hijack-lpe/) | verified | low | 2026-11-12 |
| [Windows CNG.sys CVE-2020-17087 整数截断非分页池溢出：命名管道 DATA_QUEUE_ENTRY 池喷射到任意读写与 token 窃取](binary-pwn-kernel-windows-cng-pool-overflow-pipe-data-queue-token-steal/) | verified | high | 2026-11-06 |
| [Windows I/O Ring + 命名管道任意读写：伪造 IOP_MC_BUFFER_ENTRY 并篡改预注册缓冲区指针](binary-pwn-kernel-windows-io-ring-pipe-arbitrary-rw/) | verified | high | 2026-11-06 |
| [Windows WNF 分页池喷射与挖洞：0x50 块布局、状态标记定位与洞填充](binary-pwn-kernel-windows-wnf-paged-pool-spray-hole-digging/) | verified | high | 2026-11-06 |
| [Windows 内核 shellcode 遍历 EPROCESS ActiveProcessLinks 窃取 System Token 提权](binary-pwn-kernel-windows-shellcode-token-steal-eprocess/) | verified | high | 2026-11-12 |
| [Windows 命名管道 Attribute 泄露 _NP_CCB：Flink → FileObject → DriverObject → NpFsdCreate 恢复内核基址](binary-pwn-kernel-windows-pipe-attribute-np-ccb-kaslr-leak/) | verified | medium | 2026-11-06 |
| [Windows 第三方驱动 MDL double free → Ws2P 对象 UAF 与任意递减改 KTHREAD.PreviousMode 提权](binary-pwn-kernel-windows-driver-mdl-doublefree-ws2p-arbitrary-decrement-previousmode/) | verified | low | 2026-11-10 |
| [Windows 驱动 IOCTL 栈溢出：memmove 超长用户缓冲覆盖内核栈返回地址](binary-pwn-kernel-windows-driver-stack-overflow-ioctl-ret-hijack/) | verified | high | 2026-11-12 |
| [内核 kmem_cache UAF + 同池对象复用：泄露 encoded_cb 并 XOR 改写成后门提权](binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack/) | verified | high | 2026-11-05 |
| [内核 pwn 环境搭建与调试：bzImage/initramfs/9P 共享与 GDB 符号加载](binary-pwn-kernel-qemu-initramfs-gdb-workflow/) | verified | high | 2026-11-05 |
| [内核 RWX vmalloc + 用户 shellcode 执行：commit_creds 提权](binary-pwn-kernel-rwx-vmalloc-user-shellcode-exec/) | verified | high | 2026-11-06 |
| [内核 seq_operations UAF + pt_regs 栈迁移：泄露内核基址后 ROP commit_creds(init_cred)](binary-pwn-kernel-seqops-uaf-pt-regs-stack-migration/) | verified | high | 2026-11-06 |
| [内核 shellcode 干净返回用户态：修 KernelApcDisable，从 _KTRAP_FRAME 恢复 Rip/Rsp 后 swapgs + sysret](binary-pwn-kernel-windows-kernel-shellcode-return-trapframe-swapgs-sysret/) | verified | high | 2026-11-12 |
| [内核任意读写后按 comm 扫描 task_struct 并沿 real_parent 找 init_task，覆写 cred/nsproxy 提权](binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe/) | verified | high | 2026-11-06 |
| [内核栈溢出覆盖结构体函数指针：run_cmd/call_usermodehelper 提权与 printk KASLR 泄露](binary-pwn-kernel-stack-overflow-struct-function-pointer-run-cmd/) | verified | high | 2026-11-06 |
| [内核模块 chronos_ring 的 view 原语改写 /tmp/job page cache：root 定时任务执行脚本提权](binary-pwn-kernel-chronos-ring-view-page-cache-job-root-helper/) | verified | high | 2026-11-06 |
| [内核模块 double free + io_uring personality cred 清零：SETXATTR 写 ACL 读 /flag](binary-pwn-kernel-double-free-io-uring-personality-zeroed-cred-acl/) | verified | high | 2026-11-06 |
| [内核模块 ioctl 抬高全局 MaxBuffer + sread 越界栈读：泄露 canary 与内核基址后 kernel ROP commit_creds 提权](binary-pwn-kernel-ioctl-maxbuffer-stack-read-leak-rop-commit-creds/) | verified | high | 2026-11-08 |
| [内核模块 ioctl 直接调用用户函数指针：无 KASLR 固定模块基址调用 win 提权](binary-pwn-kernel-module-ioctl-user-function-pointer-call/) | verified | high | 2026-11-06 |
| [内核模块 ioctl 隐藏提权命令：objdump 还原命令码/魔数后 commit_creds(prepare_kernel_cred(0)) 提权](binary-pwn-kernel-module-ioctl-magic-commit-creds/) | verified | high | 2026-11-08 |
| [内核模块 splice 外部页 + CRC commit：可读文件 page cache 4 字节写并 patch busybox 入口提权](binary-pwn-kernel-splice-external-page-crc-commit-page-cache-write/) | verified | high | 2026-11-06 |
| [内核模块 vm_fault 用 `pgoff <= page_num` 判界，配合未注册 vm_mremap 的 mremap 扩容，跨缓存接到 pipe_buffer.page 改写只读文件页](binary-pwn-kernel-d3kshrm-vm-fault-pgoff-offbyone-mremap-cross-cache/) | verified | high | 2026-11-08 |
| [内核队列驱动 max_entries=-1 整数回绕：0x20 堆溢出 + seq_operations 堆喷 + ret2usr 提权](binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr/) | verified | high | 2026-11-06 |
| [内核驱动 double fetch 条件竞争：多线程改写用户指针，校验用假 buf、比较读真 flag（0CTF2018 baby kernel）](binary-pwn-kernel-double-fetch-user-pointer-race-flag/) | verified | high | 2026-11-06 |
| [内核驱动 ioctl 越界读：全局长度控制 copy_to_user 泄露相邻 flag](binary-pwn-kernel-ioctl-global-length-oob-read-flag/) | verified | high | 2026-11-05 |
| [内核驱动 write 无限累加文件长度 + seek 只按逻辑大小校验：任意偏移越界读写物理内存扫残留 flag](binary-pwn-kernel-write-size-growth-seek-oob-physical-scan/) | verified | medium | 2026-11-06 |
| [按 SLUB cpu_partial 与 objs_per_slab 精确布点：七步申请/释放把指定 slab 页整页归还 buddy，完成可控的 cross-cache 页回收](binary-pwn-kernel-slub-cpu-partial-stepwise-page-release-cross-cache/) | verified | high | 2026-11-08 |
| [窃取 System Token 后开启全部特权：直接覆写 _SEP_TOKEN_PRIVILEGES 的 Present/Enabled 掩码](binary-pwn-kernel-windows-sep-token-privileges-enable-all/) | verified | high | 2026-11-12 |
| [跨缓存 off-by-null 命中 pipe_buffer.page 低字节：制造两管道同页的页级 UAF](binary-pwn-kernel-page-level-uaf-pipe-buffer-off-by-null/) | verified | high | 2026-11-06 |
| [页级 UAF 重分配为 victim 对象 slab：整页读写同一 cache 的全部结构体，改 file->f_mode/f_mapping 等数据字段做 data-only 提权](binary-pwn-kernel-page-uaf-victim-object-data-only-lpe/) | verified | medium | 2026-11-10 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
