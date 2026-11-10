---
id: binary-pwn-kernel-hfs-bnode-keylen-oob-heap-write
title: HFS/HFS+ bnode key_len 未校验：损坏镜像在 split 后读取最小 record 触发 hfs_bnode_read_key 堆溢出（CVE-2025-37782）
type: scenario
domain: binary
path: binary/pwn/kernel
technique: hfs-bnode-read-key-unchecked-keylen-heap-overflow
aliases:
- CVE-2025-37782
- HFS bnode 堆溢出
- hfs_bnode_read_key 溢出
- hfsplus_bnode_read_key
- key_len 未校验
- btree split 绕过 keylen 检查
- 恶意 HFS 镜像
tags:
- pwn
- kernel
- hfs
- hfsplus
- heap-overflow
- filesystem
- kasan
- cve
cve:
- CVE-2025-37782
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-19
  verified_at: '2026-11-08T09:07:55+08:00'
  notes: 已对照原文核对：4 张图确认 bnode 磁盘布局（0x1024F8 处 key 长度 0x24 改 0x64）、二分查找起点与 split 分界错开非法 record、gdb 断在 hfs_brec_insert+0x277 且 fd->search_key->key_len=0x64、slab kmalloc-96(size 0x60)；patch 内容、hfs_brec_keylen 检查绕过路径与卡片一致。保留理由：属可控内容/可控长度的内核堆越界写完整原语（构造镜像+mount+mkdir 即可稳定触发，有 KASAN 报告），按原语保留标准保留；原文未做提权、无 LPE，卡片已自述并标 confidence medium，未夸大为 RCE。未验证点：未本地复跑镜像，偏移依赖原文环境；原文未给内核受影响版本，affected_versions 保持空
---

## 一句话结论

Linux 的 `hfs_bnode_read_key()`/`hfsplus_bnode_read_key()` 按磁盘上的 `key_len` 直接 `memcpy` 进 `fd->search_key`（固定 `kmalloc(max_key_len*2+4)`），却不校验长度；攻击者构造损坏的 HFS/HFS+ 镜像，让某条 record 的 key 长度超出上限且**在二分查找与 `hfs_brec_keylen` 检查中从未被访问**，再通过 `mkdir` 触发 bnode split，内核就会在 `hfs_brec_insert()` 里把该 record 读进小缓冲区，形成可控长度、可控内容的堆溢出（原文以 KASAN 报告证实）。

## 原理

- **缓冲区是定长的**：`hfs_find_init()` 里 `ptr = kmalloc(tree->max_key_len * 2 + 4, GFP_KERNEL)`，`fd->search_key` 指向这块内存，`fd->key` 在其后 `max_key_len+2` 处。HFS 目录树 `max_key_len` 固定为 `HFS_MAX_CAT_KEYLEN`(0x25)，所以实际落到 `kmalloc-96`。
- **读取端不做边界检查**：`hfs_bnode_read_key(node, key, off)` 只判断 `node->tree->attributes & HFS_TREE_BIGKEYS` 决定 `key_len = max_key_len+1` 或读 `u16`，然后 `hfs_bnode_read(node, key, off, key_len)`——即按动态 `key_len` 往 `key` 所指的定长缓冲区拷贝。补丁正是加在这里：
  ```c
  if (key_len > sizeof(hfs_btree_key) || key_len < 1) { memset(key,0,...); return; }
  ```
- **为什么通常不会溢出**：正常路径上每条 record 的 `key_len` 都被 `hfs_brec_keylen()` 检查过——`((hfs_bnode_read_u8(recoff) | 1) + 1) > max_key_len + 1` 时报 “keylen too large” 并返回 0；`__hfs_brec_find()` 只要遇到 `keylen==0` 就 `-EINVAL` 返回。所以“从磁盘读入非法 key_len”本身不足以触发。
- **检查被跳过的关键**：`__hfs_brec_find()` 是**二分查找**，只会访问被比较到的 record。攻击者把非法 record 放在二分路径之外（原文：6 条 record 时从第 3 条开始比，非法的是第 4 条且位于半区之后），它在本次查找中永远不会被读，`hfs_brec_keylen()` 也就不会执行到它。
- **split 把非法 record 变成“最小键”**：`hfs_brec_insert()` 发现空间不足时调用 `hfs_bnode_split()`，按 `node_size/2` 把后半段 record 挪到新 node。随后执行
  ```c
  hfs_bnode_read_key(new_node, fd->search_key, 14);   /* 取新节点 14 偏移处的最小 record 作索引键 */
  __hfs_brec_find(fd->bnode, fd);
  ```
  这行**没有先调用 `hfs_brec_keylen()`**，而新 node 偏移 14 处的 record 正是刚被搬过去、从未被访问过的非法 record。于是 `key_len`（如 0x64）大于 `search_key` 的实际容量（0x60），`hfs_bnode_read()` 的 `memcpy_from_page` 越过缓冲区尾部。
- **危害形态**：溢出内容是攻击者写在镜像里的 key 字节、溢出长度由 `key_len`（u16）决定，属于可控内容的堆越界写；原文只做到 KASAN 报告（`__asan_memcpy` → `hfs_bnode_read` → `hfs_bnode_read_key` → `hfs_brec_insert` → `hfs_cat_create` → `hfs_mkdir`），未给出提权利用。
- **补丁性质**：CVE 的修复是“长度范围兜底”，真正的逻辑缺陷是 split 之后读取新节点最小 record 时缺少 size 校验；因此仅靠“访问时检查 keylen”无法覆盖该路径。
- **入口为什么可行**：`hfs_mkdir → hfs_cat_create → hfs_brec_insert`，用户只需在挂载的 HFS 镜像里 `mkdir` 就能触发写入与分裂，不需要额外 ioctl。

## 触发条件

- 内核开启 `CONFIG_HFS_FS`（或 `CONFIG_HFSPLUS_FS`），且未打 CVE-2025-37782 修复补丁。
- 攻击者能让内核挂载其可控的 HFS/HFS+ 镜像：本地挂载（需权限/用户命名空间 + loop）、U 盘/移动介质自动挂载、或解析不可信镜像的服务（镜像分析、备份还原、容器镜像层）。
- 镜像中的 catalog btree 某个 bnode 满足：非法 key_len 的 record 位于二分查找不会访问的位置，且会在 split 时被划入新 node 并成为 14 偏移处的最小 record；同时需要预留足够空间让下一次 insert 触发分裂。
- 挂载后能创建目录（`mkdir`），使 `hfs_brec_insert` 走到 `hfs_bnode_split` 分支。

## 利用步骤

1. 准备镜像：`qemu-img create -f raw disk1.img 1G`，`mkfs.hfs -v "MyHFS" disk1.img`（HFS+ 用 `mkfs.hfsplus`）。
2. 挂载并创建两个目录，使 btree 产生多条 record：`mkdir 1111111111111111`、`mkdir 222222222222222222222222222222`。
3. 用 `hexedit disk1.img` 跳到 catalog bnode（原文 `0x102400`），确认 node 结构与 record 偏移；把目标 record 的 key 长度字节由 `0x24` 改为 `0x64`（超出 `max_key_len`），并确保该 record 处于二分查找路径之外、split 后归入新 node。
4. 重新挂载镜像，创建一个小名字目录（如 30 个 `0`），使插入触发 `hfs_bnode_split`；`hfs_brec_insert` 读取新 node 的最小 record 时溢出。
5. 观察 KASAN：`memcpy_from_page`/`hfs_bnode_read` 在 `hfs_bnode_read_key` 处越界写，调用栈含 `hfs_cat_create`/`hfs_mkdir`。
6. 若要继续做利用，需要在溢出点之后做堆风水（控制 `kmalloc-96` 相邻对象）并把溢出转成对象字段改写；原文未提供该步骤。

## PoC

```bash
# 1) 造镜像并挂载
qemu-img create -f raw disk1.img 1G
mkfs.hfs -v "MyHFS" ./disk1.img
mount -t hfs -o rw /dev/vda /mnt/hfs

# 2) 制造多条 catalog record
mkdir /mnt/hfs/1111111111111111
mkdir /mnt/hfs/222222222222222222222222222222

# 3) 改坏 key_len：bnode 位于 0x102400，目标 record 的 key 长度 0x24 -> 0x64
hexedit ./disk1.img      # 光标跳 0x1024F8，将 24 改为 64

# 4) 重新挂载后触发 split
mkdir /mnt/hfs/000000000000000000000000000000
```

说明：偏移 `0x1024F8`、`0x24→0x64` 与目录名长度均取自原文环境，换镜像布局需重新定位 record 偏移；本条未在本地复跑。

## 变体与关联

- **HFS+ 变体**：同一缺陷在 `fs/hfsplus/bnode.c` 的 `hfsplus_bnode_read_key()`（`key_len = max_key_len + 2`），补丁同样是长度范围兜底，触发路径一致。
- **绕过技巧变体**：不限于 split，任何“先取键再校验”的路径都能绕过 `hfs_brec_keylen`；也可利用 `HFS_TREE_VARIDXKEYS` 与 `HFS_TREE_BIGKEYS` 组合改变 `key_len` 的取值方式。
- **同类审计点**：内核里大量 `kmalloc(max_*_len*2+4)` + 按磁盘字段 `memcpy` 的文件系统代码（ext4/xfs/ntfs 的 name/key 读取）都应检查“读取前是否按目标缓冲区大小校验”。
- **关联**：[[binary-pwn-kernel-qemu-initramfs-gdb-workflow]]（同类 QEMU+gdb 调试手法）。

## 检测与防御

- **检测**：内核日志出现 `hfs: Invalid key length`（已打补丁）或 `keylen %d too large` 的异常刷屏；KASAN splat 落在 `hfs_bnode_read_key`/`hfsplus_bnode_read_key`；挂载来源不可信的 HFS 镜像后立即 `mkdir` 的行为；`hfs_bnode_read_key` 处 `search_key` 的 slab 越界。
- **修复**：升级到含 CVE-2025-37782 补丁的内核（`hfs_bnode_read_key`/`hfsplus_bnode_read_key` 增加 `key_len` 范围检查并清零）；根因层面应在 `hfs_brec_insert` 调用 `hfs_bnode_read_key(new_node, fd->search_key, 14)` 之前先走 `hfs_brec_keylen()` 校验并拒绝非法节点。
- **加固**：禁止非特权用户挂载任意文件系统镜像（`mount` 需 CAP_SYS_ADMIN，限制 userns+loop 组合）；对自动挂载的移动介质先做镜像校验；生产环境不编译 HFS/HFS+（macOS 生态外基本无用）；镜像解析类服务在独立沙箱/虚拟机中运行。
