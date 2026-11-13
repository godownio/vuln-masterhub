---
id: binary-pwn-kernel-simple-xattr-list-heap-address-leak
title: simple_xattr 双向链表泄露内核堆地址：list_add 改写 list.prev，借重叠读定位用户数据堆块
type: scenario
domain: binary
path: binary/pwn/kernel
technique: simple-xattr-list-heap-address-leak
tags:
- linux
- kernel
- pwn
- heap-leak
- simple-xattr
- list-head
- user-key-payload
- kmalloc
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V593
  verified_at: '2026-11-12T15:31:33+08:00'
  notes: 已对照原文与截图核对：simple_xattr 布局(list/name/size/value)、simple_xattr_set 的 list_add(&new_xattr->list,&xattrs->head)、新增 xattr 后原首元素 VX 的 list.prev 被改写为新节点地址、经 user_key_payload 读回 list.prev 定位 kmalloc-8192 用户数据块，均与原文和图03 链表前后示意一致；该原语确为 CVE-2023-5345 链的第二步泄露，与主链卡为'通用原语+具体 CVE 链'关系，非同链重复。修正：原文'获取两个 kmalloc-8192 地址'的取法，原卡第5步写'对同一 VX 重复新增即可'不成立——list_add 每次只改当前表头首元素的 prev，VX 失去首元素地位后其 prev 固定指向首个新节点；已改为用第二对 VX/payload 重叠重复获取。未验证点：原文未给可运行代码，PoC 为原理示意，未实测偏移对齐。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-simple-xattr-list-heap-address-leak/
draft: false
kb_aliases:
- simple_xattr 泄露堆地址
- xattr 链表堆泄露
- list.prev 泄露
- 内核堆地址泄露
- kmalloc-8192 定位
---

## 一句话结论

当能通过 UAF/重叠读让一个可读对象（如 `user_key_payload`）覆盖 `simple_xattr` 时，向同一文件再 `setxattr` 一个 8192 字节属性会触发 `list_add(&new_xattr->list, &xattrs->head)`，把原首元素 VX 的 `list.prev` 改成新节点的内核地址（该节点后紧跟用户可控的 name/size/value）；从重叠对象读回这个链表指针，就得到"存放攻击者数据的内核堆地址"，可用于伪造 `file`/`f_op`/ROP 链。

## 原理

- **simple_xattr 布局**：`struct simple_xattr { struct list_head list; char *name; size_t size; char value[]; }`。`list` 在偏移 0（next +0x00、prev +0x08），`name`（+0x10）指向属性名串，`size`（+0x18）为 value 长度，`value` 从 +0x20 起完全由用户态控制。`simple_xattr_set` 按需 `kzalloc(sizeof(*new_xattr) + size)`，即用户可用 `setxattr` 的 value 长度选择缓存（本例取 64 字节 value 落在 kmalloc-96，8192 字节落在 kmalloc-8192）。
- **链表更新机制**：同一 inode 的所有 simple_xattr 挂在 `simple_xattrs` 的双向链表上，新属性用 `list_add(&new_xattr->list, &xattrs->head)` 插到表头。标准 `__list_add(new, head, head->next)` 会写 `new->next = head->next; new->prev = head; head->next->prev = new; head->next = new`——关键在第三句：原表头首元素（VX）的 `list.prev` 被改成新节点的地址。也就是说，只要 VX 还在链表里，新增任意 xattr 都会把"新节点的内核地址"写进 VX+0x8。
- **为什么能读**：`list_add` 改的是内存内容，不需要 VX 本身可控；攻击者只需要一个与 VX 同缓存重叠的读通道。在 CVE-2023-5345 的链中，先用 double free 把 `user_key_payload`（可通过 `keyctl_read` 读回其 data 区）与 VX 重叠；`keyctl_read` 返回的就是 VX 的原始字节（从 payload data 起点映射）。读出的 `list.prev` 即新 xattr 节点的内核虚拟地址。
- **为什么这个地址有用**：新节点的 `value` 区是攻击者写入的 8192 字节数据，且节点地址已知 → 等价于"内核地址已知的可控数据块"。这种块可直接放伪造的 `struct file`、`file_operations`、ROP 链（无需再泄露物理映射或做堆喷猜地址），比一般的堆喷命中率/稳定性高。再执行一次同样的新增即可得到第二个已知地址（链表首元素交替更新，VX 的 prev 指向最新节点）。
- **注意偏移映射**：`user_key_payload` 数据区不是从对象起始处开始（前面还有 `rcu_head` 与 `datalen` 等头部），实际读到的第 X 字节对应 VX 的哪个字段取决于该对象布局与重叠偏移，利用时需在调试环境中用已知标记（如 xattr 名）对齐确认；本文只给出字段级原理。
- **可替代性**：任何"内核链表插入会把新节点地址写进可读字段"的结构都能做同样的事；文章总结也点名 `msg_msg`、`nft_set`/`nft_object` 等链表/对象指针泄露思路本质相同。

## 触发条件

- 已有一个能把 `simple_xattr` 与可读对象放同一缓存并重叠的 UAF/double-free 原语（本文来自 CVE-2023-5345 的 fsconfig 双重释放，缓存大小 kmalloc-96）。
- 目标路径支持 `user.*` 扩展属性（tmpfs、ext4 等），单属性 8192 字节可创建（需在文件系统/`XATTR_SIZE_MAX` 限制内）。
- 能对同一文件多次 `setxattr`（至少两次：先放 VX，再触发 list_add 更新）。
- 有内核信息泄露通道读回重叠对象字节（`keyctl_read` 读 `user_key_payload` 最常用）。

## 利用步骤

1. 用 double free/UAF 在 kmalloc-96 上分配 VX（`setxattr(file, "vx", buf, 64, 0)`，value 大小使对象落入目标缓存），并让 `user_key_payload` 与之重叠、成为唯一可读通道。
2. 对同一文件再 `setxattr(file, "big", bigbuf, 8192, 0)`：`simple_xattr_set` 分配 kmalloc-8192 新节点并 `list_add` 到表头，VX->list.prev 被更新为新节点地址。
3. `keyctl_read(key, out, outlen)` 读重叠对象，取 VX 的 `list.prev`（struct 偏移 +0x8，按 payload 头部偏移换算），得到 `&new_xattr->list` 的内核地址。
4. 该地址 +0x20 起就是攻击者写入的 8192 字节 value；在其中布置伪造结构（如 `struct file` 的 `f_op`、`file_operations`、ROP 链），并把已知地址填到上一阶段伪造对象的指针字段。
5. 需要第二个已知块时，用第二对 VX/`user_key_payload` 重叠重复第 1–3 步：`list_add` 每次只改写"当前表头首元素"的 `prev`，VX 一旦不再是首元素，其 `list.prev` 就固定指向第一次新增的节点，后续新增不会更新它，因此不能靠对同一 VX 反复新增取第二个地址。

## PoC

原文未给可运行代码，以下为按原理整理的最小示意：

```c
/* 前置：VX 已在 kmalloc-96 与 user_key_payload 重叠（见关联卡的 double free 链） */
char small[64] = {0};
setxattr("/mnt/t/file", "vx", small, sizeof(small), 0);   // 建立 VX，落在 kmalloc-96

char big[8192];
memset(big, 'B', sizeof(big));
strcpy(big, "FAKE_FILE");                                  // 用户可控数据
setxattr("/mnt/t/file", "big", big, sizeof(big), 0);       // 新增节点，VX->list.prev = &new_xattr->list

unsigned char leak[256];
keyctl_read(key_serial, (char *)leak, sizeof(leak));       // 读重叠对象字节
unsigned long heap_addr = *(unsigned long *)(leak + payload_to_xattr_off + 0x8);
// heap_addr 即 kmalloc-8192 节点地址，heap_addr+0x20 起为 big[] 内容
```

`payload_to_xattr_off` 需按 `user_key_payload` 头部与重叠偏移在目标内核上实测确定；示意代码未在本机执行。

## 变体与关联

- 变体：用 `list_add_tail`/`list_del` 触发其它指针更新；用 `msg_msg` 的 `m_list`、`nft_set` 的链表把堆地址写进可读字段；用 `simple_xattr->name` 指针泄露属性名串地址（另一个已知堆地址）。
- 关联卡片：[[binary-pwn-kernel-cve-2023-5345-smbfs-fsconfig-double-free-ovl-dir-file-rop]]（本原语的实战出处，最终以伪造 ovl_dir_file/file/f_op 走 ROP）、[[binary-pwn-kernel-cve-2021-22555-msg-msg-oob-double-free-pipe-ops-rop]]（msg_msg 链表+M_TS 泄露的同类思路）。

## 检测与防御

- **缓解**：纵深防御 UAF/double free（SLAB_FREELIST_HARDENED、init_on_free、`CONFIG_DEBUG_LIST` 检测链表破坏）；限制非特权 userns 与未使用文件系统入口可减少此类原语的出现面；内核堆地址随机化（`CONFIG_RANDOMIZE_KSTACK_OFFSET` 无关，堆随机化有限）只能提高难度。
- **检测**：短时间内同文件反复创建 8KB 级 xattr 并伴随 user key 读取；xattr 链表出现不属于任何已知 name 的指针（DEBUG_LIST 报错）；重叠对象读取行为（keyctl 异常频率）可作为可疑信号。
