---
id: crypto-implementation-madv-dontdump-mlock-key-pages
title: MADV_DONTDUMP + mlock + PR_SET_DUMPABLE：把密钥页从 core 与 swap 泄露面移除
type: scenario
domain: crypto
path: crypto/implementation
technique: madv-dontdump-mlock-key-pages
tags:
- key-management
- core-dump
- madvise
- mlock
- prctl
- memory-safety
- linux
- libsodium
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:38:32+08:00'
  notes: 已对照原文与19张图核对：mmap+mlock+MADV_DONTDUMP 代码、崩溃后密钥仅 0x4060/0x5720 两次命中（DONTDUMP 页缺失）、secure_alloc/secure_free 顺序、PR_SET_DUMPABLE 与 libsodium 说明均与原文一致；Linux 3.4 引入 MADV_DONTDUMP 正确。未验证点：PoC 未本机复跑；卡片补充的 MADV_WIPEONFORK/mlock2 为原文外延伸知识，属通用事实；frontmatter 未含 sources/source_url。
url: /docs/crypto/implementation/crypto-implementation-madv-dontdump-mlock-key-pages/
draft: false
kb_aliases:
- MADV_DONTDUMP
- core dump 排除密钥页
- mlock 防 swap
- PR_SET_DUMPABLE
- 密钥页保护
- libsodium sodium_malloc
- secure_alloc
---

## 一句话结论

`madvise(addr, len, MADV_DONTDUMP)` 会告诉内核在生成 core 文件时跳过指定页，配合 `mlock()` 防止密钥被换出到 swap、释放时 `explicit_bzero()` 清零，以及在进程级调用 `prctl(PR_SET_DUMPABLE, 0)`，可以把密钥从 core/swap 这两个磁盘泄露面移除；原文用同一份密钥分别放在 DONTDUMP 的 mmap 页和普通 malloc 堆，崩溃后 core 中只找到全局数组与堆副本共 2 次，DONTDUMP 页那份没有出现。

## 原理

- **core dump 的写入范围**：进程崩溃时内核把整个地址空间写入 core；Linux 3.4 引入 `MADV_DONTDUMP`，被标记的虚拟内存页在写 core 时被跳过，对应的 `LOAD` 段不包含该页内容，就像这块内存从未存在。进程运行时该页仍正常可读可写。
- **swap 的泄露面**：即使不生成 core，密钥页也可能被内核换出到 swap 分区/文件；`mlock(addr, len)` 把页锁定在物理内存，阻止换出。`mlock` 需要 `RLIMIT_MEMLOCK` 足够（root 或调高限制）。
- **释放后的残留**：`munmap` 不会清零物理页；释放前必须 `explicit_bzero`（见关联卡片），否则页被重新分配后仍可能被读到。
- **进程级开关**：`prctl(PR_SET_DUMPABLE, 0)` 让进程变为 non-dumpable，禁止生成 core，并限制非 root 的 `ptrace` 与部分 `/proc/<pid>` 访问；副作用是调试/崩溃分析也会受限，适合生产进程。
- **libsodium 封装**：`sodium_malloc(size)` 内部使用 guard page + `mlock` + `MADV_DONTDUMP`，`sodium_free()` 负责清零、解锁、解除映射；自己实现时至少要覆盖 `mmap`/`mlock`/`madvise`/`explicit_bzero`/`munlock`/`munmap` 六步。
- **页粒度与边界**：`MADV_DONTDUMP` 以页为单位，密钥必须放在独立页（或整页都标记），否则会把同页其他数据一起排除；它只影响 core，不影响日志、堆副本、全局源数组、stdio 缓冲等其他泄露面。
- 原文验证：同一份密钥放在 `mmap` 后标记 `MADV_DONTDUMP` 的页，以及普通 `malloc` 堆；崩溃后 core 中密钥出现 2 次（全局 `key_source` 在 `.data`、`heap_key` 在普通堆），DONTDUMP 页那份不出现，证明内核按页跳过了它。

## 触发条件

- Linux 内核 >= 3.4（`MADV_DONTDUMP` 引入版本）；有 `mmap`/`madvise`/`mlock` 权限。
- 密钥能放在独立的 mmap 页中，而不是散落在普通堆/全局变量；否则需要改造分配方式。
- `mlock` 需要足够的 `RLIMIT_MEMLOCK`（root 或 `ulimit -l` 调整）；容器内可能受 seccomp/capability 限制。
- 进程可能崩溃并生成 core，或存在 swap；若 core 已被全局禁用、swap 关闭，收益会降低，但仍可防其他转储机制。
- `prctl(PR_SET_DUMPABLE, 0)` 会影响 `ptrace` 和 `/proc` 访问，需要确认不影响监控/调试流程。

## 利用步骤

1. 计算页对齐的分配大小：`alloc_size = (size + page_size - 1) & ~(page_size - 1)`。
2. `mmap(NULL, alloc_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` 分配专用页。
3. `mlock(ptr, alloc_size)` 锁定内存，防止 swap。
4. `madvise(ptr, alloc_size, MADV_DONTDUMP)` 标记该页不进入 core。
5. 把密钥复制到该页使用；不要把同一密钥再复制到普通堆/全局/日志。
6. 释放时：`explicit_bzero(ptr, alloc_size)` → `munlock` → `munmap`；顺序不要颠倒。
7. 进程级可选：`prctl(PR_SET_DUMPABLE, 0)`，并在启动脚本/服务单元中确认 core 策略。
8. 验证：同一密钥放 DONTDUMP 页与普通 malloc 堆，触发崩溃，搜索 core；DONTDUMP 页的副本应缺失，其他副本仍可能存在，需逐一处理。

## PoC

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char key_source[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};

void process_data(void)
{
    /* A：专用页 + mlock + DONTDUMP */
    void *key_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (key_page == MAP_FAILED) { perror("mmap"); return; }
    memcpy(key_page, key_source, 32);
    mlock(key_page, 4096);
    madvise(key_page, 4096, MADV_DONTDUMP);

    unsigned char *k = key_page;
    printf("[*] DONTDUMP key: %02x%02x%02x%02x\n", k[0], k[1], k[2], k[3]);

    /* B：普通堆，做对照（会出现在 core 中） */
    unsigned char *heap_key = malloc(32);
    memcpy(heap_key, key_source, 32);
    printf("[*] Heap key (no DONTDUMP)\n");

    printf("[*] Crashing...\n");
    char *p = NULL;
    *p = 'x';
}

int main(void)
{
    process_data();
    return 0;
}
```

```bash
gcc -g -O0 -o secret_holder_madvise secret_holder_madvise.c
./secret_holder_madvise
ls -lht core.* | head -5
python3 -c "
data=open('core.196111','rb').read()
key=bytes.fromhex('DEADBEEFCAFEBABE0123456789ABCDEFFEDCBA98765432101122334455667788')
hits=[]; s=0
while True:
    i=data.find(key,s)
    if i<0: break
    hits.append(i); s=i+1
print('密钥出现 %d 次: %s' % (len(hits), [hex(x) for x in hits]))
"
# 预期 2 次：0x4060（全局 key_source）、0x5720（普通堆 heap_key）；
# DONTDUMP 的 mmap 页不出现。
```

```c
/* 生产封装：secure_alloc/secure_free */
void *secure_alloc(size_t size) {
    size_t ps = 4096;
    size_t n = (size + ps - 1) & ~(ps - 1);
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    mlock(p, n);
    madvise(p, n, MADV_DONTDUMP);
    return p;
}

void secure_free(void *p, size_t size) {
    size_t ps = 4096;
    size_t n = (size + ps - 1) & ~(ps - 1);
    explicit_bzero(p, n);
    munlock(p, n);
    munmap(p, n);
}
```

```c
/* 进程级：禁止 core + 限制 ptrace/proc（注意副作用） */
#include <sys/prctl.h>
prctl(PR_SET_DUMPABLE, 0);
```

```c
/* libsodium：自动 guard page + mlock + MADV_DONTDUMP */
#include <sodium.h>
unsigned char *key = sodium_malloc(32);
/* ... */
sodium_free(key);   /* 自动清零、解锁、解除映射 */
```

## 变体与关联

- **变体：`MADV_WIPEONFORK`**：子进程 fork 后自动清零该页，适合会 fork 的父进程，防止子进程继承密钥；与 `MADV_DONTDUMP` 可组合使用（按内核支持情况）。
- **变体：`mlock2(MLOCK_ONFAULT)`**：按需锁定，减少一次性 mlock 大页的开销；仍需要 `RLIMIT_MEMLOCK`。
- **变体：systemd-coredump 策略**：`Storage=none`、`ProcessSizeMax=0` 全局禁用 core，与页级 DONTDUMP 互补。
- **变体：Windows**：对应 `VirtualLock` 防换页、进程缓解策略/转储排除；本卡只覆盖 Linux 语义。
- **关联卡片**：[[defense-forensics-core-dump-secret-extraction]]（从 core 中提取密钥的完整方法）、[[crypto-implementation-memset-dead-store-elimination-key-wipe]]（清零被编译器优化掉）、[[defense-forensics-proc-environ-startup-view-split]]（环境变量泄露）。
- **边界**：`MADV_DONTDUMP` 只防 core，不防 `/proc/<pid>/mem`、ptrace、日志、堆副本；`mlock` 受 `RLIMIT_MEMLOCK` 限制；`PR_SET_DUMPABLE=0` 会影响调试和崩溃分析；容器/安全策略可能禁止 `mlock` 或 `madvise`。

## 检测与防御

- **验证**：在测试环境用同一密钥做 DONTDUMP 页 vs 普通堆对照，崩溃后搜索 core；确认页级保护生效，并检查是否还有其他副本（全局、堆、日志、环境变量）。
- **代码规范**：敏感密钥统一走 `secure_alloc` 或 libsodium；禁止把密钥复制到普通堆/全局/日志；释放顺序为清零 → munlock → munmap。
- **进程加固**：生产进程设置 `prctl(PR_SET_DUMPABLE, 0)`；禁用或限制 core（`kernel.core_pattern=|/bin/false`、systemd `Storage=none`）；限制 `ptrace` 与 `/proc/<pid>/mem` 访问。
- **检测**：审计 `mlock`/`madvise(MADV_DONTDUMP)` 使用情况；监控 core 文件生成与访问；对生产 core 做秘密扫描；发现 core 中出现密钥时立即轮换并排查副本。
- **注意**：页级保护不能替代密钥生命周期管理；短期凭据、KMS 托管和最小化明文驻留仍是根本措施。
