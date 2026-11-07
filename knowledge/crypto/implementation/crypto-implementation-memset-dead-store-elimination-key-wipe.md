---
id: crypto-implementation-memset-dead-store-elimination-key-wipe
title: memset 安全清零被 dead store elimination 删除：explicit_bzero、memset_s 与 volatile 函数指针
type: scenario
domain: crypto
path: crypto/implementation
technique: memset-dead-store-elimination-key-wipe
aliases:
- memset 被优化掉
- 安全清零失效
- dead store elimination
- explicit_bzero
- memset_s
- volatile 函数指针清零
- 密钥残留内存
tags:
- key-management
- zeroization
- memset
- dead-store-elimination
- compiler-optimization
- explicit-bzero
- memory-safety
- c
- linux
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:38:30+08:00'
  notes: 已对照原文与19张图核对：-O0 memset 计数 3、-O2 计数 0、-O2 反汇编 malloc/memcpy/memset 消失与 movb$0x0,0x0+ud2、explicit_bzero@plt 保留、memset_s/volatile 指针方案均与原文一致；优先级与副本残留论述准确。未验证点：PoC 未本机复跑；原文 -O2 process_data 反汇编为文中整理版本而非截图直出（图16仅 .init/.plt），卡片已标注'原文示例'；frontmatter 未含 sources/source_url。
---

## 一句话结论

用 `memset(key, 0, 32)` 擦除密钥在 `-O2` 下可能被编译器的 dead store elimination 整段删除：清零后内存再未被读取，C 标准只要求保持“可观察行为”，编译器有权删掉这次写入；结果是密钥仍留在堆/全局区，崩溃时的 core dump 或后续堆复用会把它泄露出去；应改用 `explicit_bzero()`、`memset_s()` 或 `volatile` 函数指针调用，并同时处理 `strdup`、全局源数组、日志/ORM 缓冲等其他副本。

## 原理

- 编译器优化中的 **dead store elimination**：如果一段内存被写入后，在程序可观察行为范围内再也没有被读取，这次写入就可以被删除。`memset(aes_key, 0, 32)` 只是普通内存写，C 标准没有“安全清零”语义，因此编译器可以合法优化掉它。
- 优化链条往往更激进：密钥前 4 字节被常量折叠成 `printf` 的立即数（`mov $0xde,%esi` 等），既然密钥从未真正分配到堆上，`malloc`/`memcpy`/`memset` 全部失去意义，整个分配与清零被消除；`*p = 'x'` 属于未定义行为，`-O2` 可能直接生成 `movb $0x0,0x0` + `ud2` 的崩溃序列。
- `-O0` 下能看到 `malloc`、`memcpy`、`memset` 的真实调用；`-O2` 下 `memset` 调用可能变成 0 次。这不是编译器 bug，而是标准允许的优化：可观察行为不变即可。
- 即使 `memset` 没被优化掉，密钥仍可能残留在：
  - 全局 `key_source` 数组（密钥来源，未被清零）；
  - `strdup`/`malloc` 产生的堆副本；
  - `memcpy` 使用 SIMD 时的寄存器/栈临时值；
  - `printf`/stdio 内部 buffer、日志组件、ORM/连接池的解析缓冲；
  - `free()` 不会清零，只是把块标记为可复用，密钥在被覆盖前一直在堆上。
- **可靠清零手段**：
  - `explicit_bzero(ptr, len)`：glibc 2.25+ / OpenBSD 语义，明确要求执行清零，编译器不得删除；`-O2` 下仍保留 `call explicit_bzero@plt`。
  - `memset_s(ptr, destsz, 0, len)`：C11 Annex K 定义的安全清零函数；glibc 未实现 Annex K，Linux 上通常不可用（musl 或自行实现）。
  - `volatile` 函数指针：`static volatile memset_func_t secure_memset = memset; secure_memset(p,0,n);` 编译器无法确定每次调用的目标函数，不敢优化；OpenSSL 早期版本用过类似技巧。
  - `OPENSSL_cleanse`/`sodium_memzero` 等库封装，内部同样阻止优化。
- 优先级：`explicit_bzero` > `memset_s` > volatile 函数指针 > 裸 `memset`（不可靠）。清零只是减少暴露面，不是银弹：所有副本都要处理，core/swap 还需要 `MADV_DONTDUMP`/`mlock` 等页级保护。

## 触发条件

- C/C++ 代码用 `memset`（或编译器可识别的等价循环）清零密钥/口令等敏感 buffer，且清零后不再读取该 buffer。
- 使用 `-O2`/`-O3` 等优化级别编译；不同编译器/版本可能表现不同，但 GCC/Clang 都可能做 dead store elimination。
- 目标程序崩溃并生成 core，或堆内存被复用/被其他漏洞读取时，残留密钥可被提取。
- 使用 `explicit_bzero` 需要 glibc 2.25+ 或提供该函数的 libc；`memset_s` 需要 C11 Annex K 实现；volatile 函数指针方案兼容性最好但可读性较差。
- 仅替换清零函数不够：全局源数组、`strdup` 副本、日志/ORM/stdio buffer 等仍需审计和清理。

## 利用步骤

1. 用 `-O0` 和 `-O2` 分别编译同一份处理密钥的代码，`objdump -d <binary> | grep -c memset` 对比调用次数；若 `-O2` 为 0，说明清零已被删除。
2. 反汇编 `-O2` 的关键函数，观察 `malloc`/`memcpy`/`memset` 是否消失、密钥字节是否被内联成立即数、崩溃点是否被优化成直接写空地址/`ud2`。
3. 把 `memset` 替换为 `explicit_bzero`（或对应库的安全清零函数），重新用 `-O2` 编译，确认 `explicit_bzero@plt` 的 `call` 仍在。
4. 若平台不支持 `explicit_bzero`/`memset_s`，使用 `volatile` 函数指针或 `OPENSSL_cleanse`/`sodium_memzero`。
5. 审计所有秘密副本：全局源、堆复制、连接串/ORM buffer、日志、stdio、序列化缓存；逐一清零或避免复制。
6. 在崩溃/core 场景中验证：编译带 `MADV_DONTDUMP` 的版本与普通版本，搜索 core 中的密钥，确认清零+页保护后的残留位置；不要把“清零了”当作已验证。
7. 对生产构建做回归：在 CI 中加入 `-O2` 反汇编检查或静态规则，防止后续改动把安全清零换回 `memset`。

## PoC

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>   /* explicit_bzero 在 glibc 2.25+ */

static unsigned char key_source[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};

void process_data(void)
{
    unsigned char *aes_key = malloc(32);
    memcpy(aes_key, key_source, 32);
    printf("[*] AES key loaded, first 4 bytes: %02x%02x%02x%02x\n",
           aes_key[0], aes_key[1], aes_key[2], aes_key[3]);

    /* 不可靠：-O2 下可能被 dead store elimination 删除 */
    memset(aes_key, 0, 32);

    /* 可靠：编译器不得删除 */
    /* explicit_bzero(aes_key, 32); */

    char *p = NULL;
    *p = 'x';          /* SIGSEGV，崩溃后生成 core */
}
```

```bash
gcc -g -O0 -o secret_holder_v2_o0 secret_holder_v2.c
gcc -g -O2 -o secret_holder_v2_o2 secret_holder_v2.c

objdump -d secret_holder_v2_o0 | grep -c "memset"   # 3
objdump -d secret_holder_v2_o2 | grep -c "memset"   # 0（清零被删除）
objdump -d secret_holder_v2_o2                      # 观察 malloc/memcpy/memset 消失
```

```c
/* volatile 函数指针方案：兼容性最好 */
typedef void *(*memset_func_t)(void *, int, size_t);
static volatile memset_func_t secure_memset = memset;
/* ... */
secure_memset(aes_key, 0, 32);
```

```text
# -O2 反汇编要点（原文示例）：
# 密钥前 4 字节被内联为 mov $0xde,%esi / $0xad,%edx / $0xbe,%ecx / $0xef,%r8d
# malloc/memcpy/memset 全部消失
# *p = 'x' 被优化为 movb $0x0,0x0 + ud2
```

## 变体与关联

- **变体：`memset_s`（C11 Annex K）**：语义上保证清零，但 glibc 不实现 Annex K；使用 musl 或自带实现，注意参数顺序与返回值。
- **变体：库封装**：`OPENSSL_cleanse`、`sodium_memzero`、`mbedtls_platform_zeroize` 等内部通常有编译器屏障，跨平台可优先使用。
- **变体：只清零堆但漏掉全局/副本**：`key_source`、`strdup` 连接串、日志/ORM buffer 仍可能泄露；需要全生命周期审计。
- **关联卡片**：[[crypto-implementation-madv-dontdump-mlock-key-pages]]（从 core/swap 中排除密钥页）、[[defense-forensics-core-dump-secret-extraction]]（core 中提取残留密钥）、[[crypto-implementation-gmssl-sm2-publickey-lstrip-hex-case]]（另一个密码学实现细节问题）。
- **边界**：不同编译器/优化级别、LTO、`-fno-builtin`、`-ffreestanding` 等会改变优化结果；`explicit_bzero` 在极老 libc 上不可用；volatile 函数指针可能影响性能/内联，需权衡。

## 检测与防御

- **代码规范**：禁止用裸 `memset` 清零密钥；统一封装 `secure_zero()`（内部用 `explicit_bzero`/`sodium_memzero`），并在代码评审/静态规则中检查。
- **构建验证**：对 release 构建（`-O2`）反汇编检查 `memset`/`explicit_bzero` 调用是否存在；在 CI 中加入针对密钥清零函数的检查，防止优化级别变化导致回归。
- **运行时防护**：密钥放在 `mmap` 专用页并 `mlock` + `MADV_DONTDUMP`；进程级设置 `prctl(PR_SET_DUMPABLE, 0)`；减少 `strdup` 和日志中的秘密副本。
- **检测**：core dump/内存转储中出现预期已清零的密钥，说明清零失效或存在副本；对生产 core 做秘密扫描；对异常内存读取/崩溃转储访问告警。
- **响应**：发现密钥残留后立即轮换密钥、清理 core/转储文件、审计日志与共享存储中的副本。
