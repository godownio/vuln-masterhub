---
id: defense-forensics-core-dump-secret-extraction
title: Core dump 敏感信息提取：strings、字节搜索、ELF LOAD 映射与高熵扫描
type: scenario
domain: defense
path: defense/forensics
technique: core-dump-secret-extraction
aliases:
- core 文件密钥提取
- coredump 凭据泄露
- core dump 密码/私钥
- strings core 文件
- ELF LOAD 段虚拟地址转文件偏移
- 高熵密钥扫描
- coredumpctl 分析
tags:
- forensics
- core-dump
- credential-access
- elf
- strings
- high-entropy
- linux
- gdb
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:38:28+08:00'
  notes: 已对照原文与19张图核对：core_pattern/ulimit、strings 双份连接串、0x4060 AES 密钥、GDB 按符号读取、readelf 25 个 PHDR 与 LOAD 映射、core_scanner 3 条文本命中、MADV_DONTDUMP 后仅 2 次命中均与原文一致。未验证点：PoC 未本机复跑；原文 'strings -A2' 参数写法存疑（GNU strings 无 -A2），卡片沿用，属小瑕疵；frontmatter 未含 sources/source_url（符合 kb 约束）。
---

## 一句话结论

core dump 是进程崩溃瞬间的完整内存快照，谁拿到这个文件，谁就能用 `strings`、已知字节搜索、带符号的 GDB 或高熵扫描把进程里出现过的 AES 密钥、数据库连接串（含明文密码）、RSA 私钥、API Key、Token 原样提取出来；这不是“攻破服务器”才能做到的事，而是 core 文件落在 `/var/lib/systemd/coredump`、`/tmp`、NFS 或容器持久化卷且权限过宽时，一个普通文件读取权限就能完成的凭据窃取。

## 原理

- 进程收到致命信号（如空指针解引用触发 SIGSEGV）后，内核按 `kernel.core_pattern` 生成 core 文件；若 `ulimit -c unlimited` 或由 `systemd-coredump` 接管，整个进程地址空间会被写入：堆、栈、mmap 区（匿名映射、共享库）、可写数据段等。程序在内存里出现过的明文秘密都会留在里面，不加密、不脱敏。
- core 文件本身是 ELF 文件：一个 `NOTE` 段保存崩溃时的寄存器、信号和 auxv 等元数据，其余是若干 `LOAD` 段。每个 `LOAD` 段记录 `Offset`（在 core 文件中的偏移）、`VirtAddr`（进程虚拟地址）、`FileSiz`（实际写入字节数）和 `Flags`（R/W/X）。部分只读代码段的 `FileSiz` 可能为 0，内核为节省空间不 dump。
- 虚拟地址到文件偏移的换算：找到包含目标 `VirtAddr` 的 `LOAD` 段，`file_offset = p_offset + (vaddr - p_vaddr)`。例如 `.data` 段文件偏移 0x4000、虚拟基址 0x...1000，全局数组在虚拟地址基址 +0x60，则 core 文件偏移为 0x4060。
- 秘密的常见落点：
  - `.rodata`：`const char *` 字符串字面量，如数据库连接串、PEM 私钥文本；
  - `.data`：全局非 const 数组，如 AES-256 密钥；
  - 堆：`strdup()`/`malloc()` 的副本、ORM 连接串解析 buffer、连接池与日志组件的临时拷贝；
  - 栈/寄存器：函数局部密钥、`memcpy` 的 SIMD 临时值、`printf` 的 stdio buffer；
  - 环境变量：进程 environ 也会被 dump 进来，可能含 API Key。
- `strings` 能直接捞出可打印的文本型秘密；AES 密钥等 32 字节原始二进制不是可打印字符，需要按已知字节序列搜索。有 `-g` 符号时 GDB 可直接按变量名读取；strip 后仍可在 RW `LOAD` 段中搜字节或扫描高熵块。
- 高熵扫描：随机密钥的字节分布接近均匀，32 字节块的 Shannon 熵接近 8 bit；对每个 32 字节块计算熵并设阈值（如 7.2），可定位疑似密钥/加密数据。误报较多，需要结合上下文筛选。
- 同一秘密可能出现多次：字符串字面量一份、`strdup` 堆副本一份、格式化输出缓冲一份；实际业务里 ORM、连接池、日志、序列化 buffer 都可能复制，核心文件里可能有五六份，清零一处并不够。

## 触发条件

- 攻击者/分析人员能读取 core 文件：同用户或同组权限、目录权限 644/755、NFS/共享存储、容器持久化卷、CI 构建产物、备份系统等。
- 目标进程在崩溃前内存中持有敏感数据（密钥、连接串、Token、私钥），且 core 生成未禁用。
- 生成 core 需要 `ulimit -c` 非 0，或 systemd-coredump 启用；`kernel.core_pattern` 决定落盘位置。
- 已知密钥搜索需要事先拿到密钥的 hex；未知密钥则依赖高熵扫描和上下文判断。
- 有未 strip 的二进制和调试符号时，GDB 按变量名取值最直接；release/strip 场景改用字节搜索和 LOAD 段遍历。

## 利用步骤

1. 定位 core 文件：`cat /proc/sys/kernel/core_pattern` 看落盘路径；`coredumpctl list` 列出 systemd 保存的记录；`coredumpctl dump -o /tmp/latest_core` 导出；检查 `/var/lib/systemd/coredump`、`/tmp`、应用目录、容器持久化卷和 NFS 共享。
2. 确认文件类型和段布局：`file core.*`、`readelf -l core.*`，记录各 `LOAD` 段的 `Offset/VirtAddr/FileSiz/Flags`。
3. 文本型秘密：`strings core.* | grep -Ei 'password|passwd|secret|key|token|BEGIN|postgresql|mysql|mongodb|redis|AKIA'`；PEM 用 `strings -A2` 或 `strings -n 8` 保留多行上下文。
4. 已知二进制密钥：用 Python 直接 `data.find(bytes.fromhex(...))` 搜偏移；用 `od -A x -t x1z -j <offset> -N 64 core.*` 查看上下文，确认 32 字节完整匹配。
5. 有符号时用 GDB 批量读取：`gdb -batch -q -ex 'x/32xb aes_key' -ex 'p (char*)db_conn' ./secret_holder core.*`；`bt` 可定位崩溃点与相关对象。
6. 无符号时遍历所有 `RW` LOAD 段，按虚拟地址换算文件偏移后 dump，再对 dump 做字符串/字节/熵扫描；也可直接对全文件做 32 字节块熵扫描。
7. 用自动化脚本合并三种模式（文本正则、已知密钥、高熵块），把命中偏移与上下文导出，人工筛选误报。
8. 拿到数据库密码/API Key/私钥后，按授权范围验证影响（连接数据库、调用云 API、解密流量），并记录泄露路径与文件权限作为证据。

## PoC

```bash
# 1) 让系统在当前目录生成 core（实验环境）
ulimit -c unlimited
sudo sysctl -w kernel.core_pattern=./core.%p

# 2) 编译带符号、不优化的靶程序并触发崩溃
gcc -g -O0 -o secret_holder secret_holder.c
./secret_holder
ls -lh core.*

# 3) 文本型秘密
strings core.* | grep -E "S3cret|BEGIN|postgresql"

# 4) 已知 AES 密钥的字节搜索
python3 -c "
data=open('core.183946','rb').read()
key=bytes.fromhex('DEADBEEFCAFEBABE0123456789ABCDEFFEDCBA98765432101122334455667788')
i=data.find(key)
print('AES key at file offset 0x%08x' % i)
"

# 5) 查看上下文
od -A x -t x1z -j 0x4050 -N 64 core.*

# 6) 有符号时用 GDB 按变量名读
gdb -batch -q -ex "x/32xb aes_key" -ex "p (char*)db_conn" ./secret_holder core.*
```

```python
#!/usr/bin/env python3
# core_scanner.py：文本正则 + 已知密钥 + 高熵块（简化版）
import sys, re, math

def entropy(b):
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)

def scan_text(data):
    pats = [
        (rb'-----BEGIN [A-Z ]+-----', 'PEM 头'),
        (rb'(?:postgresql|mysql|mongodb|redis)://[^\s\x00]+', '数据库连接串'),
        (rb'(?:password|passwd|secret|api_key|token)\s*[=:]\s*\S+', '敏感键值'),
        (rb'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    ]
    for p, desc in pats:
        for m in re.finditer(p, data, re.I):
            print('0x%08x | %s | %s' % (m.start(), desc, m.group()[:120]))

def scan_known(data, key_hex):
    key = bytes.fromhex(key_hex.replace(' ', ''))
    hits, i = [], 0
    while True:
        i = data.find(key, i)
        if i < 0:
            break
        hits.append(i)
        i += 1
    print('已知密钥命中:', [hex(x) for x in hits])

def scan_entropy(data, bs=32, th=7.2):
    for i in range(0, len(data) - bs, bs):
        b = data[i:i + bs]
        e = entropy(b)
        if e >= th:
            print('0x%08x | entropy %.2f | %s' % (i, e, b.hex()))

if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    print('[*] %d bytes' % len(data))
    scan_text(data)
    if len(sys.argv) > 2:
        scan_known(data, sys.argv[2])
    scan_entropy(data)
```

```text
# 实测结果（带符号、-O0）：
# 文本命中：0x3048 PEM 头、0x3008 数据库连接串（.rodata）、0x5310 数据库连接串（堆 strdup 副本）
# 已知密钥：0x4060（.data 段，aes_key 全局数组）
```

## 变体与关联

- **变体：未知密钥**：先遍历所有 `RW` LOAD 段，按 32/16 字节块做熵扫描；再结合上下文（TLS/密码库结构、base64/PEM 邻近数据）筛选。
- **变体：strip 二进制**：没有符号时用 `readelf -l` 的 `LOAD` 映射 + 字节/熵扫描；也可用 `strings -el` 找 UTF-16 字符串。
- **变体：systemd-coredump**：core 可能是压缩格式，先 `coredumpctl dump -o out` 导出；`coredumpctl list/info` 可看进程、UID、信号与大小。
- **变体：容器/K8s**：core 可能落在宿主机 `/var/lib/systemd/coredump`、容器可写层或持久化卷；Pod 共享宿主机目录时影响面更大。
- **变体：其他平台的转储**：Windows minidump 可参考 [[pentest-ad-lsass-minidump-pypykatz-offline]]（LSASS 凭据提取），Java heap dump 可参考 [[web-java-framework-spring-actuator-heapdump-credential-leak]]；方法都是“内存快照里找明文秘密”，只是容器格式不同。
- **关联卡片**：[[crypto-implementation-madv-dontdump-mlock-key-pages]]（从 core/swap 中排除密钥页）、[[crypto-implementation-memset-dead-store-elimination-key-wipe]]（安全清零被编译器优化掉）、[[defense-forensics-proc-environ-startup-view-split]]（环境变量中的秘密）。
- **边界**：core 未生成、被 systemd 丢弃、被压缩且无权限导出、或密钥在崩溃前已被可靠清零/排除时，提取会失败；高熵扫描对压缩/加密的正常数据误报很高。

## 检测与防御

- **权限与存储**：core 文件目录 `0700`、属主 root；不要放在 NFS/Slack/共享目录；`systemd-coredump` 设置 `Storage=none` 或 `ProcessSizeMax=0` 禁止落盘；`kernel.core_pattern=|/bin/false` 可全局禁用 core。
- **生命周期**：定期清理、限制保留天数（`MaxUse`），分析完立即删除；传输 core 走加密通道；对 core 文件访问做审计（谁读、何时读）。
- **密钥内存**：敏感数据用 `mmap` + `mlock` + `MADV_DONTDUMP` 专用页，释放时 `explicit_bzero`；进程级可用 `prctl(PR_SET_DUMPABLE, 0)` 禁止 core/ptrace；使用 libsodium `sodium_malloc` 等封装。
- **减少副本**：避免 `strdup`/日志/ORM 无意复制秘密；统一密钥生命周期管理，使用 KMS/短期凭据；发现 core 泄露后立即轮换数据库密码、API Key、私钥。
- **检测**：监控 core 文件创建与大文件落盘、异常 `strings`/GDB/`coredumpctl` 访问、共享目录中的 core 文件；对生产环境开启 coredump 白名单/告警；容器安全策略禁止挂载宿主 coredump 目录。
