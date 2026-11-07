---
id: code-analysis-reverse-anti-debug-ldpreload-memcmp-hook-differential-transform
title: TracerPid 反调试下 LD_PRELOAD 钩 memcmp + 差分输入恢复魔改 RC4/仿射校验
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: ldpreload-memcmp-hook-differential-check-recovery
tags:
- reverse
- anti-debug
- ld-preload
- memcmp
- hook
- differential-analysis
- rc4
- affine
- linux
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:16:56+08:00'
  notes: 已对照原文核对：TracerPid 反调试、LD_PRELOAD 钩 memcmp 记录两侧实参、魔改 RC4 反馈与仿射 7x+11、全同字符差分恢复 M[i]=C[i]⊕(Y_A[i]⊕A)，与原文 PoC/flag 一致。未验证点：未本机复跑目标 ELF；卡内 PoC 为示意简化；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-ldpreload-memcmp-hook-differential-transform/
draft: false
kb_aliases:
- LD_PRELOAD 钩 memcmp
- memcmp 实参记录
- 差分输入恢复校验
- 无法调试的二进制逆向
- TracerPid 反调试绕过
- 魔改 RC4 反馈模式
- 仿射变换逆映射
---

## 一句话结论

目标 ELF 通过读取 `/proc/self/status` 的 `TracerPid` 拒绝调试器，但它最终仍要用 `memcmp(用户输出, 常量密文, n)` 做校验；用 `LD_PRELOAD` 在 `__attribute__((constructor))` 中钩住 `memcmp` 把两侧实参落盘，再用“全同一字符”的输入做差分，即可在不调试的情况下还原出被校验变换的密钥流，逆向仿射映射后逐位恢复明文。

## 原理

- **反调试点**：程序启动后读取 `/proc/self/status`，在 `TracerPid:` 不为 0 时改变行为或退出；调试器 attach 后该字段非零，因此断点/单步不可用。反调试只阻止“调试”，不能阻止进程按正常方式加载 `LD_PRELOAD` 指定的共享库。
- **钩子时机**：`LD_PRELOAD` 库的 `__attribute__((constructor))` 在 `main` 之前执行，可以 `dlsym(RTLD_NEXT, "memcmp")` 取到真实函数并替换符号；之后程序每次比较都会进入自定义 `memcmp`。
- **采集两侧实参**：自定义 `memcmp(a, b, n)` 在调用真实函数前把 `n`、`a`、`b` 写入日志（附长度过滤，忽略噪声）。这样即使不能下断点，也能看到“程序算出的值”和“期望常量”两段数据。
- **区分常量侧与动态侧**：用两种不同输入各跑一次；两次运行中保持不变的一侧是程序中硬编码的期望密文 `C`，随输入变化的一侧是本次输出 `Y`。
- **差分恢复密钥流**：设加密关系为 `Y[i] = M[i] ⊕ KS[i] ⊕ prev(i)`，其中 `M=F(plain)` 是逐字符仿射变换（如 `F(c)=7(c-base)+11 mod m + base`，数字 m=10、字母 m=26），`prev(0)=S[0]`、`prev(i+1)=Y[i]` 是反馈项。若把输入全部填成同一字符 `ch`，则 `M[i]` 恒为 `A=F(ch)`，于是 `KS[i]⊕prev(i)=Y_A[i]⊕A`。因为期望常量满足 `C[i]=M_target[i]⊕KS[i]⊕prev(i)`，可得 `M_target[i]=C[i]⊕(Y_A[i]⊕A)`。
- **还原真实字符**：对 `M_target[i]` 施加仿射逆映射 `F^{-1}` 得到明文位。由于反馈项 `prev` 依赖前一位的输出，逐位恢复时要把已确认的前缀写回输入缓冲再重新运行，使反馈与真实明文一致，逐位推进直到全部恢复。
- **为什么可行**：反调试保护的是执行流，而校验结果必然以数据形式出现在 `memcmp` 参数中；`LD_PRELOAD` 在动态链接层介入，绕开了 ptrace 检测。差分法把“未知的密钥流+反馈”消去，只剩常量与仿射逆映射。

## 触发条件

- Linux ELF，使用 glibc 动态链接，`memcmp`（或 `strcmp`/`strncmp`）未被内联/静态链接。
- 程序通过 `TracerPid`、`ptrace` 等反调试手段阻止常规调试，但仍以“输入变换后与常量比较”的方式校验。
- 校验变换对每个字符是确定的、与位置相关的流式变换（异或密钥流、RC4 变体、反馈链等），且对输入字符存在可逆的逐字符映射。
- 允许设置 `LD_PRELOAD` 环境变量（未 setuid，或未对 `LD_PRELOAD` 做过滤）。
- 可反复运行目标程序并观察其对同一校验点的输出。

## 利用步骤

1. 运行 `checksec`/`file` 确认架构与动态链接；用 `strings`、`strace` 观察是否读取 `/proc/self/status`、是否出现 `TracerPid:`、`ptrace` 等字符串。
2. 在反汇编中定位最终比较调用（`memcmp`/`strcmp`）及其长度；确认比较的一侧是常量缓冲区。
3. 编译 `LD_PRELOAD` 钩子库：构造函数中 `dlsym` 真实 `memcmp`，自定义实现把 `n` 和两侧字节写入固定文件，再调用真实函数。
4. 用两种不同输入各运行一次（如全 `Z` 与全 `Y`），解析日志中长度最大的记录，比较两次结果，保持不变的一侧记为 `C`，变化的一侧记为本次 `Y`。
5. 计算 `M_target[i]=C[i]⊕Y[i]⊕F(ch)`；对 `M_target[i]` 做仿射逆映射 `F^{-1}` 得到真实字符。
6. 把已恢复的前缀写回输入缓冲，重新运行取新的 `Y`，逐位重复步骤 5，直到整串恢复；最后用恢复出的明文重新运行，确认程序提示成功。
7. 若钩子被静态链接/内联绕过，可改为 hook `strlen`、`write`、`puts` 或比较前后的库函数，或在 `memcmp` 的调用点做指令级 patch。

## PoC

```c
// hook.c —— LD_PRELOAD 记录 memcmp 两侧实参
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

static int (*real_memcmp)(const void *, const void *, size_t);
static int fd = -1;

__attribute__((constructor)) static void init_hook(void) {
    real_memcmp = dlsym(RTLD_NEXT, "memcmp");
    fd = open("/dev/shm/mc.bin", O_CREAT | O_WRONLY | O_TRUNC, 0644);
}
__attribute__((destructor)) static void fini_hook(void) { if (fd >= 0) close(fd); }

int memcmp(const void *a, const void *b, size_t n) {
    if (!real_memcmp) real_memcmp = dlsym(RTLD_NEXT, "memcmp");
    if (n >= 16 && n <= 256) {              // 只记录校验长度的比较
        uint8_t tag = 0xAB; uint32_t len = (uint32_t)n;
        write(fd, &tag, 1); write(fd, &len, 4);
        write(fd, a, n); write(fd, b, n);
    }
    return real_memcmp(a, b, n);
}
```

```python
# solve.py —— 差分恢复 + 仿射逆映射（示意）
import struct, subprocess, os

def run_once(exe, hook, inp):
    try: os.remove("/dev/shm/mc.bin")
    except FileNotFoundError: pass
    env = dict(os.environ, LD_PRELOAD=hook)
    subprocess.run([exe], input=inp, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=3, env=env)
    data = open("/dev/shm/mc.bin", "rb").read()
    best, i = (0, None, None), 0
    while i < len(data) and data[i] == 0xAB:
        i += 1
        n = struct.unpack("<I", data[i:i+4])[0]; i += 4
        a, b = data[i:i+n], data[i+n:i+2*n]; i += 2*n
        if n > best[0]: best = (n, a, b)
    return best

def affine(x):                              # F(c)=7(c-base)+11 mod m + base
    if 48 <= x <= 57:  return (7*(x-48)+11) % 10 + 48
    if 65 <= x <= 90:  return (7*(x-65)+11) % 26 + 65
    if 97 <= x <= 122: return (7*(x-97)+11) % 26 + 97
    return x

def inv_affine(x):
    inv7 = {10: 3, 26: 15}                  # 7^-1 mod 10 / mod 26
    if 48 <= x <= 57:  return (inv7[10]*((x-48)-11)) % 10 + 48
    if 65 <= x <= 90:  return (inv7[26]*((x-65)-11)) % 26 + 65
    if 97 <= x <= 122: return (inv7[26]*((x-97)-11)) % 26 + 97
    return x

def pick_const(r1, r2):
    # 两次运行中不变的一侧是常量 C；变化的一侧是 Y
    if r1[1] == r2[1] and r1[2] != r2[2]: return r1[1], r1[2]
    if r1[2] == r2[2] and r1[1] != r2[1]: return r1[2], r1[1]
    raise RuntimeError("cannot identify constant side")

N = 25
ch = ord('Z'); A = affine(ch)
n1, a1, b1 = run_once("./target", "./hook.so", bytes([ch])*N + b"\n")
n2, a2, b2 = run_once("./target", "./hook.so", bytes([ch-1])*N + b"\n")
C, _ = pick_const((n1,a1,b1), (n2,a2,b2))

plain = bytearray()
for i in range(N):
    guess = bytes(plain) + bytes([ch])*(N-len(plain)) + b"\n"
    _, y1, y2 = run_once("./target", "./hook.so", guess)
    Y = y1 if y1 != C else y2
    plain.append(inv_affine(C[i] ^ Y[i] ^ A))
print(plain.decode())
```

```text
说明：实际题目中的最后一轮比较长度可能不同，需按日志中最大 n 调整；若仿射参数不同，按反汇编得到的 (a,b,m) 替换。
```

## 变体与关联

- 变体：比较函数换成 `strcmp`/`strncmp`/`bcmp` 或自写逐字节循环；可 hook 对应 libc 符号，或用 `LD_AUDIT`、`frida`/`ptrace` patch 反调试分支。
- 变体：流密码不是 RC4，而是 AES-CTR/自研 LFSR/滚动异或；差分思路不变——只要“同一输入的输出”与“常量”可观测，就能消去密钥流。
- 变体：仿射映射可能作用于不同字符集（大小写分开、十六进制、自定义表），逆映射按实际模数计算；也可用已知明文前缀直接求映射。
- 关联：[[ctf-reverse-miniprogram-variant-rc4-reverse-ksa]]（魔改 RC4 的静态还原）、[[code-analysis-reverse-windows-iat-hook-lstrcmp-xxtea]]（Windows IAT Hook 替换比较函数）、[[code-analysis-reverse-anti-debug-linux-sandbox-environment-probes]]（Linux TracerPid/LD_PRELOAD 检测手法）。

## 检测与防御

- 防御：不要仅依赖客户端二进制校验；校验逻辑放服务端，或使用远程证明/签名。
- 防御：校验前对关键常量加密/分片，避免以明文常量出现在 `memcmp` 参数中；对 `LD_PRELOAD` 做完整性检查（setuid 程序本身会忽略该变量）。
- 检测：进程环境中出现异常的 `LD_PRELOAD`；`memcmp`/`strcmp` 被非 libc 地址替换（`/proc/<pid>/maps` 中库路径异常）；进程频繁重启且输入高度相似。
- 检测（逆向视角）：`/proc/self/status` 读取、`ptrace` 调用、`TracerPid` 字符串是反调试信号；最终比较点通常是最接近成功提示的分支。
