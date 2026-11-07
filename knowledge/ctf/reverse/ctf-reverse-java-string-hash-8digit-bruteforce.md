---
id: ctf-reverse-java-string-hash-8digit-bruteforce
title: Java String.hashCode 8 位数字授权码爆破：按 h*31+c 逐位枚举匹配 32 位目标
type: scenario
domain: ctf
path: ctf/reverse
technique: java-string-hash-8digit-bruteforce
aliases:
- Java hashCode 爆破
- 8 位授权码爆破
- h*31+c
- 固定 8 位数字枚举
- APK 授权码
tags:
- ctf
- reverse
- android
- java
- hashcode
- bruteforce
- license
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:31:16+08:00'
  notes: 已用PoC实算jhash('84572399')=-711638849，与原文目标常量一致；8位数字、零填充、32位有符号比较均与原文exp一致；无CVE、无sources/source_url；未执行目标APK。
---

## 一句话结论

如果 APK 用 Java `String.hashCode()`（`h = 31*h + c`，32 位有符号 int）校验固定 8 位数字授权码，且目标哈希可在反编译代码中读到，那么直接枚举 `00000000`–`99999999` 并比较多进程即可在可接受时间内还原授权码；案例目标 `-711638849` 对应 `84572399`。

## 原理

- Java `String.hashCode()` 的定义是 `s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]`；迭代实现为 `h = 31*h + c`，每次按 32 位 int 溢出回绕。Java 的 `int` 有符号，但溢出后的位模式与无符号 32 位一致。
- 8 位数字（含前导零）的搜索空间是 `10^8`，对现代 CPU 很小；用多进程按步长切分，通常秒级到分钟级即可命中。
- 为什么不能用逆向公式直接解：`31` 与 `2^32` 不互素，且字符集受限、有前导零约束；逐位枚举比解方程更直接。
- 关键细节：
  - 必须固定 8 位并用零填充（`f"{i:08d}"`），否则长度不同会改变哈希；
  - 目标值要按 32 位有符号比较（`h if h < 0x80000000 else h - 0x100000000`）；
  - 命中后应立即停止其它进程，避免重复输出。
- 案例反编译逻辑中的 `jhash` 与 Java `String.hashCode()` 完全一致，目标常量 `-711638849`，爆破结果 `84572399`。

## 触发条件

- 校验逻辑把用户输入的固定长度数字字符串做 `String.hashCode()`/等价循环，再与常量比较。
- 目标哈希可从反编译代码、日志、native 导出或动态 hook 获得。
- 字符集与长度已知（案例 8 位纯数字），搜索空间可暴力枚举。
- 运行环境允许并行计算（本机多进程即可，不需要设备）。

## 利用步骤

1. 反编译 APK，定位校验函数；确认是 `h = 31*h + c` 的 32 位循环，并提取目标常量。
2. 确认输入长度、字符集、是否补零、是否有前缀/后缀参与哈希。
3. 实现 `jhash(s)`，用已知测试向量验证（例如空串为 0，`"a"` 为 97）。
4. 按进程数切分 `0..10^8-1`，固定宽度格式化，比较目标值；命中后通过队列返回。
5. 将结果输入原校验函数/界面验证；若失败，检查目标常量是否被异或/取反、输入是否还有额外字符。
6. 如需更快，可用 meet-in-the-middle 或按字符集剪枝，但案例规模无需。

## PoC

```python
import multiprocessing as mp

TARGET = -711638849
PROCS = max(2, mp.cpu_count() - 1)

def to_u32(x):
    return x & 0xffffffff

def jhash(s: str) -> int:
    h = 0
    for ch in s:
        h = to_u32(h * 31 + ord(ch))
    return h if h < 0x80000000 else h - 0x100000000

def worker(start, step, outq):
    i = start
    while i < 100_000_000:
        s = f"{i:08d}"
        if jhash(s) == TARGET:
            outq.put(s)
            return
        i += step

if __name__ == "__main__":
    q = mp.Queue()
    procs = [mp.Process(target=worker, args=(i, PROCS, q)) for i in range(PROCS)]
    for p in procs:
        p.start()
    ans = q.get()
    print("[FOUND]", ans)          # 84572399
    for p in procs:
        p.terminate()
```

本卡不执行目标 APK；PoC 仅做本地哈希枚举。

## 变体与关联

- 长度/字符集变化：6 位数字、字母数字、大小写混合；搜索空间随字符集指数增长，需要剪枝或 meet-in-the-middle。
- 哈希可能被改成 64 位、加盐、异或常量、取反；先确认反编译实现，不要假设就是标准 `hashCode`。
- 可能有多个校验分支/诱饵；用动态 hook 确认最终比较值。
- 关联：[[ctf-reverse-per-char-salted-md5-bruteforce-decoy-path]]（哈希爆破与诱饵）、[[ctf-reverse-fnv1a-jumptable-base131-hash]]（非标准哈希逆推）、[[mobile-android-frida-local-http-uri-check-recover]]（同一 APK 的第二阶段入口）。
- 边界：若目标哈希是 64 位强哈希或带随机盐，暴力枚举不可行；若输入长度未知，需要先确定长度。

## 检测与防御

- 开发侧：不要用 `String.hashCode()` 等非密码学校验做授权码；使用 HMAC/签名并绑定设备与服务端。
- 加固侧：把校验放到 native/服务端，避免常量直接暴露；对爆破做速率限制。
- 检测：监控高频本地校验、异常多进程 CPU 占用；分析 APK 中的 `31` 乘法循环与固定哈希常量。
- 取证/分析：记录目标常量、字符集与长度，保留爆破脚本与结果以便复现。
