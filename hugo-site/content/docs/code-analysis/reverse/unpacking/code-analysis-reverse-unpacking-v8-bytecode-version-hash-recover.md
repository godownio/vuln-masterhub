---
id: code-analysis-reverse-unpacking-v8-bytecode-version-hash-recover
title: 从 V8 code cache 头部版本哈希反推引擎版本：base::hash_combine(major,minor,build,patch) 小空间爆破
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: v8-bytecode-version-hash-recover
tags:
- v8
- bytenode
- code-cache
- reverse
- hash
- unpacking
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:52:49+08:00'
  notes: 已对照原文核对：SerializedCodeData 头偏移与 Version::Hash=base::hash_combine 折叠式、0xC6A4A7935BD1E995 与 0xCC9E2D51/0x1B873593 双路径、爆破区间与 10.4.132.24 样本均与原文一致；额外用原文折叠式独立复算得到 2165973740(0x811A22EC)，并在 20x20x500x100 空间内唯一命中 10.4.132.24，自校验向量成立。未验证点：32 位折叠分支未单独跑通。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-v8-bytecode-version-hash-recover/
draft: false
kb_aliases:
- V8 版本哈希
- Version::Hash
- 4 字节版本哈希爆破
- code cache 版本反推
- 0xC6A4A7935BD1E995 哈希
- 10.4.132.24
---

## 一句话结论

`SerializedCodeData` 头部偏移 0x04 的 4 字节是 `Version::Hash()`，它不存明文版本号而是 `base::hash_combine(major, minor, build, patch)` 的结果；因为 major/minor 极小、build/patch 有限，按该哈希的展开式写出等价实现后四层循环爆破（20×20×500×100 级别）即可在秒级内把 `<major>.<minor>.<build>.<patch>` 逆推出来，从而知道该拉哪个 V8 tag 才能反汇编这份字节码。

## 原理

- `SerializedCodeData::SerializedCodeData` 依次写入：魔数（0x00）、`kVersionHashOffset`（0x04）、`kSourceHashOffset`、`kFlagHashOffset`、只读快照校验和、payload 长度、checksum；所以拿到 code cache 后，`hexdump` 的第 5–8 字节就是版本哈希。
- V8 里 `Version::Hash()` = `base::hash_combine(major_, minor_, build_, patch_)`，而 `hash_combine` 是 MurmurHash 风格的折叠：
  - 64 位路径：`m = 0xC6A4A7935BD1E995`，`hash *= m; hash ^= hash >> 47; hash *= m;`，再 `seed ^= hash; seed *= m;`
  - 32 位路径：`c1 = 0xCC9E2D51, c2 = 0x1B873593`，`hash *= c1; RotateRight32(hash,15); hash *= c2;`，再 `seed ^= hash; RotateRight32(seed,13); seed = seed*5 + 0xE6546B64`
  - 每个值先经 `hash_value(T)`（对小整数是一段 32 位的乘法/移位混合）再参与折叠。
- 折叠顺序是嵌套调用展开的结果：最外层是 `major`，因此实际写入是 `patch → build → minor → major` 依次折叠，最后 `seed` 截低 32 位即头部那 4 字节。
- 为什么可爆破：版本号四段都是小范围整数，Electron/Node 常见的 V8 版本落在 major 6–15、minor 0–19、build 0–500、patch 0–100；总量约 2×10^7 次折叠，纯 CPU 几秒到几十秒。原文以 `10.4.132.24` 实测（对应哈希 `2165973740` / `0x811A22EC`），可作为自校验向量。
- 为什么必须先对齐版本：code cache 反序列化会校验魔数与版本哈希，不匹配就 `Deserializing failed` 并抛异常；只有拿到同 tag 的 V8 才能正确反汇编指令与常量池。
- 替代路径：Electron/CEF 应用可直接从 `electron.exe`/`chrome.dll` 的文件版本或字符串表读 `Chrome/V8` 版本；Node 应用看 `process.versions.v8`。哈希爆破是无版本信息时的通用兜底。

## 触发条件

- 已提取到至少一份 V8 code cache（`.jsc`），且其头部魔数为 `?? ?? DE C0`。
- 目标 V8 为 64 位构建（现代 Electron/Node 默认），即走 `m = 0xC6A4A7935BD1E995` 那条路径；若目标是 32 位构建需改用 32 位折叠式。
- 已知或可估计版本范围（Electron 发布年代、客户端体积、`chrome` 版本字符串）。
- 允许运行本地脚本做离线爆破（不涉及目标交互）。

## 利用步骤

1. `xxd`/hex 打开 `.jsc`，确认偏移 0x00 为 `?? ?? DE C0`，读偏移 0x04 的 4 字节小端整数作为目标哈希（原文样本为 `EC 22 1A 81` = `0x811A22EC`）。
2. 按 64 位折叠式实现 `hashValue(v)`（32 位混合）与 `hashCombine64(seed, v)`，注意每一步都做 32/64 位截断。
3. 按 `patch → build → minor → major` 顺序折叠，结果取低 32 位。
4. 四层循环遍历候选区间（如 major 0–19、minor 0–19、build 0–499、patch 0–99），命中即打印并停。
5. 用已知向量自检（例如 `10.4.132.24 → 2165973740`），确认实现正确后再对目标哈希跑。
6. 拿到版本后 `git checkout refs/tags/<major>.<minor>.<build>.<patch>` 拉对应 V8 源码，用于编译反汇编器。

## PoC

```python
# 等价于 V8 base::hash_combine(Version::Hash()) 的 64 位折叠；先自检再用目标哈希爆破
M64 = 0xC6A4A7935BD1E995

def hash_value(v):            # hash_value(unsigned)：32 位混合
    v &= 0xFFFFFFFF
    v = ((v << 15) - v - 1) & 0xFFFFFFFF
    v = (v ^ (v >> 12)) & 0xFFFFFFFF
    v = (v + (v << 2)) & 0xFFFFFFFF
    v = (v ^ (v >> 4)) & 0xFFFFFFFF
    v = (v * 2057) & 0xFFFFFFFF
    v = (v ^ (v >> 16)) & 0xFFFFFFFF
    return v

def hash_combine64(seed, value):
    value = (value * M64) & 0xFFFFFFFFFFFFFFFF
    value ^= value >> 47
    value = (value * M64) & 0xFFFFFFFFFFFFFFFF
    seed = (seed ^ value) & 0xFFFFFFFFFFFFFFFF
    seed = (seed * M64) & 0xFFFFFFFFFFFFFFFF
    return seed

def version_hash(major, minor, build, patch):
    seed = 0
    for v in (patch, build, minor, major):     # 嵌套展开顺序
        seed = hash_combine64(seed, hash_value(v))
    return seed & 0xFFFFFFFF

assert version_hash(10, 4, 132, 24) == 2165973740      # 原文样本自校验

target = 0x811A22EC
for major in range(0, 20):
    for minor in range(0, 20):
        for build in range(0, 500):
            for patch in range(0, 100):
                if version_hash(major, minor, build, patch) == target:
                    print(major, minor, build, patch)   # => 10 4 132 24
                    raise SystemExit
```

## 变体与关联

- 变体：32 位构建改走 `0xCC9E2D51/0x1B873593` 的 32 位折叠式；原文 Go 代码里两套实现都给了，注意别混用。
- 变体：无需爆破——直接从 Electron 主程序文件版本/字符串、`process.versions.v8`、或 `.node` 内嵌的 `v8` 字符串读版本。
- 变体：若只需跑起来而不在乎准确版本，可改 V8 源码把魔数/版本校验改成直接返回成功（见关联卡），代价是常量池/寄存器解释可能出错。
- 关联：[[code-analysis-reverse-unpacking-v8-bytecodeinfo-embedded-code-cache-extract]]（字节码从哪来）、[[code-analysis-reverse-unpacking-v8-code-cache-disassembler-patch]]（拿到版本后编译反汇编器）。
- 边界：目标用自定义/魔改 V8（改了 Hash 或 Flags）时哈希对不上任何官方版本；哈希有 32 位碰撞可能，需用第二份 `.jsc` 的 source hash 或二进制里的版本字符串复核。

## 检测与防御

- 检测（分析方）：`.jsc` 头部 `?? ?? DE C0` 后 4 字节既非 0 又不匹配任何已知版本哈希，说明是魔改引擎或字节码被二次处理。
- 防御（开发方）：版本哈希只是完整性校验不是保护，任何人拿到字节码都能逆推版本并反汇编；不要把它当安全边界。
- 加固：若真要阻止反汇编，需改 Hash 实现并同时改二进制内的 ExternalReferenceTable 布局（使魔数也对不上），但依然可被 patch 引擎绕过。
