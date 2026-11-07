---
id: mobile-android-shell-so-embedded-elf-carve-extract-dat
title: Android 二代壳静态脱壳：从 libshell.so 按偏移 carve 内嵌 ELF，恢复 JNI setData/ihk/test 实现
type: scenario
domain: mobile
path: mobile/android
technique: android-shell-so-embedded-elf-carve
tags:
- android
- native
- so
- unpacking
- packer
- elf
- jni
- reverse
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:10:25+08:00'
  notes: 已对照原文与图 34-42 核对：com.swdd.shell.JniBridge 声明 ihk()/setData(byte[])/test(String)（已把卡内误写的 ihl 修正为 ihk，图 34/38 可见）；ProxyApplication System.loadLibrary("shell")、assets/extract.dat、JniBridge.setData、loadDex；libshell.so 先按 0x48DC carve 头非 ELF，回退 0x48DC8 得 266.61KB ELF；setData 按 8 字节头+变长数据入红黑树并映射 0x003BEF18~0x003BF2E4。未在本地 APK 复跑 carve/IDA。
url: /docs/mobile/android/mobile-android-shell-so-embedded-elf-carve-extract-dat/
draft: false
kb_aliases:
- StrangApp
- extract.dat
- libshell.so 脱壳
- 内嵌 ELF carve
- Java_com_ 符号缺失
- 红黑树 setData
- 二代壳静态分析
---

## 一句话结论

App 的 `ProxyApplication` 静态加载 `libshell.so`，并把 `assets/extract.dat` 传给 `JniBridge.setData(byte[])`；IDA 打开 `libshell.so` 看不到 `Java_com_` 函数，是因为真正的 native 模块以 ELF 形式嵌在 stub so 内部。按 `7F 45 4C 46` 魔数（原文偏移 `0x48DC8`）从 `libshell.so` 中 carve 出内嵌 ELF，即可在 IDA/Ghidra 中恢复 `setData`、`ihk`、`test` 的真实实现。

## 原理

- **二代壳的加载结构**：`ProxyApplication` 在 `onCreate` 中 `System.loadLibrary("shell")`，然后从 assets 读 `extract.dat`，调用 `JniBridge.setData(extract.dat 的字节)`，再 `loadDex` 加载业务 dex。`JniBridge` 声明了 `ihk()`、`setData(byte[])`、`test(String)` 三个 native 方法，但 stub `libshell.so` 中可能只有壳代码，真正的 `Java_com_...` 实现被以加密/嵌套形式放在 so 内部。
- **ELF 魔数定位**：ELF64 文件以 `7F 45 4C 46`（`\x7fELF`）开头；壳把真实 so 嵌入时通常保留完整 ELF 头。用十六进制编辑器/脚本搜索该魔数，从命中偏移截取到文件末尾，得到候选文件；再用 `file`/`readelf -h` 校验 `ELF 64-bit LSB shared object, ARM aarch64`。
- **为什么 IDA 看不到 Java_com_**：stub so 的导出表可能只有壳自己的 JNI 入口，真实模块在运行时才被解密/映射；静态反编译 stub 自然看不到业务函数。Carve 出内嵌模块后，符号表/`.dynsym` 或 `JNI_OnLoad`/`RegisterNatives` 会给出真实函数。
- **`setData` 的数据结构**：恢复出的 native 代码把传入的整块二进制按“[8 字节头 + 变长数据]”切块，插入一棵按 key 索引的红黑树（key→data 字典）。后续校验/解密按 key 从树里取数据块，并映射到地址区间（原文约 `0x003BEF18 ~ 0x003BF2E4`）。理解这个结构才能把 `extract.dat` 还原成原始 native 代码/数据。
- **偏移不是唯一**：不同壳/版本的内嵌偏移会变；原文先试 `0x48DC` 得到非 ELF，再试 `0x48DC8` 才得到 ELF。可靠做法是扫描全部 `7F 45 4C 46` 命中并逐个校验 ELF 头，而不是硬编码偏移。
- **为什么这条链成立**：静态嵌入的 ELF 必须可被壳在运行时找到并映射，其头部/结构通常完整保留；ELF 头自带 `e_machine`、`e_type`、节头偏移，可用来区分真正的模块与随机字节。

## 触发条件

- APK 包含 `lib/<abi>/libshell.so`（或其他 stub so）与 `assets/extract.dat`。
- Java 层调用 `System.loadLibrary`、`JniBridge.setData(byte[])`、`loadDex` 等典型壳入口。
- stub so 中 `readelf -Ws` 找不到预期的 `Java_<pkg>_<Class>_<method>` 符号，或 IDA 反编译缺少业务逻辑。
- `libshell.so` 内部存在至少一个 `7F 45 4C 46` 命中，且 carve 后能被 `file`/`readelf` 识别为 ELF。
- 可对 `extract.dat` 与恢复出的 `setData` 逻辑做静态分析或模拟执行。

## 利用步骤

1. 解包 APK：`unzip app.apk`，定位 `lib/arm64-v8a/libshell.so`、`assets/extract.dat`，记录文件大小/哈希。
2. 检查 stub so：`file libshell.so`、`readelf -h`、`readelf -Ws libshell.so | grep -i java_com`；确认是否缺少业务符号。
3. 扫描 ELF 魔数：在 `libshell.so` 中搜索 `7F 45 4C 46` 的所有偏移；对每个偏移截取到文件末尾，保存为 `candidate_<off>.so`。
4. 校验候选：`file candidate_*.so`、`readelf -h`、`readelf -Ws`；选择 `ELF 64-bit LSB shared object, ARM aarch64` 且含 `Java_com_`/`JNI_OnLoad`/`RegisterNatives` 的候选（原文正确偏移 `0x48DC8`，大小约 266.61 KB）。
5. IDA/Ghidra 打开恢复的 so，定位 `setData`：观察 8 字节头解析、变长数据读取、红黑树插入、key 索引与后续地址区间映射。
6. 结合 `extract.dat` 的字节按 `setData` 规则解析/还原，得到业务 dex/native 代码或密文；再继续分析 flag 校验逻辑。
7. 若 carve 后 `readelf` 报节表越界，尝试从魔数开始截到下一个 ELF 魔数/已知长度，或按 ELF 头中的 `e_shoff`/`e_phoff` 计算真实长度。

## PoC

```python
import os, sys

CHUNK = 1024 * 1024

def cut_from(src, dst, offset):
    size = os.path.getsize(src)
    if offset >= size:
        raise ValueError(f"offset 0x{offset:x} >= size 0x{size:x}")
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fin.seek(offset)
        while True:
            buf = fin.read(CHUNK)
            if not buf:
                break
            fout.write(buf)

def find_elf_offsets(path):
    data = open(path, "rb").read()
    offs, start = [], 0
    while True:
        i = data.find(b"\x7fELF", start)
        if i < 0:
            return offs
        offs.append(i)
        start = i + 1

src = "lib/arm64-v8a/libshell.so"
offs = find_elf_offsets(src)
print("ELF candidates:", [hex(x) for x in offs])
for off in offs:
    cut_from(src, f"carved_{off:x}.so", off)
    print(f"carved_{off:x}.so")
```

原文脚本先用 `primary_off=0x48DC` 导出 `part2.so`（头不是 ELF），失败后回退到 `0x48DC8` 导出 `1.so`（头 `7F 45 4C 46`，266.61 KB）。实际环境建议用上面的扫描方式，避免硬编码偏移。

## 变体与关联

- **ELF 被压缩/加密**：魔数可能被抹掉；此时在运行时 hook `dlopen`/`mmap`/`fopen` 或从 `/proc/<pid>/maps` dump，参考运行时 so 提取。
- **多段/多 ELF**：一个 stub 中可能嵌入多个 ELF 或按 ABI 分开；逐个 carve 并比较大小/导出符号。
- **extract.dat 本身是加密数据**：`setData` 只是切块入树，真正解密在 `ihk`/`test` 或其他 native 函数中；需继续逆向或动态调用。
- **一代/三代壳**：一代壳用 `attachBaseContext` 解密 dex；三代壳可能整体 VMP/抽取，需结合 Frida/dump。
- 关联：[[mobile-android-encrypted-so-runtime-dlopen-extraction]]（运行时解密 so 并 dump）、[[mobile-android-first-gen-dex-packer-attachbasecontext-classloader]]（一代 DEX 壳）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 App 动态脱壳）。

## 检测与防御

- **客户端加固**：壳只能提高逆向成本；敏感逻辑/密钥应在服务端，客户端校验需配合完整性校验、反调试、运行时检测与代码混淆。
- **检测特征**：stub so 中嵌入 ELF 魔数、`extract.dat` 与 `setData` 的 JNI 调用、`System.loadLibrary` + `loadDex` 组合、so 导出表与 Java native 方法不匹配。
- **分析建议**：保留原始 so 哈希与 carve 偏移；对每个 ELF 候选校验 `e_machine/e_type/e_shoff`；在隔离环境运行/模拟，避免执行未知 native 代码。
