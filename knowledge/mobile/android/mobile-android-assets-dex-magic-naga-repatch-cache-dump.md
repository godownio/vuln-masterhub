---
id: mobile-android-assets-dex-magic-naga-repatch-cache-dump
title: Android 自定义加固：assets 中 dex 被改 magic（naga→dex\n），运行时修复落盘 .cache 后直接拉取
type: scenario
domain: mobile
path: mobile/android
technique: android-assets-dex-magic-repatch-cache-dump
aliases:
- naga magic dex
- copyAssets 脱壳
- assets dex 释放
- dex magic 修复
- 娜迦加固误判
- .cache classes.dex
- 自定义加固脱壳
tags:
- android
- unpacking
- packer
- dex
- assets
- magic
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V559
  verified_at: '2026-11-12T00:46:12+08:00'
  notes: 已对照原文与18张图核对：图01 JADX 包结构（Install/Proxy/Defines/Helper/ShellApplication）；图02 copyAssets 的 nagic{78,71,0,0}/magic{100,101,120,10} 与替换条件；图03 dataDir 下 XDATA/classes.dex 释放判断（原文正文说明为 .cache 目录）；图04 加密流量入口 /mobile。已修正卡内两处描述：(1) 原文实际替换条件是文件头 4 字节等于 110,97,103,97（十六进制 6e 61 67 61，即 ASCII 'naga'）时写回 dex\n，代码中的 nagic={78,71,0,0} 只出现在取反的前置判断中，不是实际匹配标识，原卡把 naga 写成 78 71 00 00 有误，已改正文/步骤/PoC；(2) 其余 .cache 落盘、root/run-as 拉取、静态修 magic 描述与原文一致。dedup：与第一代加固卡（AES 加密 assets dex + attachBaseContext + DexClassLoader 反射替换）机制不同（本卡无加密、仅改 magic 落盘），与 APKiD/frida-dexdump、360 Fundex 等通用脱壳亦不同，非同一链。未验证点：未复现样本；原文无 CVE/受影响版本（该卡为加固手法非组件漏洞，未设 versions）；frontmatter 无 sources/source_url（库内惯例）。
---

## 一句话结论

遇到"加固方式未知、反编译后只剩少量壳代码"的 APK 时，重点搜索壳里的 `copyAssets`/`AssetManager` 逻辑：本例壳从 assets 读取 dex，检测到文件头前 4 字节为 ASCII `naga`（字节 110,97,103,97）时，写回标准 dex magic `dex\n`（100,101,120,10）后写入应用数据目录的 `.cache`；安装运行 App 后直接到 `/data/data/<pkg>/.cache`（或 `files`/`app_*`）拉取修复后的 `classes.dex`，即可用 jadx/IDA 分析真实业务代码。

## 原理

- **简单加固只做文件重定位 + magic 伪装**：原始 dex 明文放在 assets 里，壳在运行时读取、修复文件头、写到私有目录，再由壳加载；没有加密或动态解密时，静态上唯一障碍是 assets 中的 dex 被改了 magic，无法被 jadx 直接识别。
- **magic 替换识别**：标准 dex 文件头为 `dex\n035\0`（字节 100,101,120,10）；本例壳的实际替换条件为：文件以 `.dex` 结尾且前 4 字节等于 110,97,103,97（十六进制 `6e 61 67 61`，即 "naga"）时，`System.arraycopy(magic, 0, bytes, 0, 4)` 写回 `dex\n`；代码中另定义了 `nagic={78,71,0,0}`，只出现在取反的前置判断里，不是实际匹配的标识。所以 assets 中的文件用十六进制看到 `6e 61 67 61` 开头，即为被改 magic 的 dex。
- **落盘位置可从代码追溯**：`copyAssets(output, input, context)` 的 output 由调用方传入；本例为 `context.getApplicationInfo().dataDir + .cache` 下的 `classes.dex`（代码中还有 `if (!new File(user_dir + Defines.XDATA, "classes.dex").exists())` 判断）。运行 App 触发释放后，dex 就留在私有目录。
- **MT 管理器加固识别可能出错**：本例 MT 提示"娜迦加固"但实际不是，需以反编译代码为准；包很少时逐个看 `Install`/`Proxy`/`ShellApplication` 等壳类，找 `copyAssets` 是最快入口。
- **为什么可直接拉取**：私有目录权限 0700，但 root 设备或 `run-as`（debuggable）可直接 `adb pull`；也可用 Frida hook `FileOutputStream.write`/`DexClassLoader` 定位路径。

## 触发条件

- APK 反编译后 `classes.dex` 很小，业务类不在其中，Manifest Application 指向壳类（本例 `ShellApplication`）。
- assets 中存在高熵/异常文件头（如 `naga`）的 `.dex`/`.dat` 文件。
- 壳为简单第一代/自研加固：运行时修复 magic 或解密后落盘到私有目录，未做内存加载/强反调试。
- 测试设备可 root 或应用可 `run-as`。

## 利用步骤

1. `apktool d`/jadx 打开 APK，查看包结构与 Application 类（本例 `com.*.Install`/`Proxy`/`Defines`/`ShellApplication`）。
2. 在壳代码中搜索 `copyAssets`、`getAssets().open`、`FileOutputStream`、`arraycopy`，确认 assets 文件名与 magic 修复逻辑。
3. 记录 magic 常量（本例 `naga`=110,97,103,97 → `dex\n`={100,101,120,10}；代码中的 `{78,71,0,0}` 为取反分支干扰）与输出路径（`dataDir/.cache/classes.dex`）。
4. 安装并运行 App，触发壳释放；root 下 `adb shell ls /data/data/<pkg>/.cache` 并 `adb pull`，或 `run-as <pkg> cat .cache/classes.dex > classes.dex`。
5. 校验文件头 `dex\n035` 后用 jadx/IDA 分析；若 assets 中的 dex 只是 magic 被改，也可直接静态修复 magic 后分析，无需运行。

## PoC

```text
# 壳的关键逻辑（原文 copyAssets 简化）
byte[] magic = {100, 101, 120, 10};   # "dex\n"
# 实际替换条件：.dex 且前 4 字节 == 110,97,103,97（"naga"）
# （原文另定义 nagic={78,71,0,0}，仅出现在取反的前置判断中）
if (output.endsWith(".dex") && bytes[0..3] == {110, 97, 103, 97})
    System.arraycopy(magic, 0, bytes, 0, 4);
bufferedOutput.write(bytes, 0, i);
```

```bash
# 运行时从私有目录取 dex（root 或 run-as）
adb shell su -c 'ls -l /data/data/<pkg>/.cache/'
adb shell su -c 'cp /data/data/<pkg>/.cache/classes.dex /sdcard/' && adb pull /sdcard/classes.dex
# 静态修复 magic
printf '\x64\x65\x78\x0a' | dd of=assets_class.dex bs=1 count=4 conv=notrunc
```

原文在银行 App 样本中按此拿到 `.cache` 下的原生 dex 并导入 IDA 分析（后续定位到 `telecomSMEncrypt` native 加密函数）。

## 变体与关联

- **变体**：magic 可换成任意 4 字节（`naga`、`0123`、随机串）；输出目录可换成 `files/`、`app_dex/`、`cache/`；也可先 XOR/异或加密再修复。
- **变体**：若壳把 dex 读入内存并 `InMemoryDexClassLoader` 加载而不落盘，需 Frida hook `DexClassLoader`/`InMemoryDexClassLoader` 或 dump 内存。
- **关联**：[[mobile-android-first-gen-dex-packer-attachbasecontext-classloader]]（第一代加固：assets dex 加密 + attachBaseContext + DexClassLoader 换 mClassLoader）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（通用脱壳）、[[mobile-android-dex-format-manual-parse]]（dex 格式）。
- **边界**：强壳（VMP/native 解密/内存加载/反调试）不适用；私有目录不可读且无 root/run-as 时需动态 dump。

## 检测与防御

- **检测**：反编译后业务代码缺失、assets 中出现非标准 magic 的 dex、壳代码存在 `copyAssets`/magic 替换/向私有目录写 dex 的行为；运行时私有目录出现 `classes.dex`。
- **防御**：不要只靠改 magic，dex 应加密并 native 解密、内存加载、加完整性校验与反调试；加固方案定期升级。
