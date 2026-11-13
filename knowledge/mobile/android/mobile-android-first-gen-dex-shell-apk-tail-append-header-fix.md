---
id: mobile-android-first-gen-dex-shell-apk-tail-append-header-fix
title: 第一代 DEX 落地壳变体：加密 APK 附加到 classes.dex 尾部（末 4 字节长度）并修正 checksum/signature/file_size，运行时解密加载
type: scenario
domain: mobile
path: mobile/android
technique: first-gen-dex-shell-apk-tail-append-header-fix
aliases:
- DEX 落地壳
- APK 附加 DEX 尾部
- DEX 头字段修正
- checksum signature file_size 重算
- ProxyApplication 壳
tags:
- android
- dex
- packer
- classloader
- manifest
- header-fix
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V573
  verified_at: '2026-11-12T10:45:18+08:00'
  notes: 已对照原文(194行)与9图逐张核对：图01 DEX拼接布局(头/解壳DEX Body/加密Source DEX数据/末4字节长度)；图02 LoadedApk.mClassLoader字段；图03-04 壳Manifest(.ProxyApplication、APPLICATION_CLASS_NAME、源App启动Activity)；图05 加密组装工程(classes.dex/shell.dex/source.apk/Main.java)；图06 源App入口MainActivity(package com.android.sourceapp)；图07 7z直接替换classes.dex(3,826,857字节)且不签名安装；图08-09 壳启动进入source app。技术点核对：checksum=adler32、signature=SHA-1、file_size、拼接=壳DEX+加密APK+4字节长度、XOR 0x66、RefInvoke.setFieldOjbect(android.app.LoadedApk,mClassLoader,weakReference,DexClassLoader)、fixFileSize→SHA1→CheckSum 顺序均与原文一致；原文未给完整解壳代码(声明参考开源实现)，卡内如实注明。原文未标注受影响版本(Android9/雷电9仅为演示环境)，未设置 affected_versions，正确。dedup报告0 duplicate/0 likely_duplicate(9 related/11 new)；与已验证卡 mobile-android-first-gen-dex-packer-attachbasecontext-classloader 为同代壳的不同变体(该卡为assets加密DEX+attachBaseContext+AES，本卡为APK追加classes.dex尾部+XOR+头字段修正+Manifest入口替换)，非同链重复，卡内已互链并说明差异。已知不一致：正文要求 APPLICATION_CLASS_NAME 写源App的Application子类(如XApplication，写MainActivity会失败)，但图03/04截图为com.android.sourceapp.MainActivity，卡内已注明以正文为准。未验证点：未在模拟器复现；frontmatter无sources/source_url。
---

## 一句话结论

第一代 DEX 落地壳可以把“待加固 APK”整体加密后附加到壳 `classes.dex` 的尾部，并在文件最后 4 字节写入密文长度；拼接改变了 DEX 头的 `checksum`（adler32）、`signature`（SHA-1）与 `file_size`，必须按新文件重算修正。运行时壳读取自身 `classes.dex` 尾部数据、按约定算法解密出 APK，用 `DexClassLoader` 加载并替换 `LoadedApk.mClassLoader`，同时通过 Manifest 把启动 Activity 指向源 App、用 meta-data 指定源 Application 类，从而透明运行原 APK。

## 原理

- **拼接布局**：成品 `classes.dex` = 壳 DEX（含解壳代码） + 加密后的源 APK + 4 字节源 APK 长度。DEX 头三个字段只覆盖“从 magic 之后到文件尾”的整体，因此追加数据后原值全部失效。
- **三个头字段**：`checksum` 用 adler32 校验除去 magic 与 checksum 外的全部文件；`signature` 用 SHA-1 覆盖除去 magic/checksum/signature 外的全部文件；`file_size` 为整个文件长度。拼接后必须依次重写 `file_size`、`signature`、`checksum` 才能被 Android 正常解析。
- **为什么能运行**：壳用 `RefInvoke.setFieldOjbect("android.app.LoadedApk","mClassLoader", weakReference.get(), dexClassLoader)` 把系统加载业务类的入口替换为解密 APK 的 `DexClassLoader`；Manifest 中主启动 Activity 直接写源 App 的入口（如 `com.android.sourceapp.MainActivity`），并加 `APPLICATION_CLASS_NAME` meta-data 指向源 App 的 Application 类，壳 App 无需 UI，启动后即解密并进入原 App 生命周期。
- **落地特征**：第一次启动解密并落盘/加载，第二次直接运行，故称“落地加载”；这是最基础的一代壳，易被静态解密与内存 dump。

## 触发条件

- 具备壳 DEX（含解壳/加载逻辑与反射工具类）与待加固 APK；壳的 Manifest 已按源 App 改写。
- 拼接与头修正脚本可运行（Java 即可）；测试环境为可安装未签名/自签名 APK 的模拟器或已 root 设备（原文在雷电模拟器 9/Android 9 验证）。
- 了解 DEX 头字段算法与 `DexClassLoader`/`LoadedApk.mClassLoader` 替换点。

## 利用步骤

1. 准备 `source.apk`（待加固）与 `shell.dex`（壳 DEX，含解壳逻辑）。
2. 用自定义算法（原文 XOR 0x66）加密 `source.apk` 得到密文字节。
3. 新建 `newdex`：先拷贝 `shell.dex`，再追加密文，最后 4 字节写入密文长度。
4. 依次修正头字段：`file_size` = 总长度；`signature` = SHA-1（跳过 magic/checksum/signature）；`checksum` = adler32（跳过 magic/checksum）。
5. 将产物保存为 `classes.dex`，替换壳 APK 中的 `classes.dex` 或放入工程重新打包安装。
6. 壳启动后读取自身 `classes.dex` 尾部密文与长度，解密出 APK，`DexClassLoader` 加载并反射替换 `LoadedApk.mClassLoader`，进入源 App。
7. 复现失败时优先核对：Manifest 启动 Activity/`APPLICATION_CLASS_NAME` 是否指向源 App 的类、三个头字段是否按新文件重算、末 4 字节长度是否与实际密文一致。

## PoC

```java
// 拼接 + 修正 DEX 头（对应原文流程的最小骨架）
byte[] payload = encrypt(readFileBytes(new File("source.apk")), 0x66);
byte[] shell   = readFileBytes(new File("shell.dex"));
byte[] out = new byte[shell.length + payload.length + 4];
System.arraycopy(shell, 0, out, 0, shell.length);
System.arraycopy(payload, 0, out, shell.length, payload.length);
System.arraycopy(intToByte(payload.length), 0, out, out.length - 4, 4);
fixFileSizeHeader(out);   // 重写 file_size
fixSHA1Header(out);       // 重写 signature（SHA-1）
fixCheckSumHeader(out);   // 重写 checksum（adler32）
writeFile("classes.dex", out);
```

```text
# Manifest 关键项（壳 APK）
<meta-data android:name="APPLICATION_CLASS_NAME"
           android:value="com.android.sourceapp.XApplication"/>
<activity android:name="com.android.sourceapp.MainActivity">
  <intent-filter>
    <action android:name="android.intent.action.MAIN"/>
    <category android:name="android.intent.category.LAUNCHER"/>
  </intent-filter>
</activity>
```

## 变体与关联

- 同族标准实现（assets 加密 DEX + `attachBaseContext` 解密 + 替换 `mClassLoader`）见 [[mobile-android-first-gen-dex-packer-attachbasecontext-classloader]]；本卡是其“APK 附加 DEX 尾部 + 头字段修正 + Manifest 入口替换”实现变体。
- 变体：加密算法可换 XOR/RC4/自定义；附加对象可为 DEX 或整 APK；加载可用 `DexClassLoader` 或 `InMemoryDexClassLoader`（API 26+）。
- 边界：壳逻辑仍需反射替换类加载器，容易被 Frida hook `DexClassLoader`/`mClassLoader` 或从私有目录 dump；原文未给出完整解壳代码（声明参考开源实现），且 Manifest 中 `APPLICATION_CLASS_NAME` 的取值在正文（`XApplication`）与截图（`MainActivity`）不一致，正文明确写 `MainActivity` 会失败，复现时以源 App 的 Application 子类为准。

## 检测与防御

- 检测：`classes.dex` 尾部高熵数据并以 4 字节小端长度结尾、DEX 头 `file_size` 与文件实际长度一致但 DEX 解析异常；Manifest 的 Application 为壳类、启动 Activity/meta-data 指向不在壳 DEX 中的类；`DexClassLoader`/`mClassLoader` 反射替换；首次启动后私有目录出现解密 APK。
- 防御：壳为最基础加固，应升级到 native 解密、内存加载、VMP、反调试/反 hook 与完整性校验；分析侧可静态按尾部长度切出密文解密，或 hook `DexClassLoader` 构造函数 dump。
