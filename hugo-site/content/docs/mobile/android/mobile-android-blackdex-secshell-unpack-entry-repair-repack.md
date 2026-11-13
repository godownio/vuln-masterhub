---
id: mobile-android-blackdex-secshell-unpack-entry-repair-repack
title: BB/SecShell 加固 APK 脱壳后修复重打包：BlackDex 取真实 dex + NP 修复 + 改回 MyApplication 入口 + 删 appComponentFactory + 去 SecShell 特征重签
type: scenario
domain: mobile
path: mobile/android
technique: blackdex-secshell-entry-repair-repack
tags:
- android
- apk
- unpacking
- blackdex
- secshell
- bangcle
- repack
- appcomponentfactory
- np-manager
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V588
  verified_at: '2026-11-12T14:14:13+08:00'
  notes: 已对照原文与全部24张截图核对：MT 显示梆梆加固/1.3.3(6)（图01），BlackDex 输出 cookie_*.dex/hook_*.dex 且原 classes.dex 约20KB（图02），修复后为 classes1/2/3.dex 188.06K/7.47M/8.61M 放回原包（图03），删除 aip.license、meta-data/、libSecShell*.so 后 MT 显示未加固（图04-05），SecShell.H 中 APPNAME=com.jtjsb.paitushizi.MyApplication（图06）与类名 smali com/jtjsb/paitushizi 一致，Manifest application android:name 由壳类改回 MyApplication（图07）、删除 appComponentFactory=com.SecShell.SecShell.AP（图08）后应用可正常打开（图09）。13.gif 为动图，img_small 仅保留首帧，跳过启动页过程无法逐帧复核（该场景已 skipped，不影响本卡）。dedup 唯一 duplicate 为草稿自身，其余为 related 的不同加固/不同环节卡，非同链。原文未标注受影响版本（1.3.3(6) 为目标应用版本），不设 affected_versions；Severity medium/confidence high 合理。
url: /docs/mobile/android/mobile-android-blackdex-secshell-unpack-entry-repair-repack/
draft: false
kb_aliases:
- SecShell 脱壳修复
- 梆梆加固脱壳重打包
- BB 加固 BlackDex
- appComponentFactory 删除
- SecShell.H APPNAME 真实入口
- 脱壳后打不开修复
---

## 一句话结论

对梆梆/BB（SecShell）加固的 APK，用 BlackDex 脱出真实 dex（文件名为 `cookie_*.dex`/`hook_*.dex`）后，保留原包里的壳入口 `classes.dex`、删除重复与无用的脱壳 dex，用 NP 管理器修复并重命名为 `classesN.dex` 放回原包；同时删除 `lib`/`assets` 中 `libSecShell*.so`、`aip.license` 等壳特征，把 `AndroidManifest.xml` 的 `application android:name` 改回壳类 `com.SecShell.SecShell.H` 里 `APPNAME` 常量指向的真实 Application（如 `com.jtjsb.paitushizi.MyApplication`），并删除 `android:appComponentFactory="com.SecShell.SecShell.AP"`；重签名安装后应用即可正常启动。

## 原理

- **加固入口的替换关系**：未脱壳前 Manifest 的 `android:name` 指向壳 Application（如 `com.SecShell.SecShell.H`）；壳在 `H` 类中保存两个常量：`APPNAME`（真实 Application 全名）与 `ACENAME`（组件工厂，如 `androidx.core.app.CoreComponentFactory`）。脱壳后如果仍保留壳入口，壳的代理解密/初始化逻辑已不存在或仍尝试加载壳 so，应用启动即失败。
- **appComponentFactory 的接管**：Android 10+ 的 `android:appComponentFactory` 允许壳替换默认组件工厂（如 `com.SecShell.SecShell.AP`），壳用它 hook Activity/Service 创建；脱壳后壳类/so 被删，组件工厂仍指向壳类会导致 ClassNotFound 或启动失败，因此必须删除该属性（系统会回退到真实 Application/默认工厂）。
- **为什么要保留原 classes.dex**：BlackDex 在运行时 dump 出的 dex 是解密后的业务代码，原 APK 中的 `classes.dex` 往往只是壳的极小入口（本例仅约 20KB）；若直接把它删掉/替换，Manifest 与壳的类引用关系被破坏。保留壳入口 dex 的同时把真实 dex 作为 `classes1..N.dex` 并存，可让启动链先走壳入口（此时壳 so 已删，需要入口已改回真实 Application 才不会崩），业务类则由 multidex 加载。
- **NP 管理器修复 dex**：BlackDex 导出的 dex 可能带有 dump 时的头校验/结构问题，NP 管理器的“dex 修复”可重算 checksum/signature 等；修复后再重命名放回，避免安装后 `INSTALL_FAILED_INVALID_APK`/解析失败。
- **删除壳特征**：`libSecShell.so`/`libSecShell-x86.so`、assets 下的 `aip.license`、`meta-data`、`classes0.jar` 等是壳的运行时组件；保留它们会让应用尝试走壳逻辑或触发完整性检查，删除后重签并让 MT 显示“未加固”。
- **重签名是最后一步**：删改 APK 后原签名失效，必须用 keytool/jarsigner/zipalign 或 MT/NP 重签；只要应用没有签名/完整性校验（或校验可绕过），即可安装运行。

## 触发条件

- 目标 APK 为 BB/SecShell（梆梆）加固，jadx/MT 显示加固状态，lib 中存在 `libSecShell*.so`。
- 可在 root/虚拟环境运行 BlackDex 完成脱壳，拿到解密后的 dex。
- 能修改 APK 内容（MT 管理器/NP 管理器/apktool）并重签名；应用未做严格签名校验或校验可绕过。
- 仅限授权测试环境。

## 利用步骤

1. 查壳：jadx 打开 APK 发现代码不可读；MT 管理器查看应用信息，确认“加固状态：梆梆加固”，记录包名/版本。
2. BlackDex 脱壳：在设备上运行 BlackDex，选择目标 APK，导出脱壳结果；输出中常见 `cookie_*.dex` 与 `hook_*.dex`，按大小识别真实业务 dex（本例 `classes1.dex` 188KB、`classes2.dex` 7.47MB、`classes3.dex` 8.61MB）。
3. 清理 dex：对比原 APK，原 `classes.dex` 仅约 20KB（壳入口）要保留；删除与真实 dex 重复的 `cookie_*`/`hook_*` 副本及无用文件。
4. NP 管理器修复保留下来的 dex，重命名为 `classes1.dex`…`classesN.dex`，复制进原 APK 根目录；此步不要勾选“自动签名”。
5. 删除壳特征：`lib/` 下 `libSecShell.so`、`libSecShell-x86.so`；assets 下 `aip.license`、`classes0.jar`、`meta-data/`、相关 html 等；删除后 MT 管理器应显示“未加固”。
6. 改入口：jadx 打开壳类 `com.SecShell.SecShell.H`，读取 `APPNAME` 常量（本例 `com.jtjsb.paitushizi.MyApplication`）；反编译 `AndroidManifest.xml`，把 `<application android:name="com.SecShell.SecShell.H">` 改为该真实 Application。
7. 删组件工厂：Manifest 中如有 `android:appComponentFactory="com.SecShell.SecShell.AP"`，整段属性删除。
8. 重签名并安装；若仍打不开，回查入口/组件工厂是否漏改、dex 是否修复、壳特征是否删净。

## PoC

无独立脚本（MT/NP 管理器为 GUI 操作）。关键检查点：

```text
1) 原包: classes.dex ≈ 20KB（壳入口，保留）
   BlackDex: classes1.dex 188KB / classes2.dex 7.47MB / classes3.dex 8.61MB（修复后放回）
2) 删除: libSecShell.so、libSecShell-x86.so、assets/aip.license、assets/classes0.jar、meta-data/
3) Manifest:
   android:name="com.SecShell.SecShell.H"
     -> "com.jtjsb.paitushizi.MyApplication"   # 取自 H.APPNAME
   删除 android:appComponentFactory="com.SecShell.SecShell.AP"
4) 重签名安装
```

## 变体与关联

- **其他加固**：腾讯加固可用 BlackDex + jadx 路线（见 `mobile-android-blackdex-tencent-packer-hook-bmz-native-md5-key-sign`）；360 加固可用 FunDex/LSPosed dump（见 `mobile-android-360-hardening-fundex-lsposed-dump`）；APKiD 查壳 + frida-dexdump 的通用路线见 `mobile-android-packer-apkid-frida-dexdump-jadx`。
- **壳实现侧**：第一代 DEX 壳在 `attachBaseContext` 解密 assets dex 并替换 `mClassLoader`（见 `mobile-android-first-gen-dex-packer-attachbasecontext-classloader`）；理解壳的入口替换有助于判断脱壳后要改哪些 Manifest 属性。
- **脱壳后的二次修改**：应用正常启动后，可继续改 Manifest launcher 跳过启动页（`mobile-android-apk-manifest-launcher-vip-charge-bypass`）、用 smali/Frida 绕过会员判断（`mobile-android-smali-vip-check-force-true-repack`）。
- **边界**：若应用有签名校验/完整性校验或壳使用 native 反调试，脱壳后重打包可能仍闪退，需要先绕过校验或改用运行时 hook。

## 检测与防御

- 检测：APK 的 `AndroidManifest.xml` 中 `appComponentFactory` 指向第三方壳类、`application android:name` 与包内真实 Application 不一致；`libSecShell*.so`/`aip.license` 被删除但 dex 数量异常；重签名后的证书与官方不一致。
- 防御：启用签名校验/完整性校验与服务器端校验；壳厂商启用反脱壳/反重打包（检测 BlackDex、调试、frida）；关键权益判断放服务端。
