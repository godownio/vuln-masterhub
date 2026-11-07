---
id: mobile-android-first-gen-dex-packer-attachbasecontext-classloader
title: 第一代 DEX 加固：attachBaseContext 解密 assets dex 并反射替换 mClassLoader（脱壳点）
type: scenario
domain: mobile
path: mobile/android
technique: first-gen-dex-packer-classloader-swap
tags:
- android
- dex
- packer
- unpacking
- classloader
- reflection
- attachbasecontext
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V129
  verified_at: '2026-11-06T04:31:44+08:00'
  notes: 已对照原文及6张图核对：ActivityThread.main→attachApplication→AMS.bindApplication→handleBindApplication→LoadedApk.makeApplication→Instrumentation.newApplication→attachBaseContext 启动链、AES/ECB/PKCS5 加密 assets、getDir("shell")/output.dex、DexClassLoader 与反射替换 LoadedApk.mClassLoader 均与原文一致；原文未标注受影响版本（Android 9 仅为演示环境），未设 affected_versions；卡内 PoC 将原文 Ref.getFieldOjbect/setFieldOjbect 写作 getFieldObject/setFieldObject（原文助手类拼写如此），复用需按目标 Ref 类方法名调整；PoC 未执行。
url: /docs/mobile/android/mobile-android-first-gen-dex-packer-attachbasecontext-classloader/
draft: false
kb_aliases:
- 第一代 DEX 加固
- StubApplication
- attachBaseContext 脱壳
- DexClassLoader 替换 mClassLoader
- DEX 透明加载
- 加固原理
---

## 一句话结论

第一代 DEX 加固把原始 `classes.dex` 用 AES 加密后放进 `assets`，由 `StubApplication` 在 `attachBaseContext()` 中解密到应用私有目录、创建 `DexClassLoader`，再反射替换 `LoadedApk.mClassLoader`；理解这条链后，脱壳点就是“解密后的私有目录 dex”或“DexClassLoader/mClassLoader 替换时刻”，可直接解密或 hook dump。

## 原理

- Android 启动：Zygote fork 应用进程 → `ActivityThread.main()` → `attachApplication` → AMS `bindApplication` → `handleBindApplication` → `LoadedApk.makeApplication` → `Instrumentation.newApplication` → `Application.attach()` → `attachBaseContext()`。
- `attachBaseContext()` 是 Application 最早被调用的方法：Context 已可用（能读 assets/文件系统），但业务类尚未加载；壳在此阶段替换类加载器，后续所有业务类都会走新加载器。
- 加固流程：
  1. 打包前用 AES/ECB/PKCS5 加密原始 `classes.dex`，放入 `assets/output.dex`；
  2. `StubApplication.attachBaseContext()` 读取 assets 密文，流式解密到 `getDir("shell", MODE_PRIVATE)/output.dex`；
  3. `new DexClassLoader(dexFilePath, cacheDir, nativeLibraryDir, parent)`；
  4. 反射 `ActivityThread.currentActivityThread()` → `mPackages` → `WeakReference<LoadedApk>` → `setField(LoadedApk, "mClassLoader", dexClassLoader)`。
- 为什么成立：`LoadedApk.mClassLoader` 是系统后续加载 Application/Activity/业务类的入口；替换后，壳的 `classes.dex` 只负责解密与加载，真实业务代码在解密 dex 中透明执行。
- 脱壳点：解密后的 dex 会落到私有目录（可直接 adb pull，需 root/run-as）；或在 `DexClassLoader` 构造、`mClassLoader` 替换、`ClassLoader.loadClass` 处 hook，dump 内存 dex。

## 触发条件

- APK 的 `AndroidManifest.xml` 中 `android:name` 指向壳 Application（如 `StubApplication`），原始 `classes.dex` 很小、业务类不在其中。
- `assets` 中存在加密的 dex/zip（高熵、非 `dex\n` 魔数）。
- 壳在 `attachBaseContext` 中做解密 + `DexClassLoader` + 反射替换，未使用 native/VMP/高级反调试。
- 测试设备可 root 或可运行 Frida。

## 利用步骤

1. `apktool d`/jadx 打开 APK，确认 Manifest 的 Application 是壳类，`classes.dex` 只有壳代码。
2. 反编译壳的 `attachBaseContext`，定位 assets 文件名、AES 模式/key/IV、输出路径、`DexClassLoader` 与反射字段。
3. 直接解密：用相同 key/模式解 `assets/*.dex`，校验 `dex\n035` 魔数；或用 root 从 `/data/data/<pkg>/app_shell/output.dex` 拉取。
4. 若加密 key 在 native/动态生成，hook `DexClassLoader` 构造函数或 `LoadedApk.setField`，在替换时 dump dex。
5. 用 jadx 打开解密后的 dex，审计业务逻辑。

## PoC

```java
// 壳的关键逻辑（脱壳点）
InputStream in = base.getAssets().open("output.dex");
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AES_KEY.getBytes(), "AES"));
// 解密到 getDir("shell", MODE_PRIVATE)/output.dex
DexClassLoader loader = new DexClassLoader(dexPath, cacheDir, nativeLibDir, getClassLoader());
Object at = Ref.invokeStaticMethod("android.app.ActivityThread", "currentActivityThread", null, null);
ArrayMap packages = (ArrayMap) Ref.getFieldObject("android.app.ActivityThread", at, "mPackages");
LoadedApk apk = ((WeakReference) packages.get(getPackageName())).get();
Ref.setFieldObject("android.app.LoadedApk", "mClassLoader", apk, loader);
```

```javascript
// Frida hook 脱壳点
Java.perform(function () {
  var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
  DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader")
    .implementation = function (dexPath, opt, lib, parent) {
      console.log("DexClassLoader: " + dexPath);
      return this.$init(dexPath, opt, lib, parent);
    };
});
```

## 变体与关联

- 加密可换成 XOR/RC4/自定义算法；输出路径可换成 `files/`、`cache/`；加载器可换成 `InMemoryDexClassLoader`（API 26+）。
- 替换点可换成 `BaseDexClassLoader.pathList`、`ClassLoader.parent`、`Application.mClassLoader`。
- 关联：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APKiD/frida-dexdump 通用脱壳）、[[mobile-android-apk-hidden-dex-protobuf-login-forge]]（隐藏 dex）、[[code-analysis-reverse-unpacking-upx-manual]]（通用脱壳思路）。

## 检测与防御

- 第一代壳易被静态解密/内存 dump；应使用 native 解密、VMP、反调试/反 hook 与完整性校验。
- 检测：Manifest 中 Application 为壳类、assets 中高熵 dex、`DexClassLoader`/`mClassLoader` 反射替换、私有目录出现 `output.dex`。
- 防御：密钥不硬编码、dex 不落盘（内存加载）、加固方案定期升级。
