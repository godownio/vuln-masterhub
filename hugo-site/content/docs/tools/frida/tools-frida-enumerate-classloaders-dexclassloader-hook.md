---
id: tools-frida-enumerate-classloaders-dexclassloader-hook
title: Frida hook 动态加载 dex：enumerateClassLoaders 找到 DexClassLoader 并切换 classFactory.loader 后再 hook 其中类
type: scenario
domain: tools
path: tools/frida
technique: frida-enumerate-classloaders-dexclassloader-classfactory-hook
tags:
- frida
- android
- hook
- dexloader
- classloader
- java-choose
- implementation
- ctf
- reverse
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:26:38+08:00'
  notes: 已对照原文与图15核对：Java.choose 取 getDynamicDexCheck() 返回值 、Java.enumerateClassLoaders 逐个 findClass、Java.classFactory.loader 切换、再 Java.choose + implementation hook check() 均与原文脚本一致；与既有 Frida 卡及同篇另两卡无重复；dup-scan.json(11-08)早于建卡且未涉及；原文无版本信息；未复跑 PoC
url: /docs/tools/frida/tools-frida-enumerate-classloaders-dexclassloader-hook/
draft: false
kb_aliases:
- Frida hook 动态 dex
- DexClassLoader hook
- Java.enumerateClassLoaders
- Java.classFactory.loader
- $className 运行时类名
- Frida 找不到动态加载的类
---

## 一句话结论

当目标类不在 APK 主 dex、而是运行时由 `DexClassLoader` 从 assets/缓存目录加载的插件 dex 中时，直接 `Java.use("包名.类名")` 会报找不到类；正确做法是先从一个宿主实例取得该对象的运行时类名（`$className`），再用 `Java.enumerateClassLoaders` 遍历进程中所有 ClassLoader，对每个 loader 调 `findClass(类名)`，命中者就是 `DexClassLoader`，把 `Java.classFactory.loader` 切换成它，之后 `Java.choose`/`Java.use` 就能正常解析并 hook 动态 dex 中的类。

## 原理

- **类由 ClassLoader 决定可见性**：Android 的类加载是分层的，`DexClassLoader` 在运行时把 `DynamicPlugin.dex` 加载进来，其中的类只挂在该 loader 下；Frida 的 `Java.use`/`Java.choose` 默认经 `Java.classFactory.loader` 解析，初始指向应用的 `PathClassLoader`，自然看不到插件 dex 里的类。
- **枚举与探测**：`Java.enumerateClassLoaders({onMatch, onComplete})` 遍历 VM 中所有 `ClassLoader` 包装器；对每个 loader 调 `loader.findClass(类名)`，能成功返回 Class 的即负责加载该类的 loader（本例为 `dalvik.system.DexClassLoader`）。逐个 try/catch 是因为多数 loader 找不到目标类会抛异常。
- **切换解析器**：`Java.classFactory.loader = loader` 把 Frida 后续类解析所用的 loader 换成命中的 DexClassLoader，此后 `Java.use`/`Java.choose` 才能拿到插件类。
- **运行时类名**：宿主通过接口持有动态类实例（如 `getDynamicDexCheck()` 返回 `CheckInterface`），包装器的 `$className` 给出实例的真实运行时类名（如 `com.example.androiddemo.Dynamic.DynamicCheck`），比手写字符串更可靠，也适用于实现类名与声明接口不同的情况。
- **hook 时机**：先 `Java.choose(动态类名, ...)` 拿到实例，再对目标方法赋 `implementation`，即可把 `check()` 之类返回 false 的校验改成 `return true`。

## 触发条件

- APK 在运行时用 `DexClassLoader`/`PathClassLoader` 等加载外部 dex（代码里出现 `DexClassLoader`、`loadClass(...).newInstance()` 即可判断）。
- 目标类名/接口名可从 jadx 静态分析获得；插件 dex 可以位于 assets、缓存目录或下载后落盘。
- 设备可运行 frida-server 并 attach 目标进程，应用未做阻止注入的强反调试。

## 利用步骤

1. jadx 定位动态加载逻辑：`new DexClassLoader(str, cacheDir, null, getClassLoader()).loadClass("...DynamicCheck").newInstance()`，确认接口方法与校验点（如 `onCheck()` 调 `getDynamicDexCheck().check()`）。
2. 用 `Java.choose` 枚举宿主 Activity 实例，调用其 getter 取到动态对象，打印 `ret.$className` 得到真实类名。
3. `Java.enumerateClassLoaders` 遍历 loader，对每个 loader `findClass(类名)`；命中的 loader 赋给 `Java.classFactory.loader`。
4. 用 `Java.choose(类名, {onMatch: instance => { instance.方法.implementation = function(){ return true; } }})` hook 动态类的方法。
5. 触发业务校验（点按钮），确认走到成功分支。

## PoC

```javascript
Java.perform(function () {
  var interface_classname;

  // 1) 从宿主实例拿动态类的运行时类名
  Java.choose("com.example.androiddemo.Activity.FridaActivity5", {
    onMatch: function (instance) {
      var ret = instance.getDynamicDexCheck();
      interface_classname = ret.$className;
      console.log("dynamic class:", interface_classname);
    },
    onComplete: function () {}
  });

  // 2) 枚举 ClassLoader，找到能加载该动态类的 DexClassLoader
  Java.enumerateClassLoaders({
    onMatch: function (loader) {
      try {
        if (loader.findClass(interface_classname)) {
          console.log("found loader:", loader);
          Java.classFactory.loader = loader;   // 切换 Frida 的类解析器
        }
      } catch (e) {}
    },
    onComplete: function () {}
  });

  // 3) 正常解析并 hook 动态 dex 中的类
  Java.choose(interface_classname, {
    onMatch: function (instance) {
      instance.check.implementation = function () {
        return true;
      };
    },
    onComplete: function () {}
  });
});
```

注意：`Java.choose` 的第 1 步依赖宿主 Activity 已创建（实例已存在）；若拿不到实例，可先 hook 动态类的构造方法或加载点再切换 loader。

## 变体与关联

- 变体：类名完全未知时，可先 `Java.enumerateLoadedClasses` 列出已加载类，或直接 dump 出插件 dex 后用 jadx 分析类名。
- 变体：插件 dex 被加密/加固时，先按其解密逻辑落盘或在内存中 dump，再按本卡切换 loader 后 hook；含加密 dex 段落的 dump 思路见 [[ctf-reverse-android-native-embedded-encrypted-dex-segment-dump]]。
- 关联：宿主把 dex 释放到私有目录再 `DexClassLoader` 加载的加固/插件结构，与 [[mobile-android-first-gen-dex-packer-attachbasecontext-classloader]] 描述的第一代壳 classloader 链相似，但本卡目的是在 Frida 中切换解析器后 hook 业务类，而非 dump 原始 dex。
- 关联：Java 层常规的 `implementation`/`Java.choose`/字段改写见 [[tools-frida-java-hook-static-instance-field-choose]]；本卡补的是“类不在默认 loader 时如何让 `Java.use` 找到它”。

## 检测与防御

- 分析侧信号：APK 中出现 `DexClassLoader`、`loadClass(...).newInstance()`、assets 下非标准命名的 dex，即意味着静态 `Java.use` 可能失效，应准备枚举 ClassLoader。
- 防守侧：插件 dex 加密并校验完整性；检测 Frida/注入框架与类加载器枚举行为；关键校验放服务端；避免把成功分支与明文 flag 放在同一动态 dex 中。
- 局限：强反调试/壳会让 attach 失败或进程退出；切换 `classFactory.loader` 只影响 Frida 自身的类解析，不改变应用逻辑。
