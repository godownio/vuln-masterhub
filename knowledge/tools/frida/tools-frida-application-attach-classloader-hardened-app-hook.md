---
id: tools-frida-application-attach-classloader-hardened-app-hook
title: 加固 App 的 Frida hook：hook Application.attach(Context) 在壳完成 attachBaseContext 后取 ClassLoader，切换 classFactory.loader 再 hook 目标类
type: scenario
domain: tools
path: tools/frida
technique: frida-application-attach-capture-packer-classloader
aliases:
- 加固 App hook
- 壳 App ClassLoader hook
- Application.attach hook
- attachBaseContext 后取 classloader
- Frida 加载加固类
tags:
- frida
- android
- hook
- classloader
- packed-app
- hardening
- java-use
- mobile
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V589
  verified_at: '2026-11-12T14:26:17+08:00'
  notes: 已对照原文与3张截图核对：img01 Application extends ContextWrapper、img02 attach(Context) 内部先 attachBaseContext 再取 mPackageInfo、img03 frida -f spawn 启动后打印 Hook_class 与 hook 日志，均支持卡内时序与 spawn 约束；卡内 PoC(hook attach→this.attach→context.getClassLoader→Java.classFactory.loader→classFactory.use) 与原文脚本一致。dedup：top likely_duplicate tools-frida-enumerate-classloaders-dexclassloader-hook(trigram 0.2472) 是运行时 DexClassLoader 插件 dex 场景、需枚举 loader+findClass 试探，本卡是加固壳 attachBaseContext 替换 ClassLoader 场景、在 attach 返回后直接从 context 取 loader，取 loader 时机与机制不同；与壳实现侧卡 mobile-android-first-gen-dex-packer-attachbasecontext-classloader 互补。reason 成立，保留。root 检测绕过(isRooted/isExecuted/checkRootMethod2 返回 false)与既有 mobile-android-frida-hook-isrooted-issimulator-bypass 同类，跳过建卡合理。全局 dup-scan 无本卡 pair。原文未标注版本，affected_versions 保持空。
---

## 一句话结论

加固壳会在 `Application.attachBaseContext()` 里解密 dex 并把应用 ClassLoader 换成自己的实现，此时直接 `Java.use("目标类")` 会报找不到类；改为 hook `android.app.Application.attach(Context)`，先调用原方法（其内部会触发 `attachBaseContext`），再从传入的 `context.getClassLoader()` 取到壳安装后的 ClassLoader，赋给 `Java.classFactory.loader`，之后用 `Java.classFactory.use("包名.类")` 就能正常解析并 hook 壳内的目标类。

## 原理

- **Application 启动时序**：进程启动时先 `new Application`，再调用 `attach(Context)`；`attach` 内部依次执行 `attachBaseContext(context)`（壳在这里解密 dex、反射替换 `mClassLoader`）和 `mLoadedApk = ContextImpl.getImpl(context).mPackageInfo`，最后才调用 `onCreate()`。因此在原 `attach` 返回之后取 `context.getClassLoader()`，拿到的已经是壳替换后的 ClassLoader。
- **Frida 的类解析器**：`Java.use`/`Java.classFactory.use` 默认经 `Java.classFactory.loader`（初始为应用的 PathClassLoader）解析类；壳动态加载的类只挂在它自己的 loader 下，默认解析器自然看不到。
- **切换 loader**：把 `Java.classFactory.loader` 指向壳 ClassLoader 后，Frida 后续的 `use`/`choose` 都走该 loader，目标类即可见。与“枚举所有 ClassLoader 逐个 `findClass` 试探”的做法相比，本方法不用猜类名、时机更早，适合加固壳把原 ClassLoader 整体替换掉的场景。
- **时机约束**：`attach` 在进程启动早期只执行一次，必须用 spawn 方式（`frida -U -f <包名> -l hook.js`）在 Application 创建前注入；若用 attach 方式挂到已启动进程，`attach` 已经执行完，钩子不会命中，需要改用枚举 loader 或 hook 更晚的加载点。
- **壳内的 hooks 同步生效**：拿到 loader 后所有 `Java.classFactory.use` 的类都来自壳解密后的 dex，方法覆盖（`implementation`）与普通 Frida hook 写法完全一致。

## 触发条件

- 目标 APK 带加固（第一代 dex 壳、商业加固等），壳在 `attachBaseContext` 中替换 ClassLoader；可直接看到壳的 Application/StubApp 类或 `mClassLoader` 反射赋值。
- 使用 Frida spawn 模式启动目标进程，且 frida-server 可运行、未被强反调试拦截。
- 目标类与方法名可从 jadx/静态分析得到；壳未把类名/方法名完全抹掉（多数壳只做 dex 加密，不重命名业务类）。
- 仅限授权测试环境。

## 利用步骤

1. jadx 打开 APK，查看 `AndroidManifest.xml` 的 `android:name` 指向的 Application：加固样本常见壳的 StubApplication；跟进其 `attachBaseContext` 可见解密 dex 与反射替换 `mClassLoader` 的逻辑。
2. 用 spawn 方式启动：`frida -U -f <包名> -l hook.js --no-pause`，脚本在 `Java.perform` 中注册 `Application.attach` 的 hook。
3. hook `android.app.Application` 的 `attach`（重载参数 `android.content.Context`）：先 `this.attach(context)` 执行原逻辑，再 `context.getClassLoader()` 取壳 loader。
4. `Java.classFactory.loader = classloader;` 后用 `Java.classFactory.use("com.xxx.业务类")` 取到目标类，按普通方式给方法赋 `implementation` 打印参数或改返回值。
5. 触发业务操作，确认日志中出现目标方法参数；若壳同时有 root 检测，按已有卡 `mobile-android-frida-hook-isrooted-issimulator-bypass` 的方式把检测方法返回值改为 false。
6. 若目标类仍找不到，打印 `classloader` 与 `Java.enumerateClassLoaders` 结果核对，确认 hook 的是最终生效的 loader（部分壳会多次替换）。

## PoC

```javascript
if (Java.available) {
  Java.perform(function () {
    var Application = Java.use("android.app.Application");

    Application.attach.overload('android.content.Context').implementation = function (context) {
      var result = this.attach(context);            // 先执行原 attach，内部触发 attachBaseContext
      var classloader = context.getClassLoader();   // 壳替换后的 ClassLoader
      Java.classFactory.loader = classloader;

      var Target = Java.classFactory.use("com.example.app.TargetClass");
      Target.method.implementation = function (arg) {  // 按实际签名补参数
        console.log("[hook] arg =", arg);
        return this.method(arg);                     // 需要保持业务时调用原方法
      };
      return result;
    };
  });
}
```

验证加载成功：在脚本里 `console.log("Hook_class: " + Target)`，spawn 启动后能打印类包装器即说明 loader 切换生效。

## 变体与关联

- **动态加载 dex 场景**：不是壳替换 loader，而是运行时 `DexClassLoader` 加载插件 dex 时，用 `Java.enumerateClassLoaders` 逐个 `findClass` 找 loader；见 `tools-frida-enumerate-classloaders-dexclassloader-hook`。本卡与它是同一目标（切换 `classFactory.loader`）的两种取 loader 路径，区别在时机与前提。
- **壳实现侧**：第一代 DEX 加固在 `attachBaseContext` 解密 assets dex 并反射替换 `mClassLoader`，见 `mobile-android-first-gen-dex-packer-attachbasecontext-classloader`；了解壳的行为有助于确定 hook 点。
- **脱壳替代**：若只需审计代码而非运行时 hook，可用 frida-dexdump/LSPosed dump（见 360 加固脱壳类卡片）。
- **root/模拟器检测**：壳 App 常附带 root 检测，绕过方法见 `mobile-android-frida-hook-isrooted-issimulator-bypass`。

## 检测与防御

- 检测：壳可在 native 层监控 `Java.classFactory.loader` 切换、Frida 线程与端口、`Application.attach` 的调用栈；部分加固会在 `attachBaseContext` 之后做完整性校验。
- 防御：把 ClassLoader 替换与关键逻辑放到 native 层并做多 loader 校验；对 attach 早期注入做反调试；业务签名/加密放到服务端或安全 SDK，避免仅靠客户端 hook 即可完全控制。
- 测试侧：优先 spawn 模式；若壳反复替换 loader，可在每次替换后更新 `classFactory.loader`，或改用枚举 loader 的兜底方案。
