---
id: mobile-android-unidbg-jni-static-method-blackbox-call
title: Unidbg 黑盒调用 JNI 静态注册方法解 CTF：resolveClass + callJniMethod 直接跑 j/p/init 求 flag
type: scenario
domain: mobile
path: mobile/android
technique: unidbg-jni-static-method-blackbox-call
aliases:
- Unidbg 解 CTF Android
- JNI 静态注册黑盒调用
- callJniMethodObject
- func_p 99999 次迭代
- Obpo 去 OLLVM
- libj.so 分析
tags:
- android
- reverse
- jni
- unidbg
- emulation
- ctf
- native
- ollvm
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V575
  verified_at: '2026-11-12T11:05:41+08:00'
  notes: 已对照原文与全部16张图核对：图02 aapt 得启动 Activity an.droid.j.MainActivity；图06 导出表含 Java_an_droid_j_MainActivity_j/p/init 且图05 确认无 JNI_OnLoad（静态注册）；图07 j() 返回干扰值 flag{FlagLostHelpMeGetItBack}；图08-11 p 方法 OLLVM CFF，Obpo 恢复后为 %3/%5/%7 分支简单运算；图12 func_p(1231321)=1245677；图13 init 以 memcpy "libinit" 拼接并 NewStringUTF；图14 init(9999)=flag{dglibinitcj}；图15 p 迭代 99999 次得 1738911344；图16 init(1738911344)=flag{nllibinitxv}，与卡片输出一致。已修正原理/步骤中 Java 层逻辑：计时器每 100ms 执行 zygote=p(zygote)，满 99999 次后由点击分支用 j(zygote) 拼界面 flag（j 为固定干扰值），init 在 Java 层未被调用，真实 flag 由作者手动传 zygote 调 init 得到。dedup 10 个候选均 related/new（RegisterNatives 定位、Frida 直调、Unicorn 提常量、Unidbg trace 等工具链与用途不同），无同链重复；dup-scan 无涉及本卡 pair。原文未标组件版本，未设 affected_versions；PoC 未在本机复跑。
---

## 一句话结论

对使用静态注册 JNI 的 CTF Android 题，不必先还原 OLLVM 混淆或加密算法：用 Unidbg 加载 APK 与目标 so，`resolveClass`/`newObject` 拿到 JNI 对象后直接 `callJniMethodObject/Int` 调用 `j()`、`p(I)I`、`init(I)Ljava/lang/String;`，把 so 当黑盒跑出结果；Java 层要求 `p()` 迭代 99999 次时，也可在 Unidbg 中循环调用求出最终值再传给 `init`，直接得到 flag。

## 原理

- Unidbg 基于 Unicorn 模拟 ARM CPU，并在其上实现 DalvikVM 与 JNI 环境，可直接加载 APK 中的 dex 与 native so，按 JNI 语义调用 native 方法。
- 静态注册的 JNI 方法在 so 中以 `Java_<包名>_<类名>_<方法名>` 符号导出（如 `Java_an_droid_j_MainActivity_p`）；Unidbg 通过 `resolveClass("an.droid.j.MainActivity")`、`newObject(null)` 构造对应的 `DvmObject`，再用 `callJniMethodInt/Object` 传入参数调用，不需要完整的 App 运行环境。
- 静态注册不依赖 `JNI_OnLoad`（本题 so 甚至没有），因此无需调用 `dm.callJNI_OnLoad`；动态注册则需先执行 `JNI_OnLoad` 注册函数表。
- OLLVM 控制流平坦化只影响人工阅读，不影响黑盒调用：`p()` 内部逻辑再乱，Unidbg 仍可执行并返回结果；本题用 Obpo 插件恢复后可见它只是按 `%3/%5/%7` 分支的简单运算。
- 本题 Java 层逻辑：计时器每 100ms 执行一次 `zygote = p(zygote)`，累计到 `df_all/100 == 99999` 后由按钮分支用 `j(zygote)` 拼出界面显示的 flag；但 `j()` 实际返回固定干扰值 `FlagLostHelpMeGetItBack`，`init()` 在 Java 层并未被调用。作者在 Unidbg 中循环调用 `func_p` 99999 次得到 1738911344，再手动传给 `func_init` 才拿到真实 flag，不必真等 99999×100ms。
- Unidbg 还可设置 `setProcessName("an.droid.j")` 以规避按进程名的反模拟校验；真实设备上的反调试/反模拟在这里不生效。

## 触发条件

- 目标 so 的 JNI 方法为静态注册（导出 `Java_...` 符号），方法签名可从符号/IDA 推导。
- JNI 方法可在无复杂 Java 上下文的情况下被调用（无参数或参数可由攻击者构造）。
- 本地有 Unidbg 工程与匹配的 Android 系统库（如 AndroidResolver 19/23）。
- 目标方法是纯 native 计算/校验，或 Java 层只是循环调用 native；服务端没有二次校验（CTF 场景）。

## 利用步骤

1. `aapt dump badging <apk>` 取得包名、启动 Activity 与进程名（本题 `an.droid.j.MainActivity`，进程名 `an.droid.j`）。
2. 用 jadx 分析 Java 层调用逻辑，确认要调用的 JNI 方法与触发条件（本题：计时器每 100ms 调用 `p(zygote)`，满 99999 次后 `j(zygote)` 拼出界面 flag；`init()` 在 Java 层未被调用，需手动传入算出的 zygote）。
3. 用 IDA 加载 `libj.so`，在导出表中搜索 `JNI_OnLoad` 与 `Java_` 符号，确认静态注册与各方法签名（参数/返回类型）。
4. 按 Unidbg 模板创建模拟器：`AndroidEmulatorBuilder.for32Bit().setProcessName(apkProcessname).build()`、`AndroidResolver(23)`、`createDalvikVM(new File(apk))`、`loadLibrary(new File(so), true)`、`setJni(this)`。
5. 封装方法：`dvmClass = vm.resolveClass("an.droid.j.MainActivity")`，`object = dvmClass.newObject(null)`，`object.callJniMethodObject(emulator, "j()Ljava/lang/String;")` / `callJniMethodInt(emulator, "p(I)I", arg)` / `callJniMethodObject(emulator, "init(I)Ljava/lang/String;", arg)`。
6. 在 main 中循环调用 `func_p` 99999 次得到最终 zygote，再传给 `func_init`，打印 `flag{...}`；若 `j()` 返回固定值（如 `FlagLostHelpMeGetItBack`）说明它是干扰项。
7. 可选：对 OLLVM 混淆方法用 Obpo 插件恢复控制流，便于确认参数/返回值与业务逻辑。

## PoC

```java
// Unidbg 构造（节选）
emulator = AndroidEmulatorBuilder.for32Bit().setProcessName(apkProcessname).build();
memory = emulator.getMemory();
memory.setLibraryResolver(new AndroidResolver(23));
vm = emulator.createDalvikVM(new File(apkFilePath));
dm = vm.loadLibrary(new File(soFilePath), true);
vm.setJni(this);
// 本题 so 无 JNI_OnLoad，静态注册无需调用 dm.callJNI_OnLoad

// 黑盒调用 p(I)I
public int func_p(int args) {
    DvmClass dvmClass = vm.resolveClass("an.droid.j.MainActivity");
    DvmObject<?> object = dvmClass.newObject(null);
    return object.callJniMethodInt(emulator, "p(I)I", args);
}
public String func_init(int args) {
    DvmClass dvmClass = vm.resolveClass("an.droid.j.MainActivity");
    DvmObject<?> object = dvmClass.newObject(null);
    return object.callJniMethodObject(emulator, "init(I)Ljava/lang/String;", args).getValue().toString();
}

// main：99999 次迭代后调用 init
int zygote = 1357024680;
for (int i = 0; i < 99999; i++) zygote = func_p(zygote);
System.out.println("flag{" + func_init(zygote) + "}");
```

```text
# 运行输出示例
99999次后的zygote的值: 1738911344
flag{nllibinitxv}
```

说明：原文在 Unidbg 中调用 `j()` 先得到干扰值 `FlagLostHelpMeGetItBack`，迭代 `p()` 99999 次得到 1738911344 后调用 `init()` 输出 `flag{nllibinitxv}`；本库未复跑。

## 变体与关联

- 变体：动态注册的 so 需先 `dm.callJNI_OnLoad(emulator)` 再按注册表调用；复杂 Java 回调可用 `ProxyDvmObject`/自定义 JNI 实现。
- 变体：方法依赖 `JNIEnv`/`jobject` 或复杂对象时，可用 `callJniMethodObject` 传 `DvmObject`/数组，必要时用 Frida、Unicorn、Qiling 替代。
- 变体：仅需常量/中间值时，可用 Unicorn 直接映射 PT_LOAD 并 hook 指令，比完整 Unidbg 更轻（见关联卡）。
- 关联：[[mobile-android-sig3-unidbg-trace-crc32-whitebox-aes-hmac]]（Unidbg trace 定位签名算法的进阶用法）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（Unicorn 模拟 JNI 校验链）、[[code-analysis-reverse-obfuscation-ollvm-cff-substitution]]（OLLVM CFF 还原）。
- 边界：so 有强反模拟（检测 Unidbg/Unicorn、进程名、maps、时间差）或方法依赖真实 Android 服务时，需补 JNI/环境实现；纯 native 黑盒调用也无法替代服务端校验。

## 检测与防御

- 检测（CTF/防护视角）：native 层检测模拟器特征（Unidbg/Unicorn 的内存布局、进程名、`/proc/self/maps`、JNI 调用栈）；对关键校验加入多因子/服务端校验。
- 防御：不要把 flag 或核心校验完全放在客户端 native；关键结果由服务端判定；对 native 方法做完整性校验与反调试/反模拟。
- 加固：OLLVM/白盒提高逆向成本，但不能阻止黑盒调用；结合环境检测与动态行为监控。
