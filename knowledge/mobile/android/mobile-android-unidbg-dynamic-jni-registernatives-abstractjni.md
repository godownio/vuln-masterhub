---
id: mobile-android-unidbg-dynamic-jni-registernatives-abstractjni
title: Unidbg 调用动态注册 JNI：Frida hook RegisterNatives 定位 so + AbstractJni 补环境（getAndroidId/getSafeDeviceId/Build.MODEL）
type: scenario
domain: mobile
path: mobile/android
technique: unidbg-dynamic-jni-registernatives-abstractjni-env
aliases:
- unidbg 补环境
- RegisterNatives hook
- AbstractJni
- callStaticObjectMethodV
- libj.so _d _e
- native 签名参数
- dynamic JNI unidbg
tags:
- android
- unidbg
- jni
- register-natives
- frida
- native
- emulation
- reverse-engineering
cve: []
severity: medium
confidence: medium
affected_versions: 酷狗音乐 APP 11.7.0（原文实测，libj.so）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V612
  verified_at: '2026-11-12T19:56:34+08:00'
  notes: 已通读原文全文并逐张核对61张图（均降为最长边1200 JPEG，无读图失败）：图01 版本11.7.0；图17-20 jadx 定位 signature 与 w.a hook（str=OIlwieks28dk2k092lksi2UIkp）；图25-46 pk 的 RSA 公钥/base64；图47-54 dfid 的 key_device_finger_id_date/cQ()/f198358g；图55-61 key 的 as()/lo/F/md5/b 函数。原文正文给出完整 RegisterNatives hook 脚本、libj.so 结论与 Unidbg 代码（AbstractJni 覆写 callStaticObjectMethodV/getStaticObjectField：getAndroidId=5c083d1045985cf2、getSafeDeviceId=null、Build.MODEL=Xiaomi；for32Bit、AndroidResolver(23)、按序 loadLibrary libc++_shared/libcrypto_kg/libj 并 callJNI_OnLoad、_d/_e 调用），卡内 PoC/参数与之一致；affected_versions 酷狗11.7.0 与图01/原文‘最新版本11.7.0’一致。修正：卡内 AbstractJNI 按原文与 unidbg 实际类名 com.github.unidbg.linux.android.dvm.AbstractJni 统一改为 AbstractJni（knowledge+staging 同步）。未验证点：原文后半 RegisterNatives 输出、Unidbg 报错/补环境截图多为 alidocs 远程 URL，未落到本地 img/（本地 img/ 为 01-61 前半截图），相关结论以正文代码为准、未逐图核对；未本机复跑；t1 真机/模拟器差异为原文说明。dedup：候选 tools-frida-art-registernatives-dynamic-so-offset-locate（仅 Frida 定位 so）、unidbg-jni-static-method-blackbox-call（静态注册 unidbg）、jni-registernatives-static-real-function-locate（IDA
    静态）等均非同链；dup-scan 不涉及。判原子保留。
---

## 一句话结论

对通过 `JNI_OnLoad` + `RegisterNatives` 动态注册的 native 方法（如签名参数 t1/t2 背后的 `_d`/`_e`），可以先用 Frida Hook art 的 `RegisterNatives` 枚举注册表定位到真实 so（本例 `libj.so`），再在 Unidbg 中加载 APK 与依赖 so、`resolveClass` 后 `callJniMethodObject` 直接调用；若 native 方法会回调 Java 环境（`SecretAccess.getAndroidId`、`getSafeDeviceId`、`Build.MODEL`），需继承 `AbstractJni` 覆写 `callStaticObjectMethodV`/`getStaticObjectField` 补值，否则会因环境缺失报错。

## 原理

- **动态注册的定位难点**：静态注册的 JNI 方法有 `Java_<包名>_<类名>_<方法>` 导出符号，IDA 可直接搜；动态注册则在 `JNI_OnLoad` 里调用 `RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)`，真实函数指针只存在于运行时注册表。Java 层的 `native` 方法名与 so 导出符号可能完全无关。
- **Hook RegisterNatives 枚举注册表**：art 导出符号 `_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi`。Frida 用 `Module.enumerateSymbolsSync("libart.so")` 找到该符号并 `Interceptor.attach`，在 `onEnter` 读 `args[1]`（jclass）、`args[2]`（JNINativeMethod 数组）、`args[3]`（方法数），按 3 个指针宽度解析 `{name, signature, fnPtr}`，即可看到哪个 so 注册了哪些方法（原文由此确认 `libj.so` 注册了 `com/kugou/common/player/kugouplayer/j` 的 `_d`/`_e`）。
- **Unidbg 为什么能直接调用**：Unidbg 用 Unicorn 模拟 ARM CPU，并在其上实现 DalvikVM 与 JNI 环境；加载 APK 与 so 后，`vm.resolveClass(...).newObject(null).callJniMethodObject(emulator, "_d(Ljava/lang/Object;)Ljava/lang/String;", arg)` 即可按 JNI 语义执行 native 函数。动态注册的 so 需要先 `loadLibrary` 后 `callJNI_OnLoad(emulator)`，让注册表建立。
- **补环境的必要性**：native 函数内部可能调用 Java 静态方法/字段获取设备信息。Unidbg 默认的 `AbstractJni` 对这些签名没有实现，会抛 `UnsupportedOperationException` 或返回空导致崩溃。继承 `AbstractJni` 并覆盖：
  - `callStaticObjectMethodV`：`com/kugou/common/utils/SecretAccess->getAndroidId()Ljava/lang/String;` 返回固定 StringObject；
  - 同一方法中 `getSafeDeviceId()Ljava/lang/String;` 返回固定值；
  - `getStaticObjectField`：`android/os/Build->MODEL:Ljava/lang/String;` 返回如 `"Xiaomi"`。
  这样 native 侧拿到的环境稳定，签名结果可重复。
- **设备一致性**：原文指出 t1 的返回值在真机与模拟器上不同（推测与 UUID/设备信息有关），需要以 Pixel 真机的实际值为准校准补环境常量；Unidbg 只支持 ARM 架构，模拟器 x86 结果不可直接对比。
- **局限**：Unidbg 补环境是“黑盒调用”，拿到的是当前输入下的输出，不等于还原了算法；若服务端绑定设备/时间戳/一次性随机数，仍需完整复刻签名协议。

## 触发条件

- 目标 so 的 JNI 方法为动态注册（`JNI_OnLoad` + `RegisterNatives`），Java 层 native 方法名无法直接对应导出符号。
- 能拿到 APK 与相关 so（`libj.so` 及依赖的 `libc++_shared.so`、`libcrypto_kg.so` 等），且 so 未做强混淆/反模拟。
- 知道目标 Java 类名与方法签名（可从 jadx 反编译 native 声明或 RegisterNatives Hook 输出得到）。
- native 方法依赖的 Android 环境 API 数量有限、可枚举补值；若依赖复杂 Binder/系统服务，需要更多自定义 JNI 实现。
- 本地有 Unidbg 工程与匹配的 Android 系统库（`AndroidResolver(23)` 等）；设备侧有 root + Frida 用于定位与结果对照。

## 利用步骤

1. **定位动态注册**：Frida 注入目标进程（若遇反调试先按 [[mobile-android-frida-ptrace-slot-antidebug-spawn-resume]] 处理），Hook `libart.so` 的 `RegisterNatives`，打印每次注册的 `java_class/name/sig/fnPtr` 与 `DebugSymbol.fromAddress`，确认目标方法由哪个 so 注册。
2. **确认 Java 类与签名**：jadx 查看 `com.kugou.common.player.kugouplayer.NativeParams` 的 `getToken`/`getMachineIdCode`，跟踪到 `com.kugou.common.player.kugouplayer.j` 的 `native _d(Object)`/`_e(Object)`；也可从 Hook 输出的 signature 直接取得。
3. **搭 Unidbg 骨架**：`AndroidEmulatorBuilder.for32Bit().addBackendFactory(new Unicorn2Factory(true)).setProcessName(packageName).build()`；`memory.setLibraryResolver(new AndroidResolver(23))`；`vm = emulator.createDalvikVM(new File(apk))`；`vm.setJni(this)`（this 为继承后的 AbstractJni）。
4. **按依赖顺序加载 so**：先 `libc++_shared.so`、`libcrypto_kg.so`，再 `libj.so`，每个都 `callJNI_OnLoad(emulator)`；`NativeApi = vm.resolveClass("com/kugou/common/player/kugouplayer/j")`。
5. **调用方法**：`NativeApi.newObject(null).callJniMethodObject(emulator, "_d(Ljava/lang/Object;)Ljava/lang/String;", "com.kugou.common.q.b@93e301")`，`_e` 同理；首次运行会因缺环境报错。
6. **补环境**：继承 `AbstractJni`，在 `callStaticObjectMethodV` 里按 signature 返回 `getAndroidId`/`getSafeDeviceId` 固定值，在 `getStaticObjectField` 里返回 `Build.MODEL`；不要直接改 `AbstractJni` 源码（会污染环境），用子类覆盖。
7. **对照验证**：同一输入在真机 Frida 上调用 `_d`/`_e` 取真实返回值，与 Unidbg 输出对比；若不一致，补齐更多环境字段（UUID、AndroidId、机型）直到稳定。

## PoC

Frida 枚举 RegisterNatives（节选）：

```javascript
function find_RegisterNatives() {
    let symbols = Module.enumerateSymbolsSync("libart.so");
    for (let s of symbols) {
        if (s.name.indexOf("art") >= 0 && s.name.indexOf("JNI") >= 0 &&
            s.name.indexOf("RegisterNatives") >= 0 && s.name.indexOf("CheckJNI") < 0) {
            Interceptor.attach(s.address, {
                onEnter(args) {
                    let cls = Java.vm.tryGetEnv().getClassName(args[1]);
                    let count = parseInt(args[3]);
                    let p = ptr(args[2]);
                    for (let i = 0; i < count; i++) {
                        let name = Memory.readCString(Memory.readPointer(p.add(i * Process.pointerSize * 3)));
                        let sig = Memory.readCString(Memory.readPointer(p.add(i * Process.pointerSize * 3 + Process.pointerSize)));
                        let fn = Memory.readPointer(p.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));
                        console.log(cls, name, sig, DebugSymbol.fromAddress(fn));
                    }
                }
            });
        }
    }
}
setImmediate(find_RegisterNatives);
```

Unidbg 骨架与补环境（节选）：

```java
public class Videos extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass NativeApi;
    private final String packageName = "com.kugou.android";
    private final String packagePath = "kugou11.7.0.apk";

    public Videos() {
        emulator = AndroidEmulatorBuilder.for32Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName(packageName).build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File(packagePath));
        vm.setJni(this);
        vm.setVerbose(true);
        vm.loadLibrary(new File("libc++_shared.so"), true).callJNI_OnLoad(emulator);
        vm.loadLibrary(new File("libcrypto_kg.so"), true).callJNI_OnLoad(emulator);
        vm.loadLibrary(new File("libj.so"), true).callJNI_OnLoad(emulator);
        NativeApi = vm.resolveClass("com/kugou/common/player/kugouplayer/j");
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/kugou/common/utils/SecretAccess->getAndroidId()Ljava/lang/String;":
                return new StringObject(vm, "5c083d1045985cf2");
            case "com/kugou/common/utils/SecretAccess->getSafeDeviceId()Ljava/lang/String;":
                return new StringObject(vm, "null");
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/os/Build->MODEL:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "Xiaomi");
        }
        throw new UnsupportedOperationException(signature);
    }

    public String callD() {
        return NativeApi.newObject(null)
                .callJniMethodObject(emulator, "_d(Ljava/lang/Object;)Ljava/lang/String;",
                        "com.kugou.common.q.b@93e301")
                .getValue().toString();
    }
}
```

## 变体与关联

- **静态注册变体**：若 so 使用 `Java_...` 导出符号（无 `JNI_OnLoad`），不需要 RegisterNatives Hook，直接 `resolveClass + callJniMethod` 即可，见 [[mobile-android-unidbg-jni-static-method-blackbox-call]]。
- **静态定位变体**：不运行 App 时，用 IDA 解析 `JNI_OnLoad` → `RegisterNatives` → `JNINativeMethod` 数组读 name/signature/fnPtr，见 [[mobile-android-jni-registernatives-static-real-function-locate]]；Frida 动态枚举版本的定位方法见 [[tools-frida-art-registernatives-dynamic-so-offset-locate]]。
- **前置反调试**：目标 APP 可能带 ptrace 占坑等反 Frida 机制，先按 [[mobile-android-frida-ptrace-slot-antidebug-spawn-resume]] 绕过再 Hook。
- **补环境扩展**：除 `getAndroidId`/`getSafeDeviceId`/`Build.MODEL` 外，native 还可能读取 `Build.SERIAL`、`TelephonyManager`、`Settings.Secure.ANDROID_ID`、`PackageManager` 签名等；按报错逐个补，保持与真机一致。
- **边界**：原文只展示 `_d`/`_e` 在 Unidbg 中的调用结果，未还原其内部算法；真机与模拟器的 t1 值不同，补环境常量必须按目标真机校准。

## 检测与防御

- **APP 侧（防御）**：把关键签名/校验下沉到 native 并做环境完整性校验（检测 Unidbg/模拟器特征、`/proc/self/maps`、异常 Build 字段、Hook 框架），对 native 结果做服务端二次校验（设备指纹、时间戳、一次性 nonce），避免仅靠可离线复刻的纯本地算法。
- **检测信号**：设备上出现 `frida-server`/改名二进制；目标进程被 Hook `RegisterNatives`；同一设备短时间内大量不同机型/AndroidId 组合调用签名接口；native 方法的返回值与真机分布不符。
- **边界**：Unidbg 补环境能绕过“本地可模拟”的校验，但无法伪造服务端持有的密钥/设备证明；反向结论应结合实际抓包与服务端行为验证。
