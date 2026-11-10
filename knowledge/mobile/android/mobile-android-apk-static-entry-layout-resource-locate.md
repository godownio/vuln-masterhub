---
id: mobile-android-apk-static-entry-layout-resource-locate
title: Android APK 静态定位链路：Manifest launcher 入口 → onCreate → setContentView 资源 ID → 布局 onClick → 事件常量逆运算
type: scenario
domain: mobile
path: mobile/android
technique: android-apk-static-entry-layout-resource-trace
aliases:
- APK 入口点定位
- setContentView 资源 ID 反查布局
- android:onClick 静态绑定定位
- 按钮事件函数定位
- 资源文件在 APK 中的位置
tags:
- android
- apk
- reverse
- jadx
- androidmanifest
- layout
- resource-id
- ctf
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:43:19+08:00'
  notes: 已对照原文核对：Mainifest MAIN/LAUNCHER 入口、setContentView(0x7f04001a)→R.layout.acticity_main_1、res/layout、android:onClick=showHelp 静态绑定与 setOnClickListener 动态绑定、资源 ID 0x7f020053→R.drawable.timg 的定位链均与本篇原文一致。核对时修正了 PoC：原稿把反向公式再套一遍导致输出乱码，现改为按原文脚本原顺序重放变换并标注正确逆运算（第二处 x4 依赖更新后的 x2'）；实跑得 flag{59acc538825054c7de4b26440c0999dd}，与原文截图一致。未验证点：未在真机/jadx 上复现该链路。
---

## 一句话结论

面对一个未加壳的 APK，可以用一条固定的静态追踪链把「界面」映射回「代码」：先在 `AndroidManifest.xml` 找 `MAIN` + `LAUNCHER` 的 Activity 作为入口，进 `onCreate()` 看 `setContentView(0x7f04xxxx)` 的数值资源 ID，用 jadx 全局搜索该 ID 命中 `R.layout.xxx` 常量定义，再去 `res/layout/xxx.xml` 找控件的 `android:onClick`（静态绑定）或回到代码找 `setOnClickListener`（动态绑定），最终把校验逻辑里的常量与变换逆运算成正确输入。

## 原理

- **入口点由清单而非代码决定**：Android 用 `intent-filter` 声明组件的启动方式，`<action android:name="android.intent.action.MAIN"/>` 与 `<category android:name="android.intent.category.LAUNCHER"/>` 组合标记的是桌面启动器入口；因此清单里的 `android:name` 就是唯一入口 Activity 的完整类名，不必猜测。
- **生命周期给出了阅读顺序**：Activity 首次创建必经 `onCreate()`（初始化与 `setContentView`）→ `onStart()` → `onResume()`（可能刷新状态）；界面结构与控件查找、事件注册几乎都在 `onCreate`，页面状态的二次更新常在 `onResume`，所以从 `onCreate` 入手不会漏掉主逻辑。
- **资源 ID 是界面与代码之间的桥**：编译后 `R.layout.xxx`、`R.drawable.xxx`、`R.id.xxx` 都是 32 位整数（`0x7f` 前缀表示应用资源），反编译代码里只剩数字。jadx 的全局搜索会把同一 ID 在 `R` 类常量定义、`resources.arsc` 映射与代码引用处一起列出，据此反推出符号名，再去 `res/` 目录按类型（`layout`/`drawable`/`values`）找到实际文件。
- **两种事件绑定方式决定去哪找函数**：XML 里 `android:onClick="showHelp"` 是静态绑定，系统在 inflate 时按方法名反射调用，函数签名必须是 `public void xxx(View)`；代码里 `setOnClickListener(new View.OnClickListener(){...})` 是动态绑定，逻辑写在匿名内部类的 `onClick` 里（反编译常显示为 `MainActivity$1` 或 lambda）。找不到 `android:onClick` 就要回到 `onCreate` 找 `setOnClickListener`。
- **校验常是可逆常量运算**：这类界面校验的通行写法是「对某个硬编码字符串做若干字符运算 + 逆序/交换，再与用户输入比较」。提示串与目标串都写死在代码里，因此既可以把变换按代码顺序重放得到提示/flag（原文脚本就是重放，见 PoC），也可以按相反顺序减回去逆推原始常量；两种方向都成立的前提是变换只是字符算术与置换，没有外部密钥参与。

## 触发条件

- 拿到可反编译的 APK，`classes.dex` 未被加固（加固时 `classes.dex` 只有壳代码，需先脱壳）。
- 逻辑位于 Java/Kotlin 层，没有下沉到 native 或服务端校验。
- 使用 jadx/GDA/JEB 之一即可；IDA 在此链路中通常用不上。

## 利用步骤

1. jadx 打开 APK，定位 `AndroidManifest.xml`，读 `package`、`<application>`、`<activity>` 的 `android:name`，锁定带 `MAIN`/`LAUNCHER` 的 Activity 类名。
2. 在该 Activity 源码中打开 `onCreate(Bundle)`，记录 `setContentView(0x7f0....)` 的数值。
3. 在 jadx 全局搜索框输入该数值（勾选「代码」与「资源」），命中 `public static final int xxx = 0x7f0...;`，得到 `R.layout.<name>`。
4. 到 `res/layout/<name>.xml` 浏览控件树；逐个看 `android:onClick` 属性，或记下 `android:id="@+id/xxx"` 的数值 ID 回到代码里查 `findViewById(0x7f0...)` 的对应控件。
5. 静态绑定：直接在 Activity 里搜同名方法（形如 `public void showHelp(View v)`）；动态绑定：在 `onCreate` 里找 `setOnClickListener` 的匿名类/lambda。
6. 读校验函数：把硬编码目标串、字符算术（`+/-`、ASCII 常量 `0x30`/`0x61`）、循环交换、逆序等写成脚本——按代码顺序重放可得提示/flag，按相反顺序减回去可逆推原始常量，输出正确输入。
7. 需要确认资源文件本体（图片/`values` 字符串）时，同样用资源 ID 反查 `R.drawable`/`R.string` 常量，再到 `res/drawable`、`res/values` 找文件。

## PoC

```python
# 原文脚本的做法是把代码里的 4 次字符运算按原顺序重放，再做整体前后交换，
# 目标串写死在代码里，因此不需要真的去点按钮（这就是原文得到 flag 的方式）
target = list("dd2940c04462b4dd7c450528835cca15")
target[2] = chr(ord(target[2]) + ord(target[3]) - 50)     # 0x32
target[4] = chr(ord(target[2]) + ord(target[5]) - 48)     # 0x30，用的已是更新后的 target[2]
target[30] = chr(ord(target[31]) + ord(target[9]) - 48)
target[14] = chr(ord(target[27]) + ord(target[28]) - 97)  # 0x61
for i in range(16):                                       # 前半段与后半段整体交换（自逆）
    target[i], target[31 - i] = target[31 - i], target[i]
print("flag{" + "".join(target) + "}")  # flag{59acc538825054c7de4b26440c0999dd}
```

> 若要真正逆推这串常量（而不是照原文重放），必须按**相反顺序减回去**：`x2 = x2' - x3 + 50`、`x4 = x4' - x2' - x5 + 48`（`x4` 的逆运算依赖更新后的 `x2'`，不能写成 `x4' - x3 - x5`）、`x30 = x30' - x31 + 48`、`x14 = x14' - x27 - x28 + 97`；把正向公式再套一遍是常见错误。

```bash
# 资源 ID 反查的等价命令行做法（jadx 图形搜索的替代）
jadx -d out/ target.apk
grep -rn "0x7f04001a" out/ | head
# 命中 R.layout 常量后直接看布局
sed -n '1,80p' out/resources/res/layout/activity_main.xml
```

```bash
# 静态绑定函数的运行时验证（不点按钮也能触发）
adb shell am start -n com.example.app/com.example.app.MainActivity
```

## 变体与关联

- **入口变体**：非 launcher 的 Activity/Service/Receiver 也会承载逻辑；导出的组件可用 `am start`/`am broadcast` 直接拉起，见 [[mobile-android-exported-activity-unauth-changepassword-phishing]]。
- **绑定变体**：`android:onClick` 在 Android 5.0+ 也支持 DataBinding/ViewBinding 生成的代码；Kotlin 项目多为 lambda（`setOnClickListener(v -> ...)`），反编译显示为 `-$$Lambda$` 类。
- **加固变体**：`classes.dex` 只有壳代码、清单仍明文时，先按 [[mobile-android-packer-apkid-frida-dexdump-jadx]] 脱壳得到真实 dex，再执行本链路。
- **逻辑下沉变体**：`onClick` 只是转发到 `native` 方法（`public static native int CheckString(String)`），此时转 [[mobile-android-jni-native-strcmp-target-inverse]]。
- **关联**：[[mobile-android-frida-jump-internal-activity]]（清单枚举 + Frida 拉起未导出 Activity）、[[mobile-android-apk-native-gate-hidden-activity-decrypt]]（入口由长按等隐藏手势触发）。

## 检测与防御

- 检测（分析侧）：确认入口 Activity 与 `setContentView` 资源一致、`android:onClick` 名字在源码中存在同名方法，避免把壳代码或混淆名当成业务逻辑。
- 防御（开发侧）：不要把可通过纯客户端运算还原的密钥/口令/flag 逻辑放在客户端；关键校验放服务端。
- 防御：对 UI 校验逻辑做字符串加密、控制流混淆，或把判定下沉到 native 并加完整性校验，提高静态逆运算成本。
- 检测信号：APK 中存在 `MAIN`/`LAUNCHER` 之外的隐藏 Activity、`android:onClick` 指向敏感方法、`onCreate` 里大段硬编码字符运算。
