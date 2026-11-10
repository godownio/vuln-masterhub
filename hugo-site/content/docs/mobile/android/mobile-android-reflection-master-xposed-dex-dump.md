---
id: mobile-android-reflection-master-xposed-dex-dump
title: 反射大师 + Xposed 脱第一代壳：夜神 Android 7.1.2 上从运行中 APP dump classes.dex 再用 jadx 审计
type: scenario
domain: mobile
path: mobile/android
technique: android-reflection-master-xposed-current-activity-dex-dump
tags:
- android
- apk
- packer
- unpacking
- xposed
- reflection-master
- nox
- dex
- jadx
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V282
  verified_at: '2026-11-08T05:03:52+08:00'
  notes: 已对照原文与21张截图核对：Xposed 89/Android 7.1.2、ProxyApplication attachBaseContext 中 DexClassLoader 替换 mClassLoader、反射大师当前ACTIVITY写出DEX到 /data/user/0/com.swdd.trustme/files/dump、adb pull 8226032 字节、jadx 真实 MainActivity/MoveSQLiteUtil、mydb.db ^0xFF 与 XYCTF flag 均一致；未验证点：反射大师内部 Hook 实现细节与工具安装包版本原文未给出。
url: /docs/mobile/android/mobile-android-reflection-master-xposed-dex-dump/
draft: false
kb_aliases:
- 反射大师脱壳
- Reflection Master
- Xposed 脱壳
- 夜神模拟器脱壳
- 当前ACTIVITY 写出DEX
- dump classes.dex
- XYCTF2024 Trustme
- 第一代壳脱壳
- jadx 脱壳后分析
---

## 一句话结论

在已 root 的夜神模拟器（Android 7.1.2）上安装并激活 Xposed 与「反射大师」模块后，启动加壳 APP，点悬浮红色六芒星 →「当前ACTIVITY」→ 长按「写出DEX」→ 确定，即可把当前 Activity 所在 ClassLoader 的真实 DEX 从内存写到 `/data/user/0/<包名>/files/dump`；`adb pull` 后用 jadx 打开 `classes.dex` 即可看到被第一代壳隐藏的真实入口与业务逻辑（原文以 XYCTF2024 Trustme 为例，脱壳后再用 SQL 注入万能钥匙或对 `mydb.db` 异或 0xFF 取 flag）。

## 原理

- **第一代壳的静态特征**：原文用 jadx 打开 APK，发现 `AndroidManifest.xml` 中启动 Activity 为 `com.swdd.tru5tme.MainActivity`（注意 `tru5tme`），而 Application 为 `com.swdd.trustme.ProxyApplication`，类名/包名对不上；源码树只有 `ProxyApplication`、`R`、`RefinvokeMethod` 等少量壳类。`ProxyApplication.attachBaseContext()` 中读取 `shell.apk`、用 `DexClassLoader` 加载并反射替换 `android.app.LoadedApk.mClassLoader`——这是典型第一代 DEX 加固：真实 `classes.dex` 加密/存放在壳资源中，运行时才解密加载，静态反编译只能看到壳。
- **反射大师的工作方式**：它是一个 Xposed 模块，运行在目标 APP 进程内，Hook 运行时/反射相关逻辑，能枚举当前 Activity 及其 ClassLoader，并把 ClassLoader 中已加载的 DEX 从内存导出。因此不需要逆壳的解密算法，直接在“解密后已加载”的时刻 dump。
- **为什么需要 Xposed 激活**：模块必须在 Xposed 中勾选并重启模拟器/设备后才生效；原文环境为夜神 7.0.3.5（Android 7.1.2，x86）、Xposed 框架 89，激活状态显示绿色对勾。
- **适用范围**：适用于没有检测反射大师、没有魔改的简单第一代壳；若壳带反调试/反 Xposed、VMP 或检测工具特征，dump 可能失败。工具对 Android 版本有要求（原文为 Android 7.1.2）。
- **例子后半段（非脱壳必需）**：真实 `MainActivity` 的 `MoveSQLiteUtil.move()` 把 `assets/mydb.db` 复制到 `/data/data/<包名>/databases/`，并对每个字节 `^ 0xFF`；`onClick` 直接拼接 `SELECT * FROM User WHERE username = '<输入>' AND password = '<输入>'`，存在 SQL 注入万能钥匙；`onCreate` 还查询 `username='flag'` 的密码。数据库文件在 jadx 中打开会卡死，改后缀后用 010 Editor 的「工具 → 十六进制运算 → 二进制异或」（操作数 FF、整个文件）还原，可见 `XYCTF{...}`。

## 触发条件

- 已 root 的 Android 设备/模拟器，Android 版本与反射大师兼容（原文夜神 7.0.3.5，Android 7.1.2）。
- 已安装 Xposed 框架并激活，安装「反射大师」模块后在 Xposed 模块列表中勾选并重启，确保模块生效。
- 目标 APP 为第一代 DEX 壳且未检测反射大师/Xposed；APP 可正常启动并进入某个 Activity。
- 用于授权的逆向分析/CTF 题目；不得用于未授权应用。

## 利用步骤

1. 搭建环境：夜神模拟器切 root，安装 Xposed 并激活（原文框架 89），安装反射大师；在 Xposed 左上角菜单 → 模块中勾选反射大师，重启模拟器。
2. 安装目标 APK（原文 `Trustme.apk`，包名 `com.swdd.trustme`），先运行确认界面正常。
3. 打开反射大师，在应用列表找到目标（原文「相信我」，包名 `com.swdd.trustme`），点「选择这个软件」，按提示重新打开目标 APP。
4. 目标 APP 页面上出现红色六芒星悬浮图标，点击它；在弹出的类/Activity 信息中点击「当前ACTIVITY」（原文显示 `com.swdd.tru5tme.MainActivity`）。
5. 长按「写出DEX」按钮，弹出「dex文件夹输出路径，默认请留空」对话框，直接确定（可选「修复Magic」）。
6. 提示「处理成功，共写出 1 个 dex，文件夹位于 `/data/user/0/com.swdd.trustme/files/dump`」，点「复制」复制路径。
7. 在主机执行 `adb pull /data/user/0/com.swdd.trustme/files/dump`（原文拉回 8226032 字节），`dump` 文件夹内的 `classes.dex` 用 jadx 打开。
8. 在 jadx 中查看真实 `com.swdd.tru5tme.MainActivity`/`MoveSQLiteUtil` 等，继续逆向或对示例数据库异或取 flag（见 PoC）。

## PoC

环境准备与 dump（原文 UI 流程对应的命令）：

```bash
# 前提：模拟器已 root、Xposed 已激活、反射大师模块已勾选并重启
# 在反射大师中：选择目标软件 -> 重新打开 APP -> 点击红色六芒星 -> 当前ACTIVITY
# 长按「写出DEX」-> 确定 -> 复制提示中的路径
adb pull /data/user/0/com.swdd.trustme/files/dump ./dump
# dump/classes.dex 用 jadx 打开
```

示例数据库异或（原文 Java 代码逻辑，Python 等价）：

```python
data = open("mydb.db", "rb").read()
open("mydb_decrypted.db", "wb").write(bytes(b ^ 0xFF for b in data))
# 或 010 Editor: 工具 -> 十六进制运算 -> 二进制异或, 操作数 FF, 整个文件
```

原文 jadx 中真实入口的关键逻辑：

```java
public class MoveSQLiteUtil {
    public static void move(Context context) {
        String str = "/data/data/" + context.getPackageName() + "/databases/";
        File file = new File(str + "mydb.db");
        ...
        int read = open.read(bArr);
        for (int i = 0; i < read; i++) {
            bArr[i] = (byte) (bArr[i] ^ UByte.MAX_VALUE); // ^ 0xFF
        }
    }
}
// MainActivity.onClick: "SELECT * FROM User WHERE username = '" + obj + "' AND password = '" + obj2 + "'"
```

原文未给出工具安装包下载地址/版本号，反射大师与 Xposed 需按兼容版本自行准备。仅限授权环境使用。

## 变体与关联

- **同类非 Frida dump 方案**：[[mobile-android-360-hardening-fundex-lsposed-dump]]（LSPosed/FunDex，适用于 360 加固且 Frida 被检测）、[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APKiD 查壳 + frida-dexdump）——本卡是 Xposed 反射大师路线，工具、Hook 框架与操作流程不同。
- **壳原理**：[[mobile-android-first-gen-dex-packer-attachbasecontext-classloader]]（第一代壳 attachBaseContext 解密 assets dex + 反射替换 mClassLoader 的原理；本卡的 dump 对象正是该链加载后的 DEX）。
- **其他脱壳路线**：[[code-analysis-reverse-unpacking-jvmti-classfileloadhook-frida-dump]]（JVM/JVMTI 场景，非 Android APK）。
- **示例后半段**：SQL 注入万能钥匙可参考 SQL 注入基础卡；XOR 0xFF 数据库还原可参考字符串/文件异或类卡。二者只是例题解法，不是本卡核心。
- **边界**：需要 Xposed + 模块激活；高版本 Android 对 Xposed 兼容性差；壳检测反射大师/Xposed、VMP、抽取壳、方法体加密等会使 dump 不完整或失败；dump 出的 dex 可能缺 Magic/需修复（工具提供「修复Magic」选项）。

## 检测与防御

- 应用侧：检测 Xposed/LSPosed 框架与常见模块（反射大师、FunDex 等）、检测悬浮窗/无障碍/调试与 root/模拟器；对 DEX 做完整性校验与运行时自校验；使用更高级壳（VMP、抽取、方法体加密）并做反 Hook。
- 逆向侧（授权场景）：优先在隔离模拟器操作，dump 后校验 DEX Magic 与类完整性，必要时用多个 dump 工具交叉验证；对缺失的类可结合 Frida/ClassLoader hook 补齐。
- 防守方检测：终端/模拟器环境中出现 Xposed 框架、反射大师包名与悬浮窗、异常的 `/data/user/0/<pkg>/files/dump` 目录与 `adb pull` 行为；应用启动时进程被注入 Xposed 模块。
