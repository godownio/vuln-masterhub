---
id: mobile-android-blackdex-tencent-packer-hook-bmz-native-md5-key-sign
title: 腾讯加固新闻类 App 的 st/sn 风控参数逆向：BlackDex 脱壳 + jadx 搜「sn=」定位混淆类 + hook bmz$a.a 打印闭包字段 + IDA 从 so 取出 readMD5Key 硬编码盐后复现 MD5 拼接
type: scenario
domain: mobile
path: mobile/android
technique: android-blackdex-unpack-hook-sign-native-md5-key
tags:
- android
- reverse
- unpacking
- blackdex
- frida
- hook
- jni
- native
- md5
- signature
- tencent-packer
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:54:58+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；腾讯加固→BlackDex 脱壳→jadx 搜 sn= 定位→hook bmz\x24a.a(boolean)/a(String,boolean) 打印 z/e/j/c/l→readMD5Key 为 native 并返回常量 acF%#*{_b1mQt@..ifvy→ces.b 为标准 MD5→st=时间戳+随机数求和、sn=MD5(版本号+e+l+j+c+sn+str3+key) 的结论链与正文逐条一致，卡片常量取值与正文相同；未验证点：hook 打印的具体值（z=false、e=ifengnews、j=2964、c=v0012...）与 IDA 反编译视图、jadx 命中位置仅见于截图，且正文对常量是否跨设备不变用的是「猜测」措辞，未实测；服务端是否额外校验设备指纹未知
url: /docs/mobile/android/mobile-android-blackdex-tencent-packer-hook-bmz-native-md5-key-sign/
draft: false
kb_aliases:
- BlackDex 脱壳腾讯加固
- st/sn 请求参数逆向
- hook 混淆类 a 方法打印字段
- readMD5Key 硬编码盐
- ifeng_secure.so JNI 常量提取
- 新闻 App 风控签名
---

## 一句话结论

抓包发现请求里 `st`/`sn` 两个参数一变就失效，说明它们是本地生成的防篡改签名；APK 是腾讯加固、直接 jadx 只看到壳代码，用 BlackDex 在设备上脱壳后拿到真实 dex，jadx 里搜 `sn=` 定位到混淆类 `bmz$a`，用 Frida hook 其 `a(boolean)`/`a(String, boolean)` 重载打印出闭包字段（版本号、渠道、设备相关常量），再顺着 `readMD5Key` 这个 JNI 方法进 `ifeng_secure.so`、在 IDA 里把参数类型改成 `JNIEnv*` 后看到它返回硬编码字符串 `acF%#*{_b1mQt@..ifvy`，最终确认 `sn = MD5(版本号 + e + l + j + c + sn + str3 + key)`，`st = str`（时间戳与随机数求和）。

## 原理

- **为什么必须脱壳**：加固壳把真实业务 dex 加密保存在 `assets`/native 里，启动后由壳解密到内存并 `DexClassLoader` 加载；磁盘上的 `classes.dex` 只有壳代码，所以 jadx 里搜业务字符串搜不到。BlackDex 采用"在设备上启动目标 App，由脱壳机读取其进程内存中已加载的 DexFile 并落盘"的方式，得到干净的真 dex。
- **为什么搜 `sn=`**：签名参数在代码里通常以字符串拼接或 `StringBuilder.append("sn=")` 出现，直接搜参数名比在混淆类名里盲猜快得多；命中处即签名组装点，顺着它能看到调用的是哪个类的哪个方法。
- **为什么要 hook 混淆方法而不是硬读代码**：`bmz$a.a(String, boolean)` 的实现里可能读 `Build`/`TelephonyManager`/`SharedPreferences` 等运行期值，静态只能看到字段名；用 Frida 按重载（`overload('java.lang.String','boolean')`）挂上，把 `this.e`、`this.j`、`this.c`、`this.l` 直接打印出来，一次就能拿到"同一设备上不变"的常量集合，省掉大量猜测。
- **为什么要进 native**：`sn` 的计算还差一个"盐"，它来自 `readMD5Key()`——一个 `native` 方法。把 `libifeng_secure.so` 从 APK 里取出、IDA 里定位 `Java_..._readMD5Key`，把第一个参数类型改为 `JNIEnv*` 后即可看出函数体是 `NewStringUTF("acF%#*{_b1mQt@..ifvy")` 之类的"直接返回常量"。这类"把关键常量藏在 so 里"的做法只提高静态门槛，一旦 so 未加壳/未混淆字符量就等价于明文。
- **为什么要确认 `ces.b` 是标准 MD5**：脱壳 dex 里 `ces.b(...)` 是最终哈希入口，反编译看到初始化常量（`0x67452301`/`0xefcdab89` 等）与 64 次循环即可判定为标准 MD5，无需再逐位移位复刻；这样签名就能在 Python 里一行 `hashlib.md5` 复现。
- **`st` 与 `sn` 的分工**：`st = str`，而 `str` 是"时间戳 + 随机数"求和得到的短串，负责防重放/时效；`sn = MD5(拼接串)` 负责防篡改，拼接串里的 `sn`（旧值或空）和 `str3`（布尔为 false 时为空串）参与其中，说明它还有一层"链式"防重放设计。

## 触发条件

- 目标 App 使用加固（本例腾讯加固）且关键签名逻辑在脱壳后的业务 dex 中。
- 设备可运行该 App（脱壳与 hook 都需要目标进程真实启动），已 root 或能在可调试环境运行 BlackDex/Frida。
- 签名参数参与请求头/查询串且服务端强校验（改动即失效），否则无需还原。
- 关键盐值在 native 库中以常量形式存在（未做运行时派生/混淆），否则需要进一步动态插桩。

## 利用步骤

1. **抓包定位参数**：刷新目标页面，对比多次请求，确认 `st`、`sn` 变化且手工改动后请求被拒（响应错误/空数据），确定这两个是必逆参数。
2. **查壳**：jadx 打开 APK 只看到少量壳类（`StubApp`、`com.tencent.StubShell` 之类），用 APK 查壳工具确认是腾讯加固。
3. **脱壳**：在设备上运行 BlackDex，把存储路径改到可读目录（如 `/sdcard/BlackDex`），选择目标包名开始脱壳；完成后目录里出现多个 `classes.dex`/`*.dex`，`adb pull` 到本地，全部拖进 jadx。
4. **定位签名点**：在脱壳后的 jadx 工程里搜 `sn=`，逐个看命中处，找到把 `st`、`sn` 塞进请求的代码，跟到生成处 `bmz$a`。
5. **hook 确认并取值**：先用 `Java.use('bmz$a')` hook `a(boolean)` 打印返回值，确认这里返回的正是 `sn`/`st`；再 hook `a(String, boolean)`，打印 `z`（布尔）、`this.e`、`this.j`、`this.c`、`this.l`。本例得到 `z=false`、`e="ifengnews"`、`j=2964`、`c="v0012czN2YDMwM2Y4QGM2ITN40AZgfr3r340gf"`、`l=""`，并推测同设备上不变。
6. **取 native 盐**：从 APK 的 `lib/<abi>/` 取出 `libifeng_secure.so`，或从设备 `/data/app/<pkg>/lib/` 拉取；IDA 载入后搜 `readMD5Key`，把函数签名第一个参数改成 `JNIEnv*` 以便识别 `NewStringUTF`，读出返回的常量串（本例 `acF%#*{_b1mQt@..ifvy`）。
7. **确认哈希**：跳到 `ces.b`，看初始化常量与轮函数，确认是标准 MD5。
8. **离线复现**：按 `MD5(版本号 + e + l + j + c + sn + str3 + key)` 拼串（`str3` 在布尔为 false 时为空串），`st` 用"时间戳 + 随机数"的求和串，构造请求验证。

## PoC

```javascript
// 1) 确认返回值就是 st/sn
Java.perform(function () {
    var bmz = Java.use('bmz$a');
    bmz.a.overload('boolean').implementation = function (z) {
        var r = this.a(z);
        console.log("result=>", r);
        return r;
    };
});

// 2) 打印闭包字段，拿到同设备不变的常量集合
Java.perform(function () {
    var bmz = Java.use('bmz$a');
    bmz.a.overload('java.lang.String', 'boolean').implementation = function (str, z) {
        console.log("z=>", z, "e=>", this.e, "j=>", this.j, "c=>", this.c, "l=>", this.l);
        return this.a(str, z);
    };
});
```

```python
import hashlib, time, random

KEY = "acF%#*{_b1mQt@..ifvy"        # 从 libifeng_secure.so 的 readMD5Key 取出
VERSION = "7.38.0"
E, L, J = "ifengnews", "", 2964
C = "v0012czN2YDMwM2Y4QGM2ITN40AZgfr3r340gf"

st = str(int(time.time()) + random.randint(0, 9999))   # 时间戳 + 随机数求和
str3 = ""                                              # 对应布尔为 false
sn_prev = ""                                           # 参与拼接的旧 sn（首次为空）

sn = hashlib.md5(
    (VERSION + E + L + str(J) + C + sn_prev + str3 + KEY).encode()
).hexdigest()
```

## 变体与关联

- **换脱壳机**：BlackDex 之外可用 frida-dexdump（spawn 模式）、反射调用 `DexFile` 批量 dump、或针对特定壳的 FART/FunDex；思路一致——拿运行期内存里的真 dex。
- **盐在 native 且非常量**：若 `readMD5Key` 参与运行时派生（读设备指纹、做简单变换），则需 Unicorn 模拟或 hook JNI 调用取返回值，而不是静态读常量。
- **hook 目标差异**：也可以 hook 最终哈希函数（`ces.b`）直接打印入参与结果，用"输入-输出对拍"反推拼接顺序，比逐个 hook 字段更省事但拿不到语义。
- **关联**：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（APKiD + frida-dexdump 的通用脱壳流程）、[[mobile-android-360-hardening-fundex-lsposed-dump]]（另一壳种的脱壳对照）、[[mobile-android-okhttp-addheader-stack-native-sign-locate]]（hook addHeader 堆栈定位签名的另一入口）、[[mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix]]（与本地 MD5 对拍确认算法）、[[mobile-android-jni-native-unicorn-emulation-constant-extraction]]（native 常量提取的进阶手段）。

## 检测与防御

- **客户端侧**：不要把签名盐以明文常量放在 so 里（`NewStringUTF` 直接返回字符串等于公开）；改用服务端下发/派生密钥、白盒加密或把盐与设备指纹绑定并做完整性校验；对 `readMD5Key` 这类方法做返回值混淆（分段异或、运行时拼装）。
- **服务端侧**：签名只做本地拼接 MD5 无法防重放，需加入时间窗、随机数与一次性 nonce 校验；避免"签名参与自身"的链式设计被离线复现。
- **检测视角**：脱壳与 hook 都需要目标进程被调试/注入，可通过 `ptrace` 自检、`/proc/self/maps` 扫描 frida-agent、检测 `Java.perform` 相关线程名等手段提高成本（但都可被绕过）。
- **边界**：本卡所有常量均来自原文复现结果，同一 App 的不同版本（不同 `this.j`/`this.c`）需重新 hook 取值；未验证服务端是否额外校验设备指纹。
