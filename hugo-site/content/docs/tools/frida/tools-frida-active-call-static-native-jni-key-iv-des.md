---
id: tools-frida-active-call-static-native-jni-key-iv-des
title: Frida 主动调用 JNI 静态 native 方法导出 DES key/iv：Java.use 直接调 getkey/getiv，无需 hook 或逆向 so
type: scenario
domain: tools
path: tools/frida
technique: frida-active-call-static-native-jni-key-iv
tags:
- frida
- android
- jni
- native
- des
- ctf
- key-extract
- crypto
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:26:42+08:00'
  notes: 已对照原文与图17-20核对：jni 类 static native getiv/getkey、2.js 直接 Java.use(...).getkey() 输出 A8UdWaeq、getiv 输出 wf3DLups、CyberChef From Base64+DES CBC 解密一致；图片16反编译显示 DES/CBC/PKCS5Padding 与 Arrays.copyOf(str2,8)，key/iv 8 字节，卡内按 DES-CBC 描述正确(反编译同时出现 AES 字样属原文代码不一致)；与 mobile-android-frida-hook-native-key-material-precomputed-mapping(hook 返回值)在触发方式/PoC 上不同；dup-scan 早于建卡；未复跑 PoC
url: /docs/tools/frida/tools-frida-active-call-static-native-jni-key-iv-des/
draft: false
kb_aliases:
- Frida 调用 native 方法
- getkey getiv
- static native 主动调用
- JNI 密钥材料提取
- DES CBC 解密 CTF
- Java.use 调 JNI 方法
---

## 一句话结论

当 Java 层声明了 `public static native String getkey()/getiv()`（实现藏在 so 里）而校验逻辑在 Java 层用 DES/CBC 比较密文时，不需要 hook、不需要触发业务、也不需要逆向 so：`Java.use("包名.jni")` 拿到类包装后直接 `jni.getkey()` / `jni.getiv()` 主动调用，就会经 ART 的 JNI 桥进入 so 中的实现并返回密钥材料；拿到 key/iv 后用 CyberChef 或脚本按 `DES/CBC/PKCS5Padding` 解目标密文即可还原合法输入。

## 原理

- **Java 层声明的 native 方法仍是可调用的 Method**：`static native` 只是表示实现由 JNI 提供，ART 在类加载时绑定对应 so（本例 `System.loadLibrary("Secret_entrance")`），Java 侧调用点经 JNI 桥进入 native 实现。Frida 的 `Java.use` 包装器暴露的正是这个 Method，因此可以直接调用并取得返回值——与调用普通静态 Java 方法在脚本写法上没有区别。
- **为什么比 NativeFunction 省事**：用 `NativeFunction`/`Interceptor` 走 native 路线要先定位 so、解析导出名或偏移、自己处理 JNIEnv/jstring 转换；而经 Java 包装器调用时，ART 负责加载 so、绑定符号和 JNI 类型转换，只要方法签名无参或参数可构造就能直接拿到 Java 类型返回值。
- **为什么比 hook 省事**：hook 需要目标方法被业务真实调用一次才有输出；`getkey()/getiv()` 这类纯函数无副作用，主动调用在任何时刻都能取值，不必先触发校验、也不必构造合法输入。
- **解密侧**：反编译可见 `Cipher.getInstance("DES/CBC/PKCS5Padding")`、`new SecretKeySpec(key, ...)`、`new IvParameterSpec(iv)`，因此 key 8 字节、iv 8 字节；密文是 Base64 字符串常量，Base64 解码后 DES-CBC 解密即得明文（明文即通过校验的输入，或按题目要求拼成 flag）。

## 触发条件

- APK 的 Java 层存在返回 key/iv/盐值的 `static native` 方法，且名字与用途可从 jadx/JEB 反编译的调用点（如 `inspect()` 内 `jni.getkey()`、`jni.getiv()`）确认。
- 设备/模拟器可运行 frida-server 并 attach；应用未做阻止注入的强反调试。
- 已知密文比对位置与算法参数（模式、填充、Base64 编码）。

## 利用步骤

1. jadx 打开 APK，定位校验函数（如 `inspect(String)`）：确认它把输入做 `DES/CBC/PKCS5Padding` 加密后与 Base64 常量比较，key/iv 来自 `jni.getkey()`、`jni.getiv()`。
2. 确认 key/iv 方法是 `static native`，找到其声明类（如 `com.example.re11113.jni`）与 `System.loadLibrary` 的 so 名。
3. 写 Frida 脚本 `Java.use(声明类)` 后直接调用两个方法，打印返回值。
4. 用 CyberChef（From Base64 → DES Decrypt，Key/IV 以 UTF8 输入，Mode CBC）或 Python `pycryptodome` 解目标密文。
5. 得到明文后按题目格式提交；若校验是"输入加密后等于密文"，该明文就是应提交的输入。

## PoC

Frida 脚本（无 hook，直接主动调用）：

```javascript
Java.perform(function () {
  var jni = Java.use("com.example.re11113.jni");
  console.log("key=" + jni.getkey());
  console.log("iv=" + jni.getiv());
});
```

运行（attach 前台应用并加载脚本）：

```bash
frida -UF -l keyiv.js
```

本例输出 `key=A8UdWaeq`、`iv=wf3DLups`。随后离线解密（CyberChef）：

```text
From Base64
DES Decrypt
  Key: A8UdWaeq   (UTF8)
  IV:  wf3DLups   (UTF8)
  Mode: CBC
  Input: Raw
```

Python 等价写法：

```python
import base64
from Crypto.Cipher import DES
ct = base64.b64decode("Jqs1HrdVtgJrRs2QAp+FEVdwRPNLswrnykD/sZMivmjGRKUMVIC/rw==")
pt = DES.new(b"A8UdWaeq", DES.MODE_CBC, iv=b"wf3DLups").decrypt(ct)
print(pt)
```

## 变体与关联

- 变体：key/iv 方法不是静态、需要实例时，可 `Java.use(类).$new()` 构造实例后调用，或 `Java.choose` 枚举已有实例。
- 变体：若 key/iv 只有在业务调用时才生成（依赖运行时状态），改为 hook 该方法打印返回值而不是主动调用；见 [[mobile-android-frida-hook-native-key-material-precomputed-mapping]]。
- 变体：需要直接调 so 中未导出/非 JNI 声明函数时，才用 `Module.findBaseAddress + 偏移` 与 `NativeFunction`，见 [[tools-frida-native-hook-export-unexport-retval-constructor]]。
- 变体：需要批量调用并对外提供取值接口时用 `rpc.exports`，见 [[tools-frida-rpc-active-call-native-sign-function-bypass-reverse]]。
- 关联：objection 的 `watch class_method --dump-return` 也能在 Java 边界观察 native 方法返回值，见 [[tools-frida-objection-watch-class-method-dump-return]]。

## 检测与防御

- 分析侧信号：反编译中 `static native` 且无参、返回 String 的 `getkey/getiv/getsecret` 一类方法，通常就是硬编码密钥材料的出口；调用点直接出现在校验函数里。
- 防守侧：不要把静态密钥放在客户端；密钥由服务端下发或基于设备/会话动态派生；关键校验放服务端；加壳/反调试/RASP 提高 Frida attach 成本；对 Java 层 native 方法返回值做完整性校验的意义有限，核心是不要把敏感材料送进客户端。
- 局限：强反调试/壳会让 attach 失败；主动调用只适用于方法可在当前上下文安全执行（无参或参数易构造）的情况。
