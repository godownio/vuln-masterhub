---
id: ctf-reverse-android-native-luajit-xor-keystream-cancel
title: APK 原生校验黑盒反推：Hook Java eq 与 native strcmp，用 XOR 线性关系消去 keystream
type: scenario
domain: ctf
path: ctf/reverse
technique: android-native-luajit-xor-keystream-cancel
aliases:
- antiapk
- Frida hook strcmp
- LuaJIT 字节码校验
- RSB 函数
- keystream 抵消
- 一次观测反推 flag
tags:
- ctf
- reverse
- android
- apk
- frida
- luajit
- native
- xor
- keystream
- strcmp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:49:54+08:00'
  notes: 已对照原文 antiapk 节及内嵌 base64 图核对：Java MainActivity 仅校验长度16并 loadLibrary("anti")；native Java_..._eq 是伪校验（strcmp("flag{thisflag}")，15字符，16位输入不可达），真正校验为 LuaJIT RSB 路径；JNI_OnLoad 读 TracerPid/kill 反调试，sub_9950 写 LuaJIT 字节码(1B4C4A)、sub_9E08 pushString("82ns65ig1")+pcall、sub_9470 以 seed "qs7j2ps2" 生成128字节子密钥、strcmp 常量为 "95 01 3C ... 73 "（带尾空格）、clock 反调试均与原文/内嵌图一致；flag=TARGET XOR RSB_out XOR input。已把该诱饵比较与“真正校验在LuaJIT RSB”补入卡内。未验证点：线性关系为原文经验假设，Frida脚本未在本机对样本复跑；frontmatter无sources/source_url。
---

## 一句话结论

当 APK 的原生校验把 16 字节输入送进 LuaJIT 脚本的 `RSB` 函数，得到 `RSB_out = input XOR KS`，再与目标常量 `TARGET = flag XOR KS` 做 `strcmp` 时，不必逆出 `KS` 或还原 LuaJIT 字节码：用 Frida hook Java `eq` 拿到 input、hook native `strcmp` 拿到 RSB_out，按 `flag = TARGET XOR RSB_out XOR input` 一次观测即可还原 flag。

## 原理

- 校验关系是逐字节 XOR 的线性关系：同一 keystream `KS` 同时作用于用户输入和真实 flag。`RSB_out = input XOR KS`，`TARGET = flag XOR KS`；两式异或后 `KS` 抵消，得到 `flag = TARGET XOR RSB_out XOR input`。
- 因此逆向目标不是“还原 LuaJIT 字节码/ARX 变换”，而是“在运行时观测一次输入和输出”。`RSB` 内部即使有 128 字节子密钥、16 轮 ARX 和常量表，只要观测点满足线性假设，就不必展开。
- 观测点：Java 层 `MainActivity.eq(String)` 接收用户输入；native 层 `strcmp` 的两个参数中，一个是目标常量 hex 串，另一个是 `RSB` 的输出。Frida 同时 hook 两处即可把 input 与 RSB_out 配对。
- 注意：native 的 `Java_..._eq` 内还有一处 `strcmp("flag{thisflag}", input)` 诱饵比较（该字符串 15 字符，Activity 的 16 位长度检查使其不可达），不要误把它当作真正校验；真正校验走 LuaJIT `RSB` + 目标常量 `strcmp`。
- 目标常量可从 native 代码/字节码中提取：本题为 `95 01 3C 79 F8 4A 84 85 B6 2F 2E 9A F4 AB A5 73`（16 字节）。
- 前提：`RSB` 对输入是逐字节 XOR（或至少在观测点满足 `out = in XOR KS`）。若 `RSB` 含非线性变换，需要多次 chosen-input 观测/差分建模；若 keystream 依赖输入，线性抵消不成立。
- 边界：样本可能有 `kill`/`clock` 反调试、模拟器检测、完整性校验；需要 patch 或用 Frida 替换相关函数后再观测。

## 触发条件

- 已拿到 APK，能 jadx 反编译并定位 Java 校验入口与 `System.loadLibrary` 加载的 native 库。
- native 库中能看到 `JNI_OnLoad`、LuaJIT 字节码写入（文件头 `1B 4C 4A`）与 `strcmp` 目标常量。
- 目标设备/模拟器可运行 App，且能注入 Frida（root/可调试）。
- 校验关系在观测点满足 XOR 线性假设。

## 利用步骤

1. jadx 打开 APK，确认 MainActivity 的 onClick 只做长度 16 检查并加载 `libanti.so`；native eq 中的 `flag{thisflag}` 比较是诱饵，真正校验在 LuaJIT `RSB`。
2. IDA 分析 `JNI_OnLoad`/`sub_9950`：确认把 `unk_1C000` 写成 LuaJIT 字节码、调用 `RSB(input)`、`toString` 后与目标常量 `strcmp`。
3. 从 native/字节码提取 `TARGET` 16 字节。
4. 编写 Frida 脚本：patch `kill`/`clock` 反调试；hook `MainActivity.eq` 记录 input；hook `strcmp`，当参数等于 `TARGET` hex 串时记录另一个参数（RSB_out）。
5. 在 App 输入任意 16 字符触发校验；用脚本计算 `flag = TARGET XOR RSB_out XOR input`，输出 16 字符 flag。
6. 若结果不可打印，检查字节序/hex 空格/输入编码（ASCII），或改用多次观测验证线性关系。

## PoC

```javascript
// Frida 关键逻辑（精简）
Java.perform(function () {
  const TARGET_HEX = "95 01 3C 79 F8 4A 84 85 B6 2F 2E 9A F4 AB A5 73 ";
  const TARGET = TARGET_HEX.trim().split(/\s+/).map(x => parseInt(x, 16));
  let lastInput = null, solved = false;

  const Main = Java.use('com.zhuotong.antiapk.MainActivity');
  Main.eq.overload('java.lang.String').implementation = function (s) {
    lastInput = s ? ('' + s) : null;
    return this.eq(s);
  };

  const strcmp = Module.findExportByName(null, "strcmp");
  Interceptor.attach(strcmp, {
    onEnter(args) { this.a = args[0]; this.b = args[1]; },
    onLeave() {
      if (solved) return;
      const A = Memory.readCString(this.a), B = Memory.readCString(this.b);
      const other = (A === TARGET_HEX) ? B : (B === TARGET_HEX ? A : null);
      if (!other || !lastInput || lastInput.length !== 16) return;
      const out = other.trim().split(/\s+/).map(x => parseInt(x, 16));
      const inp = Array.from(lastInput).map(c => c.charCodeAt(0) & 0xff);
      const flag = TARGET.map((v, i) => String.fromCharCode(v ^ out[i] ^ inp[i])).join('');
      console.log('flag =', flag);
      solved = true;
    }
  });
});
```

## 变体与关联

- 变体：比较函数换成 `strncmp`/`memcmp`/`strcasecmp` 时 hook 对应导出；Java 层比较换成 `Objects.equals`/`String.equals` 时 hook 对应方法。
- 变体：若 keystream 非线性或依赖输入，可用 chosen-input 差分、查表、符号执行（angr/Unicorn）或直接 dump LuaJIT 字节码后用 luajit-decompiler 还原。
- 变体：LuaJIT 字节码可 dump 后静态分析 `RSB` 的 ARX/表操作，确认线性关系；也可以用 Frida 直接调用 `RSB` 做 oracle。
- 关联：[[ctf-reverse-python-str-eq-monkey-patch-comparison-log]]（Hook 比较函数直接记录正确答案）、[[ctf-reverse-android-apk-environment-state-derived-keystream]]（keystream 依赖 APK 环境状态）、[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（Unicorn 离线 oracle）。
- 边界：`RSB` 可能对输入做非线性/带进位变换，线性假设需验证；Frida 注入可能被反调试/完整性校验阻断；LuaJIT 字节码版本需与运行时匹配。

## 检测与防御

- **检测（CTF）**：APK 含 `libanti.so`、LuaJIT 字节码、JNI `strcmp` 目标常量；Java 层只做长度检查；运行时可用 Frida 观测输入/输出。
- **修复（真实 App）**：不要在客户端用固定 keystream 的 XOR 做授权校验；改为服务端校验或非对称签名；关键逻辑放入 native 并加反调试/完整性校验只能提高成本，不能根治。
- **加固**：检测 Frida/Xposed（端口、maps、线程名、hook 痕迹）、模拟器/调试器；对 `strcmp` 等比较函数做内联/白盒；使用代码混淆与字符串加密；定期轮换密钥。
