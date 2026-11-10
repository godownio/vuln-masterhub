---
id: mobile-android-frida-result-getter-callcount-dfs-char-bruteforce
title: 逐字符独立加密的 Frida DFS 爆破：hook 结果对象 getter 按调用计数取中间值
type: scenario
domain: mobile
path: mobile/android
technique: frida-getter-callcount-oracle-per-char-dfs-bruteforce
tags:
- android
- frida
- reverse
- bruteforce
- dfs
- hook
- java
- obfuscation
- ctf
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:47:42+08:00'
  notes: 已对照原文核对：round(int[],String) 逐字符 32 轮、iArr 常量表与初始 i=33、密文 {352,646,752,882,65,0,122,0,0,7,350,360}、length!=12 判否、Result.getNum 计数截取第 idx 字符中间值、DFS 枚举多前像与 MakePath.encode 取 Context 均与正文一致；原文未给 CVE/版本；本次核对未读取图片，仅依据正文。未验证点：Frida 脚本未在本机运行，PoC 为按原脚本整理
url: /docs/mobile/android/mobile-android-frida-result-getter-callcount-dfs-char-bruteforce/
draft: false
kb_aliases:
- 单字符加密爆破
- getNum 调用计数取值
- Frida DFS 求 flag
- Result 对象中间值提取
- 逐字符独立加密
---

## 一句话结论

当校验函数对 flag **逐字符独立加密**（每个字符经过固定轮数的小状态机/VM 运算，字符之间不互相影响）时，不必逆出等价算法：用 Frida `Java.use` 加载目标类，hook 结果对象的 getter（如 `Result.getNum`），按「第 i 个字符 × 固定轮数」的调用计数把该字符的最终中间值截下来，与密文数组逐位比较，配合 DFS 即可在字符集内枚举出完整 flag；同一字符可能对应多个密文前像，所以要 DFS 而不是简单映射。

## 原理

- **逐字符独立 ⇒ 可分解**：若 `encrypt(flag)` 的实现是 `for each char: state = f(state, char)` 且每个字符的状态机只依赖该字符与固定初始状态（本例初始 `i = 33`、`iArr` 为常量表），那么第 i 个输出字节只与第 i 个明文字符有关。爆破空间从 `62^12` 降到 `12 × 62`。
- **中间值比最终布尔值信息量大**：只拿到 `round(...) == true/false` 时，枚举要跑完整长度才能判定；而 hook 结果 getter 能直接读到「第 i 个字符算完后的数值」，与目标数组 `[352, 646, 752, ...]` 逐位比对即可在 O(1) 内判断某字符候选是否命中。
- **为什么要按调用计数取值**：一次 `round(input)` 调用里，getter 会被调用 `12 × 32 = 384` 次（12 字符 × 32 轮），无法从返回值本身区分「属于第几个字符」。用计数器 `num` 累加调用次数，当 `num == 32 × (已确定长度 + 1)` 时取到的就是第 `idx` 个字符的最终值，其余调用只透传。
- **DFS 而非贪心**：多个明文字符可能映射到同一密文值（`(x % 5)` 之类的分支选择 + 取模运算存在碰撞），因此每层要收集**所有**命中的候选字符，再深搜下一层；任一路径走通即得 flag。
- **补齐长度避免越界**：为只确定前 k 个字符的输入补占位符（如 `*`）凑满 12 位，让 `round` 正常跑完，但只读取第 k 个字符对应的那个中间值。
- **前置**：目标为 Android Java 层实现（或可被 Frida 调用的 Java 类），校验函数与结果类未被混淆到无法 `Java.use` 的程度，且能构造合法输入对象（如 `MakePath` 需要 `Context`，用 `ActivityThread.currentApplication().getApplicationContext()` 取）。

## 触发条件

- 校验逻辑为「逐字符独立加密 + 与固定密文数组比较」，字符集已知且较小（字母、数字、下划线等）。
- 能在设备上附加 Frida（可 spawn/attach），并能 `Java.use` 到校验类与结果类（类名/方法名可读，或已通过脱壳还原）。
- 结果对象通过 getter 暴露中间值（`getNum`/`getValue`/字段），或可 hook 到等价的中间函数返回值。
- 目标进程允许 hook（无强反调试/完整性校验，或已绕过）。

## 利用步骤

1. 反编译定位校验入口：找出 `round(int[], String)` 一类方法，确认字符循环是「外层遍历字符、内层固定轮数」且内层状态不跨字符传递（本例内层 32 轮，起始索引 `i = 33` 由常量表决定）。
2. 确认密文数组（如 `{352, 646, 752, 882, 65, 0, 122, 0, 0, 7, 350, 360}`）与 flag 长度（`length != 12` 直接返回 false）。
3. 写 Frida 脚本：`Java.use` 目标类，构造实例与必要参数（`Context` 从 `ActivityThread` 取），准备好输入数组。
4. hook 结果类的 getter，用闭包计数器累计调用次数；当 `num % (32 * (len+1)) == 0 && num / (32 * (len+1)) == 1` 时把本次返回值记为该位置的结果。
5. 对当前位置遍历字符集，构造「已确定前缀 + 候选字符 + 占位符补齐」的测试串，调用校验函数，比较截获的值与密文数组对应项；相等的候选全部收集。
6. 对候选递归 DFS 到下一位置；长度等于 flag 长度时输出结果并逐层回传终止。
7. 用拿到的 flag 在原始程序中验证（`round` 返回 true）。

## PoC

```javascript
Java.perform(function () {
  var RoundClass = Java.use('com.example.demo.Round');
  var roundInstance = RoundClass.$new();
  var ResultClass = Java.use('com.example.demo.Round$Result');
  var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var box = Java.use('com.example.demo.MakePath').$new().encode(ctx, 'dummy_input');

  var charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_';
  var target = [352, 646, 752, 882, 65, 0, 122, 0, 0, 7, 350, 360];
  var num = 0, captured = 0;

  function dfs(len, prefix) {
    if (len === 12) { console.log('flag: ' + prefix); return true; }
    var hits = [];
    for (var i = 0; i < charset.length; i++) {
      var test = prefix + charset[i] + '*'.repeat(12 - prefix.length - 1);
      num = 0;
      var n = 32 * (prefix.length + 1);
      ResultClass.getNum.implementation = function () {
        var v = this.getNum();
        num += 1;
        if (num === n) captured = v;      // 第 len 个字符算完时的中间值
        return v;
      };
      roundInstance.round(box, test);
      if (target[prefix.length] === captured) hits.push(charset[i]);
    }
    for (var j = 0; j < hits.length; j++) {
      if (dfs(len + 1, prefix + hits[j])) return true;
    }
    return false;
  }

  dfs(0, '');
});
```

```text
预期：每层打印候选集合，最终输出 12 位 flag；把该 flag 输入原程序应返回 true。
单字符命中多个候选时 DFS 会回溯，因此需保留全部 hits 而不是只取第一个。
```

## 变体与关联

- 变体（无 Frida）：把反编译出的 `Round.add/sub/xor/shl/shr` 与 `round()` 直接翻译成 Python/Java，离线跑同一 DFS，效果等价且更快（本例正文也指出可以直接复制代码到 Java 跑）。
- 变体（中间值不可 hook）：只暴露布尔返回值时，退化为「按位置枚举 + 只看最终 true」的组合爆炸，此时需先猜出一部分字符（如已知 flag 前缀）再逐段确定。
- 变体（跨字符依赖）：若状态机把上一字符的结果带入下一字符（链式状态），逐字符分解失效，需要改为整体搜索或先逆出状态转移。
- 关联：[[ctf-reverse-vm-instrumentation-instruction-count-bruteforce]]（同为用插桩计数当 oracle 的爆破，那张卡用的是指令执行计数定位比较点，本卡是 Java 层结果 getter 的调用次数 + 逐字符独立加密的分解前提）、[[mobile-android-runtime-ciphertext-frida-dexdump-java-char-rc4-aes]]（同样在运行时取真实中间量而非静态常量）。
- 边界：若字符集未知或包含 Unicode/随机盐，枚举空间不可控；若 `round` 带随机性或全局状态（跨调用累积），同一输入两次结果不同，计数截取会失效。

## 检测与防御

- 防御（应用侧）：不要把「逐字符独立加密」当作校验强度——它让爆破从指数降到线性。应使用带盐的哈希、整串参与的 MAC，并让校验结果不暴露中间值。
- 反调试：检测 Frida（端口、`frida-server` 进程、`/proc/self/maps` 中的 `frida-agent`、`Java.use` 相关的 hook 痕迹）、校验关键方法是否被 inline hook、对结果类做混淆/内联以去掉可 hook 的 getter。
- 检测：进程被附加后短时间内校验函数被调用数百次、参数长度固定且末尾充满占位符；同一方法的高频调用来自非 UI 线程。
- 检测/审计：Java 层校验若能在纯计算层面被复刻，说明其安全边界只能依赖服务端二次校验，客户端校验不应作为唯一防线。
