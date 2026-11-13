---
id: tools-frida-hook-resources-getstring-dynamic-resource
title: Frida hook Resources.getString(int) 提取动态资源字符串：strings.xml 里找不到的 R.string.key 运行时直接打明文
type: scenario
domain: tools
path: tools/frida
technique: frida-hook-resources-getstring-runtime-string
aliases:
- hook Resources.getString
- 动态资源字符串提取
- R.string.key 运行时取值
- Android 资源解密 hook
- getString 重载 hook
- 资源字符串动态生成
tags:
- frida
- android
- resources
- getstring
- reverse
- dynamic-string
- java-hook
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V544
  verified_at: '2026-11-11T20:43:26+08:00'
  notes: 已通读content.md并逐张核对4张图：img01 JNI_OnLoad动态注册（off_26E8/sub_B18）、img02 sub_B18密文比较循环、img03 sub_AC4引用Rijndael_AES_LONG表（确认AES）、img04 CyberChef AES-ECB key=G>IkH<aHu5FE3GSV 解出hgame{df3972d1b09536096cc4dbc5c}。卡片核心技巧与原文一致：jadx看到getResources().getString(R.string.key)但values.xml找不到值→Frida hook android.content.res.Resources.getString(int) overload打印resourceId+返回值，拿到key 3e1fel（原文注释# 3e1fel），随后RC4解密用户名G>IkH<aHu5FE3GSV；卡内PoC与原文hook脚本等价，输出ID 2131427328为示例值（原文未截resource id，已标注示例）。补充核对：原文脚本先Java.perform再安装hook、implementation内调用this.getString并return，卡内写法语义一致。图片处理更正：worker在cards.json称4张图均小于1200px无需压缩，实际4张长边1680/1888/1291/1685均超1200，验证时已重新生成ingest/tmp/13123/img_small/01-04.jpg（最长边1200）并逐张读取，无读图失败。dedup：候选（frida-dexdump运行时密文、RegisterNatives动态注册、RC4 keystream等）均非hook资源字符串取key，verdict均为new；dup-scan无本卡pair；卡内3个关联wikilink均确认存在。CTF题无组件版本，affected_versions不设。
---

## 一句话结论

App 需要字符串时通常最终调用 `Resources.getString(int resourceId)`；当静态反编译在 `res/values/strings.xml` 里找不到 `R.string.key` 的真实值（被运行时解密、动态替换或资源混淆）时，用 Frida hook `android.content.res.Resources.getString(int)` 的 overload，打印 `resourceId` 与返回值，就能在调用发生的瞬间直接拿到运行时明文（本例拿到 RC4 的 key `3e1fel`），省去逆资源解密逻辑。

## 原理

- **资源字符串的最终出口**：Android 资源系统把字符串存在 resources.arsc，Java 层通过 `Resources.getString(int)` / `getText(int)` 读取；`Context.getString(int)` 在 `ContextImpl` 中委托给 `Resources`，所以 hook `Resources` 能覆盖绝大多数“从 R.string 取值”的调用。
- **静态看不到的原因**：资源可能被加密/压缩/混淆（字符串池被替换、运行时用解密结果覆盖），或代码用 `getIdentifier` 动态拼名字、或值来自服务端/本地配置；但无论值怎么生成，Java 层要使用它时一般仍会走 `getString`（或 `getText`），这就是抓手。
- **hook 点选择**：`Java.use("android.content.res.Resources")`，对 `getString` 的 `overload("int")` 实现自定义 implementation；先调用原实现（`this.getString(resourceId)`），再记录入参 id 与返回值。也可同时 hook `getText(int)`、`getString(int, Object...)` 处理格式化字符串。
- **价值**：不侵入业务逻辑，不需要定位解密函数或算法；一次 hook 能捕获 App 生命周期内所有资源字符串读取，配合 `getResourceName(id)` 还能反查资源名与包名，快速定位关键字符串（密钥、URL、校验字）。
- **边界**：若 App 绕过 Resources 直接从 AssetManager/native 读字符串，或用自定义 Resources 子类且未被 Java.use 覆盖，则 hook 不到；多 dex/动态加载的类对 `Java.use` 无影响（Resources 是框架类）。

## 触发条件

- 目标 App 可被 Frida 注入（可 root/模拟器，或已打包 frida-gadget）。
- App 使用 `R.string.*` 资源字符串，且静态资源里值可疑/为空/加密。
- 已定位到读取该资源的 Java 代码或知道资源 id（也可用 hook 全量观察）。
- 仅用于授权测试与自有应用分析。

## 利用步骤

1. 在 jadx 中定位使用处（如 `getResources().getString(R.string.key)`），记录资源名；若 strings.xml 里是占位/密文，确认需要运行时取值。
2. 编写 Frida 脚本 hook `android.content.res.Resources.getString` 的 `overload("int")`，打印 resourceId 与结果。
3. `frida -U -f <package> -l hook.js --no-pause` 启动并触发目标界面（输入/点击），观察日志中的返回值。
4. 如无输出，补充 hook `getText(int)`/`getString(int, Object[])`，或 hook `ContextWrapper.getString(int)` 判断是否走了别的入口。
5. 拿到明文后回到静态分析继续（本例用 key 做 RC4 解密）；也可把资源 id 转名字（`getResourceName`）确认对应关系。
6. 记录结果；对多个资源 id 可循环触发界面收集全量字符串。

## PoC

```javascript
function hook_key() {
  var Resources = Java.use("android.content.res.Resources");
  Resources.getString.overload("int").implementation = function (resourceId) {
    console.log("getString called with resource ID: " + resourceId);
    var result = this.getString(resourceId);
    console.log("Result of getString: " + result);
    return result;
  };
}
setImmediate(function () { Java.perform(hook_key); });
```

```text
# 运行输出（示例）
getString called with resource ID: 2131427328
Result of getString: 3e1fel        # R.string.key 的运行时明文
```

```javascript
// 可选的补充 hook：文本资源与格式化字符串
var R = Java.use("android.content.res.Resources");
R.getText.overload("int").implementation = function (id) {
  var t = this.getText(id);
  console.log("[getText] " + id + " -> " + t);
  return t;
};
R.getString.overload("int", "[Ljava.lang.Object;").implementation = function (id, args) {
  var s = this.getString(id, args);
  console.log("[getString fmt] " + id + " -> " + s);
  return s;
};
```

## 变体与关联

- 变体：hook `ContextWrapper.getString`/`getText` 或在 `Activity` 实例上直接调用，用于确认调用链；也可 hook `Resources.getIdentifier` 观察动态资源名。
- 变体：资源字符串在 native 层解密时，改用 hook native 解密函数或直接从内存搜字符串；Resources hook 只覆盖 Java 资源读取路径。
- 变体：批量提取可用 `Resources.getResourceName(id)` 把 id 映射回 `包名:type/name`，便于整理。
- 关联：[[tools-frida-art-registernatives-dynamic-so-offset-locate]]（同一 CTF 题中定位 so 内动态注册函数）、[[ctf-reverse-android-frida-keystream-recovery-bypass-rc4-compare]]（RC4 密文比对场景，本篇用拿到的 key 做离线 RC4 解密）、[[tools-frida-java-hook-static-instance-field-choose]]（Java 层 hook 基础）。

## 检测与防御

- 检测：App 侧检测 Frida（端口、线程、maps 中的 frida-agent、Java 栈特征）；资源字符串被 hook 读取本身难以直接检测，可辅以完整性/调试检测。
- 防御：敏感字符串不要放资源或运行时明文持有过久；核心校验用 native + 混淆 + 服务端校验；使用 R8/资源混淆并避免在 Java 层长期保存密钥；加入反调试/反 hook。
- 说明：本文是 Frida hook 资源字符串取运行时明文的分析技巧（CTF/授权逆向），severity low；仅用于授权测试与自有应用分析。
