---
id: mobile-android-frida-spdy-switch-disable-force-http-capture
title: Hook 私有协议开关强制 Android App 从 SPDY 降级到 HTTP，绕过 Charles/Fiddler 抓不到的限制
type: scenario
domain: mobile
path: mobile/android
technique: frida-hook-spdy-switch-force-http-downgrade
aliases:
- SPDY 开关
- SwitchConfig.A
- 强制降级 HTTP
- 私有协议抓包
- 淘系 MTOP 抓包
- Xposed setResult false
- Charles 抓包
tags:
- android
- frida
- xposed
- spdy
- private-protocol
- packet-capture
- charles
- downgrade
- hook
- reverse
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-7
  verified_at: '2026-11-08T01:15:54+08:00'
  notes: 已对照原文核对；原文图04显示 Hook 后 Charles 抓到 POST /gw/mtop.taobao.idlemtopsearch.search/1.0/ HTTP/1.1 完整明文请求头，降级打通证据充分；dedup为new（duplicate 0/related 0/new 20）、无同一 sink（Hook 私有协议开关布尔返回值强制协议降级）等价卡，dedup_review成立；与18259的RPC卡为不同链（协议层开关Hook vs 进程内主动调用加密函数取token），本篇C草稿已按同链reject；卡内PoC为最小化占位、未实际运行（文章为不可信数据），真实类名/包名与设备环境无法在此复现验证。
---

## 一句话结论

当 App（如淘系/闲鱼）用私有协议 SPDY 与服务端通信、导致 Charles/Fiddler 等基于 HTTP 代理的抓包工具看不到明文请求时，可在 jadx 中定位「是否启用 SPDY」的布尔开关方法（如 `mtopsdk.mtop.global.SwitchConfig.A()`），用 Frida/Xposed Hook 让它恒返回 false（或把 setter 入参改为 false），强制网络层回退到普通 HTTP/HTTPS，代理即可正常抓取并解密请求与响应。

## 原理

- 私有协议（SPDY / 自定义二进制帧）不经过系统 HTTP 代理的常规明文通道，传统抓包工具无法解析；但 App 通常同时保留「私有协议 + 普通 HTTP 回退」两套网络栈，由配置开关选择。
- 开关多由配置类的布尔 getter 控制：jadx 搜 `spdy` 可见 `SwitchConfig.A() boolean` 返回 `c.enableSpdy && b.enableSpdy`，以及 setter `a(boolean spdySwitchOpen)` 把值写入 `c.enableSpdy`；网络层按该布尔决定走 SPDY 还是普通 HTTP。
- 因此不必理解或解密私有协议，只需在 Java 层把「是否走私有协议」的判定改为 false，让 App 自己选择可抓包的 HTTP 路径——把协议层对抗转化为「一个可 Hook 的布尔返回值」。
- 用 `Java.use(...).A.overload().implementation = function(){ return false; }`（Frida）或 `XposedHelpers.findAndHookMethod(..., "A", beforeHookedMethod → param.setResult(false))`（Xposed）即可；`overload()` 用于在同名重载里选中无参 getter。

## 触发条件

- App 可反编译（未被加固彻底阻断）、可注入 Frida 或安装 Xposed 模块、未做 Hook 检测/完整性校验（或已绕过）。
- App 保留可切换的私有协议开关与普通 HTTP 回退路径（多数成熟 SDK 如此）。
- HTTPS 场景还需代理 CA 已受信任（SSL Pinning 需另行绕过）。

## 利用步骤

1. 用代理抓包发现请求不可见/为私有协议；jadx 打开 APK 文本搜索 `spdy` 等关键词。
2. 在命中结果里找「开启/是否开启 spdy」的开关类与方法（如 `mtopsdk.mtop.global.SwitchConfig` 的 `A()` / `a(boolean)`），确认其布尔语义。
3. 写 Frida 脚本 Hook 该 getter 恒返回 false（或用 Xposed `setResult(false)`）；必要时同时把 setter 入参改 false。
4. 启动 Hook 后重开 App 触发搜索等请求，Charles 应看到 `POST ... HTTP/1.1` 明文请求头与响应。
5. 之后即可按常规流程复现请求、逐个分析加密参数（x-sign / x-sgext / x-mini-wua / x-umt 等）。

## PoC

```javascript
Java.perform(function () {
  var SwitchConfig = Java.use('mtopsdk.mtop.global.SwitchConfig');
  SwitchConfig.A.overload().implementation = function () {
    return false;   // 强制不走 SPDY，回退 HTTP
  };
});
```

```java
// Xposed 等价写法（仅示意）
XposedHelpers.findAndHookMethod(
  XposedHelpers.findClass("mtopsdk.mtop.global.SwitchConfig", lpparam.classLoader),
  "A", new XC_MethodHook() {
    protected void beforeHookedMethod(MethodHookParam param) { param.setResult(false); }
  });
```

（最小化示意，类/方法名为占位，未执行任何 PoC。）

## 变体与关联

- 变体：若开关是 setter 型（`a(boolean)`），可 Hook 并把入参改为 false；若 getter 里是 `c.enableSpdy && b.enableSpdy` 多个开关，需同时处理或改最外层判定。
- 关联：降级成功后转入常规「请求头加密参数分析」链——Hook HashMap.put 打印堆栈定位签名生成函数（另有对应卡）、再 Frida RPC 主动调用生成函数批量取签名复现请求（另有对应卡）。
- 关联：与 SSL Pinning 绕过（库内另有卡）互补——本卡解决「协议层不可抓」，后者解决「HTTPS 证书校验不可解密」，二者常需同时使用。
- 边界：本卡只到「让流量可被代理抓取」，不含私有协议解密或签名算法还原。

## 检测与防御

- 检测：监控 `SwitchConfig` 等协议开关方法被 Hook、返回值被恒定改写、进程加载 Frida/Xposed 模块、同一 App 突然从私有协议回退到 HTTP。
- 防御：反调试 / Frida / Xposed 检测、协议开关读取做完整性校验与服务端协商校验（不允许客户端单方面降级）、私有协议与业务签名强绑定、证书绑定 + 关键逻辑下沉 native；服务端对异常降级/非私有协议请求做风控。
