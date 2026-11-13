---
id: mobile-android-mpaas-rpcsignutil-signature-request-data-hook
title: mPaaS RPC 签名抓取：hook RpcSignUtil.signature 打印待签明文，配合 RpcInvoker.a 取 Request-Data 并 Base64 解码
type: scenario
domain: mobile
path: mobile/android
technique: mpaas-rpcsignutil-signature-request-data-hook
aliases:
- mPaaS 签名 hook
- RpcSignUtil hook
- RpcInvoker 抓包
- 支付宝 RPC 签名原文
- Request-Data 提取
tags:
- android
- frida
- hook
- mpaas
- rpc
- signature
- api-security
- mobile
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V589
  verified_at: '2026-11-12T14:26:19+08:00'
  notes: 已对照原文与3张截图核对：原文 a() 中 signPlain 拼接 Operation-Type=、Request-Data=(Base64.encodeToString(body,2))、Ts=，再调 RpcSignUtil.signature(context,appKey,isReq2Online,content,useSignAtlas)，卡内链路/参数/类名(com.alipay.mobile.common.transport.utils.RpcSignUtil、com.alipay.mobile.common.rpc.RpcInvoker、InnerRpcInvokeContext)与原文一致；img03 控制台可见 externalAppKey、content=Operation-Type=com.ifp.query...Request-Data=...&Ts=... 的 hook 效果。修正/澄清1处：原文最终 hook 脚本打印 body 用 Base64 flag 10(URL_SAFE|NO_WRAP)，而签名拼装处用 flag 2(NO_WRAP)，卡片 PoC 采用与签名串一致的 flag 2 并已在注释注明原文用 10(知识库与 staging 同步)；另卡片 PoC 保留原方法返回值，原文脚本只打印会改变业务，已在卡内说明。dedup：报告 new，top 候选为 OkHttp addHeader 定位、native getSign/udid/3DES、Frida RPC 主动调用签名、TreeMap MD5 等，均为其他网络栈或自实现签名，非同一链。全局 dup-scan 无本卡 pair。原文未标注版本，affected_versions 保持空。
---

## 一句话结论

使用支付宝 mPaaS（`com.alipay.mobile.common.*`）RPC 框架的 App，所有业务请求在发送前统一走 `RpcSignUtil.signature(context, externalAppKey, isReq2Online, content, pUseSignAtlas)`，其中 `content` 是 `Operation-Type=<操作类型>&Request-Data=<Base64 请求体>&Ts=<时间戳>` 拼接的待签明文；用 Frida hook 这个方法即可直接拿到签名原文，再 hook `RpcInvoker.a(String, byte[], String, InnerRpcInvokeContext, int[])` 的 `body` 参数并做 Base64 解码，即可得到明文请求体，用于接口分析与重放测试。

## 原理

- **mPaaS RPC 的签名入口**：业务层把操作类型、请求体和时间戳交给 `RpcInvoker`，后者在 `a(...)` 中拼出 `signPlain`（`Operation-Type`、`Request-Data`、`Ts` 三段，分隔符 `&`），再调用 `RpcSignUtil.signature` 交给安全 SDK（`SecurityUtil.signature`）计算签名；签名算法通常在 native/安全库里，静态还原成本高。
- **hook 参数即可拿到明文**：`signature` 的 `content` 参数就是完整待签字符串，`RpcSignUtil.signature` 是框架固定类名与公开方法，直接 `Java.classFactory.use("com.alipay.mobile.common.transport.utils.RpcSignUtil").signature.implementation` 打印各参数即可，无需逆签名算法。
- **Request-Data 的来源**：`RpcInvoker.a` 的 `body` 是请求体原始字节，框架内部用 `android.util.Base64.encodeToString(body, 2)`（NO_WRAP）编码后拼入签名明文；hook 该方法打印 `body` 并按相同 flag 解码，就能得到明文请求体，比从 `content` 字符串里二次截取更可靠。
- **触发条件由框架决定**：只有请求真正走到 RPC 签名阶段才产生日志；App 若使用其他网络栈（OkHttp 直连、H5）则不会经过这些类，需要改找对应入口。
- **与加固的关系**：这些框架类在加固壳解密后的 dex 中，直接 `Java.use` 可能找不到，需要先按加固 hook 卡切换 `Java.classFactory.loader`。

## 触发条件

- 目标 App 使用 mPaaS/支付宝 RPC 框架：反编译可见 `com.alipay.mobile.common.transport.utils.RpcSignUtil`、`com.alipay.mobile.common.rpc.RpcInvoker`、`SignRequest`、`SecurityUtil.signature` 等类。
- 已解决加固 App 的 ClassLoader 问题，能在壳解密后的 dex 上 `Java.classFactory.use`。
- Frida 可注入进程（spawn 或 attach 均可，attach 已启动进程时类已加载，通常无需等待）。
- 仅限授权测试环境；签名绕过/重放需遵守业务与法律边界。

## 利用步骤

1. jadx 搜索 `RpcSignUtil`/`signature`/`Operation-Type`，确认签名拼接逻辑与参数签名（不同 mPaaS 版本参数列表可能略有差异，按目标 APK 实际声明 hook）。
2. 处理加固：按 `tools-frida-application-attach-classloader-hardened-app-hook` 的方式拿到壳 ClassLoader 并设置 `Java.classFactory.loader`。
3. `Java.classFactory.use("com.alipay.mobile.common.transport.utils.RpcSignUtil")`，覆盖 `signature`：打印 `context`、`externalAppKey`、`isReq2Online`、`content`、`pUseSignAtlas`，并调用原方法返回结果以免破坏业务。
4. `Java.classFactory.use("com.alipay.mobile.common.rpc.RpcInvoker")`，覆盖 `a`（参数 `java.lang.String`、`[B`、`java.lang.String`、`com.alipay.mobile.common.rpc.transport.InnerRpcInvokeContext`、`[I`）：打印 `operationType`、Base64 后的 `body`、`ts`，并用 `android.util.Base64.encodeToString(body, 2)` 或等价实现解码明文。
5. 触发 App 的业务请求（登录、查询等），日志中出现 `Operation-Type`、`Request-Data`、`Ts` 与请求体明文。
6. 重放/改包时注意：签名由安全 SDK 生成，不能只改 `content`；若需要合法签名，可用 Frida RPC 主动调用原签名方法或走动态重签方案。

## PoC

```javascript
Java.perform(function () {
  var RpcSignUtil = Java.classFactory.use("com.alipay.mobile.common.transport.utils.RpcSignUtil");
  RpcSignUtil.signature.implementation = function (context, externalAppKey, isReq2Online, content, pUseSignAtlas) {
    console.log("[sign] externalAppKey:", externalAppKey);
    console.log("[sign] isReq2Online:", isReq2Online);
    console.log("[sign] pUseSignAtlas:", pUseSignAtlas);
    console.log("[sign] content:", content);   // Operation-Type=...&Request-Data=...&Ts=...
    return this.signature(context, externalAppKey, isReq2Online, content, pUseSignAtlas);
  };

  var RpcInvoker = Java.classFactory.use("com.alipay.mobile.common.rpc.RpcInvoker");
  RpcInvoker.a.overload('java.lang.String', '[B', 'java.lang.String',
                        'com.alipay.mobile.common.rpc.transport.InnerRpcInvokeContext', '[I')
    .implementation = function (operationType, body, ts, invokeContext, signCostPtr) {
      console.log("[rpc] operationType:", operationType, "ts:", ts);
      var B64 = Java.use("android.util.Base64");
      var b64 = B64.encodeToString(body, 2);   // 与签名串拼装处一致的 NO_WRAP；原文脚本打印时用的是 flag 10(URL_SAFE|NO_WRAP)
      console.log("[rpc] Request-Data(base64):", b64);
      return this.a(operationType, body, ts, invokeContext, signCostPtr);
    };
});
```

说明：原文脚本只打印不返回，会改变业务行为；上面的写法保留原调用返回值，仅用于观测。

## 变体与关联

- **签名入口变体**：不同 mPaaS 版本可能把 `signature` 包装在 `SecurityUtil.signature(SignRequest)`，或直接调用 native 方法；找不到 `RpcSignUtil` 时可按字符串 `Operation-Type=`/`Request-Data=` 交叉引用定位。
- **动态代签**：不还原签名算法，用 `java.use` 取到签名方法后由 Frida RPC 主动调用，给任意 `content` 生成签名，见 `tools-frida-rpc-active-call-native-sign-function-bypass-reverse`。
- **重签/透明加解密**：Burp 插件类方案见 `tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign`；App 侧验签逆向见 `mobile-android-mcp-assisted-sign-reverse-autodecoder`。
- **前置条件**：加固壳 loader 获取见 `tools-frida-application-attach-classloader-hardened-app-hook`；TLS pinning 会同时阻碍抓包，见 `mobile-android-ssl-pinning-bypass-cert-frida`。

## 检测与防御

- 检测：App/安全 SDK 可在签名方法内做 Frida 检测（线程名、maps、hook 框架特征），或对签名调用栈做完整性校验；服务端可校验 Ts 时效与请求体哈希，防止改包重放。
- 防御：签名密钥与算法放安全 SDK/native 并加壳；请求体关键字段做服务端业务校验；对重复 nonce/Ts 拒绝重放；不要把仅客户端签名当作唯一信任边界。
- 测试侧：hook 时务必保留原方法返回值，先在测试账号上验证业务不中断，再批量采集；日志中的请求体可能含个人信息，注意脱敏与授权范围。
