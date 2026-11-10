---
id: tools-frida-rpc-active-call-native-sign-function-bypass-reverse
title: Frida RPC 主动调用 App 内加密函数批量取 anti-token/签名值，绕过 native 算法逆向复现请求
type: scenario
domain: tools
path: tools/frida
technique: frida-rpc-active-call-encrypt-function
aliases:
- Frida RPC 主动调用
- rpc.exports
- 绕过算法逆向
- 动态取签名
- 批量取 token
- 请求复现
- 黑盒调用加密函数
tags:
- frida
- rpc
- android
- native
- anti-token
- signature
- request-replay
- reverse
- automation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-7
  verified_at: '2026-11-08T01:10:37+08:00'
  notes: 已对照原文核对；原文图12显示RPC取值后请求成功返回商品JSON，打通证据充分；dedup的duplicate候选为卡自身（同名staging草稿命中已入库卡），其余19个候选均为new且无同sink卡，dedup_review成立；卡内PoC为最小化占位、未实际运行（文章为不可信数据），真实包名/类名与设备环境无法在此复现验证。
---

## 一句话结论

当 App 的加密/风控参数（anti-token、sign）由 native 层或强混淆算法生成、静态还原不现实时，可在 App 进程内用 Frida 的 `Java.perform` **主动调用**该生成函数（按其签名构造 Context、时间戳等参数），把结果经 `rpc.exports` 暴露给外部 Python，每次请求实时取值填入 header，从而在完全不还原算法的前提下复现并批量构造合法请求。

## 原理

- 加密函数本身在目标 App 进程里是「可执行的黑盒」：只要能构造出它要求的入参，就能让它输出正确的 token，无需理解内部逻辑；`Java.use` 可直接取得类并调用其静态/实例方法。
- 参数一致性是关键：本文函数需要 `(Context, Long)`，脚本借用 App 自有类（`BaseApplication.getContext()`、`TimeStamp.getRealLocalTime().longValue()`、`Long.valueOf`）生成，保证与真实调用的上下文/时间一致，避免外部伪造值导致 token 被服务端拒绝。
- `rpc.exports = { anti: hook_anti_token }` 把 JS 函数注册为 RPC 端点，Frida 的 Python 绑定通过 `script.exports.anti()` 跨进程同步拿到返回值，于是「生成 token」从 App 内部能力变成外部可循环调用的服务。
- 因此对抗点从「逆向算法」转移为「维持一个可注入的 App 进程」，适合以数据抓取/请求复现为目的；若目标是完全离线还原算法，则仍需 IDA 分析 so（属另一条链）。

## 触发条件

- 已定位到生成该参数的 Java/native 方法（如经 HashMap.put 堆栈定位到 `SecureNative.deviceInfo2`）。
- 目标 App 可在已 root/可控设备上运行并注入 Frida，且未阻断主动调用（无反调试/完整性校验，或已绕过）。
- 能用 App 自有类构造出与真实调用一致的参数（上下文、时间戳等）。

## 利用步骤

1. 抓包确认缺失该头时服务端返回不正确，明确要复现的目标头。
2. 用 Hook 打印调用栈 + jadx 定位生成函数（如 `deviceInfo2(context, Long)`），确认其所在类与参数类型。
3. 写 Frida 脚本：`Java.perform` 内 `Java.use` 取类，用 App 自有类构造入参，调用生成函数，返回字符串。
4. `rpc.exports` 导出；Python 端 `frida.get_usb_device().attach(pkg)` → `create_script` → `script.load()` → `script.exports.anti()` 取值。
5. 把返回值填入 `headers["anti-token"]`，用 `requests.post` 复现搜索/业务请求；循环调用即可批量取值。

## PoC

```javascript
function hook_anti_token() {
  var result = null;
  Java.perform(function () {
    var SecureNative = Java.use("com.xunmeng.pinduoduo.secure.SecureNative");
    var BaseApplication = Java.use("com.xunmeng.pinduoduo.basekit.BaseApplication");
    var context = BaseApplication.getContext();
    var TimeStamp = Java.use("com.xunmeng.pinduoduo.basekit.util.TimeStamp");
    var ts = TimeStamp.getRealLocalTime().longValue();
    result = SecureNative.deviceInfo2(context, Java.use("java.lang.Long").valueOf(ts));
  });
  return result;
}
rpc.exports = { anti: hook_anti_token };
```

```python
device = frida.get_usb_device().attach("<包名>")
script = device.create_script(open("zxc.js", encoding="utf-8").read())
script.load()
anti_token = script.exports.anti()
headers["anti-token"] = anti_token
```

（最小化示意，包名/类名为占位，未执行任何 PoC。）

## 变体与关联

- 变体：若生成函数在 native 层且无 Java 入口，可用 `NativeFunction` 按「基址 + 偏移」主动调用（库内另有对应卡）。
- 关联：与「Burp/autoDecoder 自动重签」「Hook buildHeaders 改参」同属「绕过算法还原、动态取值」族；差别是本卡用 RPC 把进程内函数直接暴露给外部脚本，可脱离 Burp 批量调用。
- 关联：前置步骤是「Hook 请求头写入 + 打印堆栈定位生成点」（另有对应卡）；本卡不触及 native 算法本身，遇到 OLLVM 强混淆时是更省力的替代路径。

## 检测与防御

- 检测：同一 App 进程高频调用加密函数、出现 `rpc.exports`/Frida 脚本加载、非 UI 触发的批量请求、服务端看到同一设备指纹高频取 token。
- 防御：反调试/Frida 检测、对加密函数加入调用来源与频率校验、把 token 与设备/会话/行为强绑定并在服务端风控、关键逻辑下沉 native 且做完整性校验；服务端限制单设备请求频率与异常 token 复用。
