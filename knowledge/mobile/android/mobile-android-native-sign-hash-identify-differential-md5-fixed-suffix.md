---
id: mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix
title: 未知 native 签名逆向：hook 逐层收窄到哈希函数后与本地 MD5 对拍确认，再定位「仅一个时间戳变量 + 固定后缀」的 auth 生成式
type: scenario
domain: mobile
path: mobile/android
technique: android-native-sign-hash-differential-identify-md5-fixed-suffix
aliases:
- native 签名算法识别
- auth 值生成分析
- hook 对拍识别 MD5
- 未知哈希函数识别
- MakeUrlClient native_newmakeUrl
- RegisterNatives 定位签名函数
- 固定盐后缀拼接
- 时间戳参与签名定位
tags:
- android
- reverse
- frida
- native
- signature
- md5
- hash-identification
- jni
- request-forgery
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:24:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片；调用链 RequestInterceptor → MakeUrlClient → JniMakeUrl.native_newmakeUrl（动态注册，导出表无符号）、hook RegisterNatives 定位、libmakeurl3.3.0.so 偏移 0x6168/sub_10898/sub_CD68/sub_CE10/sub_CC34、strArr2 元素 3 为 System.currentTimeMillis()/1000、sub_CC34 与本地 MD5 对拍、尾部固定常量串（形如 vOXGo3ad7hLHyTw4Zgu2blCjEBQDcx6z）均与正文一致；反调试绕过用 Florida 定制 server 也与原文一致。未验证点：未执行 hook；固定常量的完整性、前后缀顺序在截图中，未读图二次核对；卡内已注明仅到复刻公式、服务端是否接受未验证。原文无受影响版本。
---

## 一句话结论

当请求头里的 `auth` 由 native 层生成、静态看不出算法时，可以按「Java 拦截器 → MakeUrlClient → JNI 方法」顺着调用链用 Frida 逐层 hook 收窄，直到停在一个只做「字符串拼接 + 哈希」的小函数上；把这个函数的入参与输出成对 dump 下来，与本地 `md5`/`sha1` 对拍即可确认它是标准 MD5，再回溯调用链确认「除一个时间戳外全是常量」，最后发现结果尾部还硬编码拼接了一段固定常量串——至此 `auth` 可在离线的脚本里稳定复现，无需再还原控制流。

## 原理

- **定位 JNI 真实函数的必要性**：`Java_com_xxx_JniMakeUrl_native_newmakeUrl` 这类符号在导出表里常常不存在，因为 so 在 `JNI_OnLoad` 里用 `RegisterNatives` 动态注册；Hook `libart.so` 的 `RegisterNatives`、解析 `JNINativeMethod` 数组即可拿到「方法名 → 函数指针 → so 基址 + 偏移」，再在 IDA 里按偏移跳过去（偏移在 so 内固定，不受 ASLR 影响）。
- **为什么要逐层 hook 而不是死磕反汇编**：native 函数经过 OLLVM/控制流平坦化后，静态追一条「参数怎么变成 auth」的路径成本极高；而在每一层函数入口/出口 dump 参数与返回值，就能把「未知大函数」切成若干小函数，只在可疑的那一小段做静态分析，成本低一个数量级。
- **对拍（differential identify）为什么成立**：标准哈希实现是确定性的——同一个输入必须得到同一个摘要。取一次真实调用的入参 `x` 与该函数输出 `R(x)`，在本地对 `x` 依次尝试 `md5`、`sha1`、`md5(hex)`、`sha1(hex)` 等候选；若 `md5(x) == R(x)`（或 `R(x)` 的前 32 位等于它），即可确认算法与输入边界，剩余工作只是确定 `x` 由哪些字段按什么顺序拼成。
- **找唯一变量**：把 dump 出的多组入参逐字段比对，绝大多数字段在多次调用间完全相同（包名、渠道、设备常量、固定 key），只有个别字段变化；变化的那个是时间戳（`System.currentTimeMillis()/1000`，秒级，10 位；毫秒级 13 位），它决定了 auth 的时效性，必须按相同单位生成。
- **尾部固定常量的发现方式**：如果 `md5(入参) != 完整返回值`，先比较长度——返回串比 32 位长，说明除了哈希还拼了东西；把返回值的前 32 位与 `md5(入参)` 比较确认前半是哈希，剩余部分多次调用不变，即为硬编码后缀/前缀（本例形如 32 位字母数字常量串）；把它作为固定常量抄进脚本即可。
- **为什么最终能离线复现**：`auth = MD5(按固定顺序拼接的字段，其中仅时间戳变化) + 固定后缀`。此式不含设备指纹、不含服务端挑战值，因此只要时钟同步，任意请求都能算出合法 `auth`，从而脱离 App 直接构造请求。
- **边界**：本例只到「确认算法 + 复刻公式」，未在服务端验证伪造 `auth` 的请求是否被接受；若服务端还校验了与设备绑定的其它头或做过一次性 nonce，公式需要再扩展。

## 触发条件

- App 的签名/鉴权头由 native 生成，且 Java 层能追到对应的 `native` 方法声明与调用链（拦截器/网络层）。
- 能注入 Frida（含绕过 Frida 反调试：本例用去除特征的定制 frida-server 规避特征扫描与进程附加检测）。
- 签名函数的入参可由 App 自身代码路径产生（时间戳等），即「黑盒可调用」。
- 目标哈希未做非标准改造（未改初始向量/未加自定义轮），否则对拍会失败，需要退回静态分析。

## 利用步骤

1. 抓包确定需要复现的头（如 `auth`），并确认缺失/篡改后服务端拒绝，明确目标。
2. `jadx` 反编译 APK，全局搜头名/参数名，定位到添加该头的 `Interceptor`，往上追到 `MakeUrlClient`，再到 `JniMakeUrl.native_newmakeUrl`。
3. 判断是否为动态注册：`IDA` 打开对应 so，导出表里没有 `Java_..._native_newmakeUrl`；用 Hook `RegisterNatives` 的脚本打印全部注册项，得到 `native_newmakeUrl` 对应的 so、偏移与函数指针。
4. 若 hook 失败/无输出，先排查 Frida 反调试（特征字符串扫描、`/proc/self/maps`、端口、线程名、`TracerPid`），换用去掉部分特征的定制 server 再注入。
5. 在 `native_newmakeUrl` 上 hook 打印全部入参：找出其中多次调用间唯一变化的元素（时间戳），并回溯 Java 调用链确认它就是 `System.currentTimeMillis()/1000`。
6. 在返回值所在的子函数（示例为 `sub_10898`）上 hook，onEnter dump 入参、onLeave dump 返回值，确认「入参 → auth」确实在这一层完成。
7. 继续向被调用的更小子函数（示例 `sub_CD68`、`sub_CE10`、`sub_CC34`）下沉：`sub_CE10` 像格式化输出、`sub_CC34` 疑似哈希；对 `sub_CC34` 的入参与返回值做对拍，与本地 `md5` 比较命中即确认算法。
8. 把返回值与 `md5(入参)` 逐字节比较，确认前 32 位是哈希、尾部是多次调用不变的固定常量串。
9. 在脚本里复现：按 hook 到的拼接顺序拼串 → MD5（注意大小写）→ 拼接固定后缀 → 填进请求头；时钟与目标保持一致（秒级时间戳）。

## PoC

无独立 PoC（原文是逆向过程记录，未给出可直接运行的伪造请求脚本）。可复用的对拍与复现骨架如下：

```javascript
// 1) 动态注册定位：拿到 native_newmakeUrl 的 so 与偏移
//    （遍历 libart.so 符号、Hook RegisterNatives，解析 JNINativeMethod 的 name/sig/fnPtr）
// 2) 逐层 dump：父函数入参 → 子函数返回值
var base = Module.findBaseAddress("libmakeurl3.3.0.so");
Interceptor.attach(base.add(0x10898), {
  onEnter: function (a) { this.in = a[8]; },
  onLeave: function (r) { console.log("in:", hexdump(this.in), "out:", r.readUtf8String()); }
});
```

```python
# 3) 对拍确认算法 + 复刻 auth
import hashlib
raw = "<hook 到的拼接串，仅时间戳变化>"
digest = hashlib.md5(raw.encode()).hexdigest()      # 与 hook 返回值前 32 位比较
auth = digest + "<多次调用不变的 32 位固定常量后缀>"
```

原文的结论形态为「`auth = MD5(固定字段拼接 + 秒级时间戳) + 固定常量后缀`」，其中后缀在多次调用中恒定。

## 变体与关联

- **算法非标准时**：对拍全部失败则说明哈希被改造（自定义 S 盒、改 IV、加轮），此时把子函数的常量表 dump 出来与标准实现比对，或直接 hook 该函数当黑盒调用（见 [[tools-frida-rpc-active-call-native-sign-function-bypass-reverse]]）。
- **入参无法离线构造时**：若某个入参依赖设备指纹/服务端挑战，放弃离线复刻，改为在真机内 RPC 取签名。
- **定位手段的选择**：动态注册用 Frida 枚举（[[tools-frida-art-registernatives-dynamic-so-offset-locate]]），静态分析用 IDA 解析 `JNI_OnLoad` 里的注册表（[[mobile-android-jni-registernatives-static-real-function-locate]]），HTTP 头场景也可先 hook `addHeader` 打堆栈（[[mobile-android-okhttp-addheader-stack-native-sign-locate]]）。
- **反调试对抗**：本例用去特征的定制 frida-server；其它路径见 [[tools-frida-source-patch-anti-detection]]、[[mobile-android-frida-antidebug-dlsym-fake-pthread-create-offset-patch]]。
- **同族签名复刻**：[[mobile-android-token-md5-account-timestamp-sign-reverse]]（已知 MD5 结构的复刻）、[[mobile-android-c2-api-md5-salt-signature-replay]]（时间戳+固定盐）。

## 检测与防御

- **检测**：`libart.so` 的 `RegisterNatives` 被 attach、`Module.enumerateSymbolsSync` 遍历；进程内出现 Frida 特征（maps 中的 `frida`/`gadget`、`27042`、异常线程名、`TracerPid` 非 0）；同一账号在短时间内出现大量时间戳连续且可预测的签名请求。
- **加固**：把时间戳之外再引入服务端下发的一次性 nonce/挑战值并参与签名，使「纯离线复刻」失效；签名函数加入设备绑定因子（Keystore/Keychain 内不可导出的密钥、安全区签名）；对签名参数做完整性校验（不要把全部参数交给校验和拦截器外的代码重新拼）。
- **反逆向**：native 层控制流平坦化 + 字符串加密 + 关键常量运行时解密；Frida 检测常态化（多维度、多 so）。
- **服务端侧**：校验时间戳窗口（拒绝过期/超前请求）并对同账号高频请求做限速，可在签名被复刻后仍限制滥用规模。
