---
id: mobile-android-sign-treemap-salts-both-ends-md5-uppercase
title: App _sign 逆向：TreeMap 参数 key+value 字典序拼接 + 固定 KEY_V2 首尾包裹 + MD5 大写
type: scenario
domain: mobile
path: mobile/android
technique: android-sign-treemap-salt-both-ends-md5-upper
tags:
- android
- reverse
- signature
- md5
- treemap
- frida
- hook
- api-reverse
- request-forgery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V454
  verified_at: '2026-11-10T02:25:41+08:00'
  notes: 已对照原文核对：图42 SignManager.signByType 按 i 选 KEY_V1/KEY_V2/KEY_SHARE/KEY_AUTOHOME（默认 KEY_V1）、sb.append(盐)+遍历 treeMap.keySet() 拼 key+value+再 append(盐)、encodeMD5(...).toUpperCase()，与卡一致；图24/26/27 lambda$initRequestCommonParams$0 在 checkNullParams 后 treeMap.put(KEY_SIGN, signByType(i,treeMap))，图23 用例列表、图18-21 _sign 定位（先 hook toSign 不执行，再定位 LaunchModel.KEY_SIGN）、图17/32 hook encodeMD5 可见明文 "W@oC!AH_6Ew1f6%8_appidatc.android..."，均支撑卡内定位流程与盐值。注意：抓包（图12/06）与图32 返回 TreeMap 中登录参数还含空值 signkey/type，原文 Python 示例与卡 PoC 未列出；复现实际请求签名时需以 hook 到的完整 TreeMap 为准，卡内步骤4/边界已提示重新 hook 确认，属原文示例简化而非卡错。与 token MD5(account+timestamp+sign)、AES-CBC header sign、native XOR 后缀等候选结构不同，dedup new 成立。原文无受影响版本区间，affected_versions 已 --clear。未在本机复跑。
url: /docs/mobile/android/mobile-android-sign-treemap-salts-both-ends-md5-uppercase/
draft: false
kb_aliases:
- _sign 签名逆向
- signByType 逆向
- TreeMap 签名
- KEY_V2 W@oC!AH_6Ew1f6%8
- lambda$initRequestCommonParams$0 hook
- 固定盐首尾拼接 MD5
- 汽车之家签名
---

## 一句话结论

App 的 `_sign` 由 `SignManager.INSTANCE.signByType(i, treeMap)` 生成：按类型 `i` 选一个固定盐串（KEY_V1/KEY_V2/KEY_SHARE/KEY_AUTOHOME，示例 `i=1` 用 `W@oC!AH_6Ew1f6%8`），拼成「盐 + TreeMap 中所有 key 与 value 依次拼接 + 盐」，再做 MD5 并转大写；TreeMap 保证 key 字典序，盐硬编码在客户端，因此 hook 公共参数构造方法或 encodeMD5 拿到一次明文即可离线复现任意请求的 `_sign`。

## 原理

- **签名函数**：`SignManager.signByType(int i, TreeMap<String,String> treeMap)` 先 `StringBuilder sb`，按 `i` 选择 `str`：`i==0 → KEY_V1`、`i==1 → KEY_V2`、`i==2 → KEY_SHARE`、`i==3 → KEY_AUTOHOME`（默认为 KEY_V1）；`sb.append(str)`；`for (String k : treeMap.keySet()) { sb.append(k); sb.append(treeMap.get(k)); }`；再 `sb.append(str)`；最后 `SecurityUtil.encodeMD5(sb.toString()).toUpperCase()`。
- **TreeMap 的顺序**：普通 HashMap 的遍历顺序不可控，而 `_sign` 的入参是 `TreeMap`，`keySet()` 按 key 的自然字典序迭代，所以拼接顺序是确定的（与 Python `sorted(dict.keys())` 等价）。这是能离线复现的前提。
- **公共参数构造**：`lambda$initRequestCommonParams$0(int i, TreeMap treeMap)` 会补全/校验 `_appid`、`channelid`、`appversion`、`udid`、`userkey` 等公共参数，然后 `treeMap.put(KEY_SIGN, SignManager.INSTANCE.signByType(i, treeMap))`；即 `_sign` 覆盖的是“除 `_sign` 自身外的全部业务+公共参数”。
- **定位过程**：jadx 搜 `_sign` 命中多个位置（AHAAPIHelper.toSignMap/toSign、LaunchModel.KEY_SIGN 等）；先 hook `AHAAPIHelper.toSign` 发现登录时不执行（不是该位置）；再按 `LaunchModel.KEY_SIGN = "_sign"` 的用例找到 `signByType(i, treeMap)`，hook `lambda$initRequestCommonParams$0` 确认 —— 该方法的返回 TreeMap 里出现 `_sign=0CAABE...`，说明命中。
- **hook 对拍**：同时 hook `SecurityUtil.encodeMD5` 可看到 MD5 的原始输入（如 `W@oC!AH_6Ew1f6%8_appidatc.androidappversion3.45.0channelid...`）与输出，直接验证“盐 + key+value + 盐”的拼接顺序和是否存在分隔符。
- **为什么能伪造**：签名算法、盐、参数顺序全部在客户端且无服务端密钥/nonce；服务端只能校验同一 MD5，因此任何能构造参数的人都能算出合法 `_sign`，实现请求重放/篡改（例如改价格、改设备标识、批量接口调用）。
- **边界**：不同接口可能用不同 `i`（盐不同）；参数值可能含 URL 编码/嵌套结构，需与客户端拼接前形态一致；若服务端另有时间戳/nonce/设备绑定头，需一并复现。

## 触发条件

- App 请求带 `_sign` 字段，值随参数变化；服务端校验通过后才能访问业务接口。
- APK 可反编译（未加固或已脱壳），能搜索 `_sign`/`signByType`/公共参数构造方法。
- 有 Frida/可调试环境，SSL Pinning 已绕过或未启用。
- 目标需要接口自动化、参数篡改验证或安全评估（授权场景）。

## 利用步骤

1. 抓包确认 `_sign` 存在，且请求参数（`_appid`、`appversion`、`channelid`、`pwd`、`udid`、`username` 等）与业务字段一同提交。
2. jadx 搜索 `_sign`：区分「参数名常量」与「实际签名调用」；关注 `treeMap.put(KEY_SIGN, SignManager.INSTANCE.signByType(i, treeMap))` 的调用点。
3. 找到公共参数构造方法（示例 `lambda$initRequestCommonParams$0(int i, TreeMap treeMap)`），记录 `i` 的来源与 treeMap 中会出现的全部 key。
4. Frida hook 公共参数方法，打印入参/返回 TreeMap（确认 `_sign` 生成位置）；再 hook `SecurityUtil.encodeMD5` 打印 MD5 输入/输出，确认盐值与拼接顺序。
5. 用 Python 复现：对参数字典按 key 字典序拼接 `key+value`，前后各加盐，`md5(...).upper()`；与抓包 `_sign` 对比一致。
6. 构造篡改后的参数重新计算 `_sign`，发送请求验证服务端是否接受；如要求时间戳/其它头，一并复现。

## PoC

```python
import hashlib

def md5_upper(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest().upper()

salt = "W@oC!AH_6Ew1f6%8"          # i=1 时的 KEY_V2；i=0/2/3 换对应常量
params = {
    "_appid": "atc.android",
    "appversion": "3.45.0",
    "channelid": "csy",
    "pwd": "e10adc3949ba59abbe56e057f20f883e",
    "udid": "<抓包值>",
    "username": "13111111111",
}
body = "".join(k + params[k] for k in sorted(params.keys()))
print(md5_upper(salt + body + salt))
```

Frida hook 关键位置：

```javascript
Java.perform(function () {
  var LaunchModel = Java.use("com.che168.autotradercloud.launch.model.LaunchModel");
  LaunchModel["lambda$initRequestCommonParams$0"].implementation = function (i, treeMap) {
    var res = this["lambda$initRequestCommonParams$0"](i, treeMap);
    console.log("i=", i, "treeMap=", res.toString());
    return res;
  };
  var SecurityUtil = Java.use("com.autohome.ahkit.utils.SecurityUtil");
  SecurityUtil.encodeMD5.implementation = function (s) {
    var r = this.encodeMD5(s);
    console.log("MD5 input:", s, "\nMD5 out:", r);
    return r;
  };
});
```

说明：示例参数按文章；`udid` 等动态值需从抓包/hook 获取。未在本机执行。

## 变体与关联

- [[mobile-android-token-md5-account-timestamp-sign-reverse]]：另一种 `MD5(account+timestamp+sign)` 签名，含时间戳单位坑；本卡是 TreeMap 全参数 + 盐首尾包裹。
- [[mobile-android-c2-api-md5-salt-signature-replay]]、[[mobile-android-native-sign-hash-identify-differential-md5-fixed-suffix]]：固定盐/固定后缀的签名复现与识别思路。
- [[mobile-android-udid-3des-jni-key-hook-fixed-iv]]：同 App 的 udid 生成算法，需与 `_sign` 一起复现才能构造完整请求。
- 变体：`i` 选不同盐；参数可能包含嵌套 JSON/数组，需按客户端实际字符串化方式拼接；可能存在大小写/分隔符/URL 编码差异。
- 边界：服务端增加时间戳、nonce、HMAC 或设备证明后，单纯复现此 MD5 不足以伪造；字段集合变化需重新 hook 确认。

## 检测与防御

- 检测（分析侧）：hook 公共参数构造与 encodeMD5，导出多组参数→签名对，验证拼接规则；检查不同 `i` 值对应盐。
- 检测（防御侧）：同一账号短时间大量请求、参数被修改但签名仍合法，说明签名算法已被还原；监控异常设备指纹/udid。
- 防御：客户端签名改为 HMAC/服务端下发密钥或挑战值，加入时间戳+nonce 并服务端校验一次性；不要把可复用的固定盐当安全边界；关键业务（改价、下单、支付）加服务端二次校验。
- 响应：确认签名密钥泄露范围，轮换密钥/升级协议，评估历史请求是否被伪造。
