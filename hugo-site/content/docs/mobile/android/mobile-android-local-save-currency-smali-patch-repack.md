---
id: mobile-android-local-save-currency-smali-patch-repack
title: 本地存档型手游金币/钻石修改：改 getCoins 返回值或 loadStore 赋值后重打包重签
type: scenario
domain: mobile
path: mobile/android
technique: apk-smali-local-save-currency-patch
tags:
- android
- apk
- smali
- repack
- game-cheat
- sharedpreferences
- client-side-trust
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V561
  verified_at: '2026-11-12T07:40:35+08:00'
  notes: 已对照原文13005及21张媒体逐图核对：getCoins/loadStore 的 smali 修改点、方案A/B、888888金币/999999钻石截图与购买生效均一致；验证时修正了卡内将十进制常量误写成 0x66666/0x888888/0x999999 的数值错误（十六进制值与截图不符），并注明原文 getter 常量写作 66666 而截图显示 666 666 的出入；未本机重打包执行。
url: /docs/mobile/android/mobile-android-local-save-currency-smali-patch-repack/
draft: false
kb_aliases:
- 手游金币修改
- 钻石修改
- InAppPurchaseStore 改值
- SharedPreferences 改存档
- getCoins 返回值修改
- 单机游戏内购绕过
---

## 一句话结论

单机/弱联网游戏把金币、钻石直接存在本地 SharedPreferences 并由客户端类（本例 `InAppPurchaseStore`）读写时，用 jadx 定位 `getCoins`/`loadStore` 后经 apktool 反编译修改 smali：把 `getCoins` 的返回值改成固定常量（或删掉 `sget mCoins` 直接 `const v0, 666666`），或在 `loadStore` 中给 `mCoins`/`mGems` 的 `sput` 前插入固定值，重打包重签安装后启动即显示 888888 金币/999999 钻石，且能直接用于购买车辆等游戏内道具。

## 原理

- **客户端信任本地存档**：游戏的付费货币没有服务端账本校验，`InAppPurchaseStore.loadStore` 启动时从 SharedPreferences 读取 `numCoins`/`numGems` 到静态字段 `mCoins`/`mGems`，`saveStore` 再把静态字段写回；充值失败提示也印证数据只在本地。
- **改 getter 返回值**：`getCoins()` 逻辑为 `if (mModified) i = 0; else { ... if (mCoins > 0) ...; i = mCoins; } return i;`。把赋 0 的分支或 `i = mCoins` 改成固定大数，所有调用方（包括 UI 显示和购买校验）都拿到该值。
- **改存档加载赋值**：`loadStore` 里 `invoke-interface getInt` 后 `move-result v0` 再 `sput v0, mCoins`。在 `sput` 前插入 `const v0, 888888` 覆盖读出的值，效果等同"把存档改成大数"。
- **重打包为什么可行**：APK 未加固且无签名校验时，apktool 反编译→改 smali→重编译→用任意密钥重签→安装，系统只校验 APK 签名一致性（同一签名才能覆盖安装），不校验内容与官方一致；游戏内也没有对 APK 签名的自校验。
- **边界**：若货币由服务端记账、购买走服务端校验或存在签名/完整性校验，此方法只改本地显示，无法真正解锁（本场景属纯客户端作弊）。

## 触发条件

- APK 未加固（无壳、无反调试/签名校验），可直接 apktool 反编译；
- 游戏货币/解锁状态存在本地（SharedPreferences、本地文件、SQLite）且客户端自行判定；
- 攻击者可安装重签名的 APK（自用设备或允许侧载的环境）；
- 无服务端账本校验（弱联网或单机游戏）。

## 利用步骤

1. jadx 打开 APK，按关键词 `Coin`/`Gem`/`getIAPCoins` 搜索，定位 `InAppPurchaseStore` 与 `getCoins`。
2. `apktool d target.apk -o out` 反编译，打开 `smali*/com/.../InAppPurchaseStore.smali`。
3. 方案 A（改 getter）：把 `getCoins` 中 `const/4 v0, 0x0` 等返回 0 的分支改为 `const v0, 666666`（原文正文写作 66666，但实操截图显示 666 666，以截图为准；注意 `const/4` 只能表示 -8..7，赋大数必须用 `const`），或删除 `sget v0, ...->mCoins:I` 后直接 `const v0, 666666`。
4. 方案 B（改存档加载）：在 `loadStore` 中 `sput v0, ...->mCoins:I` 前插入 `const v0, 888888`；钻石同理在 `sput ...->mGems:I` 前插入 `const v0, 999999`。
5. `apktool b out -o patched.apk` 重编译，用 apksigner/jarsigner + zipalign 重签，卸载原版后安装（签名不同不能覆盖安装）。
6. 启动游戏确认货币数量，并尝试购买原本锁定/收费的道具验证是否真正生效。

## PoC

jadx 中看到的原始 smali（getCoins 返回 0 的分支）：

```smali
const/4 v2, 0x1
if-ne v0, v2, :cond_b
.line 113
const/4 v0, 0x0        # 改为 const v0, 666666
:goto_9
monitor-exit v1
return v0
```

删除静态字段读取直接赋常量：

```smali
# sget v0, Lcom/fingersoft/game/InAppPurchaseStore;->mCoins:I
const v0, 666666
```

loadStore 中改存档赋值：

```smali
invoke-interface {v0, v1, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I
move-result v0
const v0, 888888     # 新增：先覆盖为固定金币数
sput v0, Lcom/fingersoft/game/InAppPurchaseStore;->mCoins:I
# 钻石处同理新增 const v0, 999999 再 sput mGems
```

重打包后启动截图显示 888 888 金币 / 999 999 钻石，购买车辆提示"购买完成"。

注意：上述 smali 使用十进制立即数（smali 接受十进制），不要写成 `0x888888`/`0x999999`——它们分别是 8,947,848 和 10,066,329，与截图数值不符。

## 变体与关联

- 直接修改设备上 SharedPreferences XML 中 `numCoins`/`numGems` 的值（需 root），与改 `loadStore` 赋值等价；
- 用 Frida hook `getCoins`/`getCoins` 调用点直接返回大数，免重打包，适合有签名校验但可动态注入的场景；
- 桌面启动页/会员门禁类重打包绕过，见 [[mobile-android-apk-manifest-launcher-vip-charge-bypass]]；
- smali 改布尔权益判断，见 [[mobile-android-smali-vip-check-force-true-repack]]；
- 强制更新/版本校验重打包，见 [[mobile-android-apk-version-spoof-bypass-forced-update]]。

## 检测与防御

- 金币、钻石、道具解锁等付费资产必须由服务端记账并在购买/消费时校验，客户端只做展示；
- 接入 Google Play Billing 等服务端收据校验，拒绝本地伪造的购买记录；
- 对 APK 做签名校验/完整性校验（服务端下发签名摘要、Play Integrity），加壳或反调试提高改包成本；
- 服务端风控可检测异常货币增长、异常消费速率、同一账号多设备/重装行为；
- 客户端存档加密只能提高门槛，不能替代服务端权威数据源。
