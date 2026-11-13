---
id: mobile-android-payment-result-code-client-check-bypass
title: Android 支付结果客户端校验绕过：jadx 定位 PayTask 返回码 9000 判断，smali 赋值 9000 或反转 if-eqz 免支付购买
type: scenario
domain: mobile
path: mobile/android
technique: android-alipay-paytask-result-code-smali-bypass
aliases:
- 支付宝 PayTask 9000
- 支付结果码 9000
- TextUtils.equals 9000
- 支付逻辑绕过
- 记牌器购买绕过
- MT 管理器 dex 编辑支付判断
- if-eqz 改 if-nez
- com.june.game.a.e
tags:
- android
- apk
- smali
- repack
- reverse
- payment-bypass
- alipay
- paysdk
- client-side-check
- jadx
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V667
  verified_at: '2026-11-13T08:31:41+08:00'
  notes: 已对照原文 17 图逐张核对：图01 MT 显示未加固/V1 签名/2.3.6(236)；图02-04 Activity 记录器 StartActivity→b.d→com.alipay.sdk.app.H5PayActivity；图05-08 记牌器搜索定位 b.v.a(int,int)、三处 onClick 传参 2/7/30、价格 2.0/6.0/20.0、调用 com.june.game.a.a.a().a(this.e,str,str2,d+"",new w(this))；图09-10 订单构造 new b(this, a2+&sign="..."&sign_type="RSA", cVar)，b.run() 内 new PayTask(...).pay(this.f550a,true) 并回调 f551b.a(pay)，查找用例指向 com.june.game.doudizhu.activities.b.w.a(String)；图11 w.a 中 new com.june.game.a.e(str).a() 后 TextUtils.equals(a2,"9000")，成功块 UMGameAgent.pay(...) 与 SharedPreferences；图12-13 com.alipay.sdk.app.j 枚举 SUCCEEDED(9000,处理成功)/FAILED(4000)/CANCELED(6001)；图14-15 smali 原 if-eqz v1,:cond_91 与两改法（move-result-object v0 后 const-string v0,"9000"；if-nez v1,:cond_91）；图16 不付款返回后记牌器可用并显示到期时间。卡内类名/方法名/常量与截图一致，两种改法描述成立。未验证点：PoC 未本机复跑；样本版本 2.3.6(236) 为目标 APP 版本非组件受影响区间，未设 affected_versions；无 CVE；frontmatter 无 sources/source_url。
---

# 一句话结论

当 Android 应用把支付宝 `PayTask.pay()` 的返回结果字符串解析成结果码、并仅在客户端用 `TextUtils.equals(a2, "9000")` 判断“支付成功”后发放道具时，用 jadx 沿“购买按钮 → 订单参数 → PayTask → 回调”定位到该判断，再用 MT 管理器 DEX 编辑器把解析结果寄存器强制赋值 `"9000"`（或在 smali 中把 `if-eqz` 改为 `if-nez`），重打包重签即可在跳转支付宝后不付款返回也完成购买（文章案例：单机斗地主记牌器，两种改法均生效）。

# 原理

- **支付调用链**：案例中点击“记牌器”弹窗的 2/7/30 天购买项，Listener 调用 `com.june.game.doudizhu.activities.b.v.a(int,int)`；后者按天数设置商品名与价格 `d`，调用 `com.june.game.a.a.a().a(context, str, str2, d+"", new w(this))` 构造订单参数（`a2 = a(str,str2,str3,str4)`，用 APK 内置的 RSA 私钥字符串 `f.a(a2, "MIICdQ...")` 生成 `sign`，拼成 `a2 + "&sign=\"...\"&sign_type=\"RSA\""`），再由 `com.june.game.a.b.run()` 执行 `new PayTask(activity).pay(orderInfo, true)`，回调 `this.f551b.a(pay)` 即 `com.june.game.doudizhu.activities.b.w.a(String)`。
- **成功判断**：`w.a(String)` 中先 `String a2 = new com.june.game.a.e(str).a();` 解析支付返回串，然后 `if (TextUtils.equals(a2, "9000")) { ... UMGameAgent.pay(...); ... }` 发放道具/开通记牌器。jadx 搜索 `9000` 可见其来自支付宝 SDK 枚举 `com.alipay.sdk.app.j`：`SUCCEEDED(9000,"处理成功")`、`FAILED(4000)`、`CANCELED(6001,"用户取消")` 等——9000 就是支付成功的 resultCode。
- **为什么可绕**：道具发放完全依赖客户端对 resultCode 的比较，属于“客户端信任支付结果”。把 `a2` 改成 `"9000"` 后 `TextUtils.equals` 恒真；或者反转分支让失败结果也进入成功块。案例为单机类应用（道具/到期时间写本地 SharedPreferences），服务端未复核，因此补丁后不付款返回也能开通，且记牌器功能与到期时间正常显示。
- **两种等价改法**（文章在同一张截图里同时演示）：
  - 方法一：在 `move-result-object v0`（a2）之后插入 `const-string v0, "9000"`，后续 `TextUtils.equals(v0,v1)` 恒真。
  - 方法二：把 `if-eqz v1, :cond_91`（equals 为 false 则跳过成功块）改为 `if-nez v1, :cond_91`（为 true 才跳走），使原本失败的结果落入成功分支。
- **前置条件**：APK 未加固（MT 管理器显示“未加固”），可直接 jadx 反编译与 DEX 编辑；有加固时需先脱壳（BlackDex/frida-dexdump 一类）。重打包后需重签（案例 V1 签名）。

# 触发条件

- 目标 APK 未加固且无重打包/签名完整性校验；DEX 可直接编辑或用 apktool 重编译。
- 支付成功判断在客户端完成：`PayTask`/支付 SDK 的返回码在本地解析并与成功码（Alipay 为 `9000`）比较，之后由客户端直接发放道具/权益。
- 道具发放逻辑不依赖服务端二次校验（单机游戏、本地道具或服务端信任客户端结果）。
- 能从 UI 或抓包定位到购买入口与回调类（案例用 MT 管理器 Activity 记录器确认购买跳到 `com.alipay.sdk.app.H5PayActivity`）。

# 利用步骤

1. 用 MT 管理器查看 APK 加固状态；未加固直接用 jadx 加载，加固则先按库内脱壳卡处理（BlackDex/frida-dexdump）。
2. 用 MT 的 Activity 记录器操作购买流程：点击记牌器 → 弹出 2/7/30 天购买 → 点击购买跳转 `com.alipay.sdk.app.H5PayActivity`，确认支付入口。
3. jadx 搜索业务关键词（如“记牌器”），定位 `com.june.game.doudizhu.activities.b.v.a(int,int)` 与三处调用（参数 2/7/30），继续跟进到订单构造函数与 `PayTask.pay(...)`。
4. 查看 `PayTask` 回调 `com.june.game.doudizhu.activities.b.w.a(String)`：`com.june.game.a.e(str).a()` 解析结果码后 `TextUtils.equals(a2,"9000")` 判断成功，成功块内调用 `UMGameAgent.pay(...)` 开通记牌器。
5. 搜索 `9000` 确认其为支付宝 SDK `ResultCode.SUCCEEDED`（`com.alipay.sdk.app.j`）。
6. MT 管理器 DEX 编辑器定位 `w.a`：方法一在 `move-result-object v0` 后插入 `const-string v0, "9000"`；方法二把 `if-eqz v1, :cond_91` 改为 `if-nez v1, :cond_91`。保存、重打包、重签安装。
7. 打开游戏点击购买，跳转支付宝后直接返回（不付款），记牌器开通且显示到期时间，验证两种改法均可用。

# PoC

```text
# jadx 原始判断（com.june.game.doudizhu.activities.b.w.a）
String a2 = new com.june.game.a.e(str).a();
if (TextUtils.equals(a2, "9000")) { ... UMGameAgent.pay(...); ... }

# 方法一：smali 中在解析结果后强制赋值（MT DEX 编辑器）
invoke-virtual {v0}, Lcom/june/game/a/e;->a()...
move-result-object v0
const-string v0, "9000"          # 新增：无论真实支付结果如何都当作成功

# 方法二：反转判断分支
if-eqz v1, :cond_91            # 原逻辑：equals=false 跳过成功块
if-nez v1, :cond_91            # 改为：equals=true 才跳转，失败结果落入成功块
```

# 变体与关联

- 与库内 `mobile-android-smali-branch-invert-expected-constant-bypass`（通用 if-ne/if-eq 反转 + 赋常量）、`mobile-android-smali-vip-check-force-true-repack`（会员 boolean 判断改真）、`mobile-android-apk-manifest-launcher-vip-charge-bypass` 等属同一类 smali 补丁手法，但本卡的业务语义是“支付结果码”，需要先沿 PayTask/回调链定位到结果码比较，而非直接改布尔方法。
- **内置签名私钥**：案例订单签名在客户端完成，APK 中内置 PKCS#8 RSA 私钥（`f.a(a2, "MIICdQ...")`，`sign_type=RSA`）。攻击者提取私钥后可离线伪造订单签名请求；文章未展开利用，但这是与支付逻辑并列的可复用风险点（签名/密钥不应放客户端）。
- 若服务端以支付平台异步通知/主动查询为准发放权益，客户端补丁只影响本地展示；本案例是单机本地道具，服务端不参与，所以能直接生效。
- 加固 APK 需先脱壳再打补丁（参见库内 BlackDex/frida-dexdump 脱壳卡），重打包后注意签名校验与so层完整性检查。

# 检测与防御

- 权益发放以服务端校验支付平台结果（异步通知验签 + 主动查询订单）为准，客户端只做结果展示，不信任 `PayTask` 返回码。
- 支付参数签名放到服务端，私钥绝不内置 APK；客户端只持有公钥或使用平台 SDK 的订单签名。
- 增加 APK 签名/完整性校验与运行环境检测（重打包、Hook、Root），结合平台侧风控（未支付订单发放、结果码异常分布）。
- 检测重打包：安装包签名与原厂商不一致、DEX 校验变化、`const-string "9000"` 出现在 `TextUtils.equals` 附近的 smali 特征、购买成功但支付平台无对应订单/金额。
