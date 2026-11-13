---
id: mobile-android-smali-isuserlogin-flag-branch-invert-bypass
title: smali 反转 SharedPreferences 登录标志判断：if-nez 改 if-eqz 批量改点跳过客户端登录门禁
type: scenario
domain: mobile
path: mobile/android
technique: apk-smali-sharedprefs-login-flag-branch-invert
aliases:
- isUserLogin 改 if-eqz
- 跳过客户端登录
- smali 登录门禁绕过
- SharedPreferences 本地标志反转
- APK 跳过登录弹窗
tags:
- android
- apk
- smali
- repack
- reverse
- client-side-check
- login-bypass
- sharedpreferences
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V640
  verified_at: '2026-11-13T02:37:20+08:00'
  notes: 已对照原文与15张图核对：图09 smali 确认为 sget-object MyApplication->a、const-string "isUserLogin"、const/4 v2,0x0、invoke-static Lcom/f0208/lebotv/g/f;->a(Context;String;Z)Z、move-result v0、if-nez v0,:cond_0；已据此把卡内 PoC 的类名/寄存器改为截图实际值（原 C0261f 为 jadx 反编译名），并注明批量反转策略与原文一致；登录逻辑图02-07（Dialog/C0320p、hashmap phone/password/uuid、/login、错误响应）、图10 登录成功响应、图11-15 HttpCanary 静态注入均与正文对应。未验证点：未复跑改包与重签；原文『可跳过登录但无法播放是后台数据问题』仅为作者推测；原文未标注应用版本。dedup：与 mobile-android-smali-branch-invert-expected-constant-bypass 的 likely_duplicate 判定不成立——该卡为 if-ne/if-eq 比较常量并赋期望值（CTF 输入相等校验），本卡为 if-nez/if-eqz 反转 SharedPreferences 登录标志（登录门禁场景），指令、目标与 PoC 均不同，属相关不同链，保留。
---

## 一句话结论

当 APK 把"是否已登录"存进 SharedPreferences（本例 `com.f0208.lebotv` 的 `isUserLogin`），业务代码用 `if (!C0261f.a(ctx, "isUserLogin", false)) { 弹登录框 }` 做门禁时，用 jadx 搜索提示文本定位到该判断，再在 smali 中把 `if-nez` 反转为 `if-eqz`（并把所有引用该判断的调用点一并反转），重打包重签后即可跳过客户端的登录拦截；能否真正播放/使用受服务端鉴权约束，本地绕过只影响客户端门禁。

## 原理

- `C0261f.a(Context, String, boolean)` 的实现是 `context.getSharedPreferences("com.f0208.lebotv", 0).getBoolean(str, z)`，即从本地 SharedPreferences 读取登录标志（默认 false）。
- Java 的 `if (!a(...))` 在 smali 中通常编译为 `invoke-static ... ->a(...)Z` + `move-result vX` + `if-nez vX, :cond_login_ok`：返回值非零（已登录）时跳到正常流程，否则落入弹登录框的分支。把 `if-nez` 改成 `if-eqz` 后条件反转，未登录也会进入正常流程。
- 混淆 App 中同一 helper 被多处调用且调用点分散，逐点分析耗时；由于对该 helper 的判断都表示"是否已登录"，可批量把所有 `isUserLogin` 相关 `if-nez` 反转，代价是可能改到与登录无关的判断（需重新测试）。
- 客户端登录门禁只信本地标志、不向服务端实时校验会话，是该方法成立的根本原因；但播放等核心接口若要求服务端 token，改包只能绕过 UI 层，不能凭空获得服务端权限。

## 触发条件

- APK 未加壳或壳可脱（文章用 MT 管理器查看确认无壳；jadx 能读出 Java 源码）。
- 登录门禁基于本地 SharedPreferences 布尔标志，且服务端未对每个功能强制校验会话。
- 具备 apktool/MT 管理器反编译、重打包、重签名能力；测试设备允许安装重签 APK。
- 若 App 有签名校验/完整性校验，需要额外绕过（本场景未涉及）。

## 利用步骤

1. 用 MT 管理器查看 APK 基本信息（包名、是否加壳），安装后打开 App，用 Activity 记录器观察启动链路（`SplashActivity` → `HomeActivity`），或在 `AndroidManifest.xml` 中确认入口 Activity。
2. 操作触发登录弹窗（如点开视频），记录弹窗文案（"账号登录"/"请登录后再操作"）。
3. jadx 打开 APK，全局搜索弹窗文案，定位登录 Dialog 类（`C0320p`/`Dialog` 封装）与触发它的功能代码。
4. 在功能代码中找到判断：`if (!C0261f.a((Context) MyApplication.f3171a, "isUserLogin", false))`；跟进 `C0261f.a` 确认是 SharedPreferences 读取。
5. apktool/MT 管理器反编译为 smali，搜索 `isUserLogin`，找到对应的 `if-nez vX, :cond_x`，改为 `if-eqz vX, :cond_x`。
6. 重新打开 App 测试：若仍弹登录，说明还有其他调用点未改；搜索所有引用该 helper/该字符串的 smali（如 `grep -r "isUserLogin"`），把相关 `if-nez` 全部反转（文章最终采用"全改"策略）。
7. 回编译、重签名、安装，验证登录门禁被跳过（文章验证 App 不再弹登录，但因后台数据不可用未能播放）。

## PoC

```smali
# 改造前：a(...) 返回 true（已登录）则跳过登录提示（录自原文图 09，实际混淆类为 com.f0208.lebotv.g.f）
sget-object v0, Lcom/f0208/lebotv/application/MyApplication;->a:Lcom/f0208/lebotv/application/MyApplication;
const-string v1, "isUserLogin"
const/4 v2, 0x0
invoke-static {v0, v1, v2}, Lcom/f0208/lebotv/g/f;->a(Landroid/content/Context;Ljava/lang/String;Z)Z
move-result v0
if-nez v0, :cond_0

# 改造后：条件反转，未登录也走正常流程
if-eqz v0, :cond_0
```

说明：寄存器编号、标签名按目标 APK 调整；jadx 中的 `C0261f.a(...)` 反编译名对应 smali 里的混淆类 `Lcom/f0208/lebotv/g/f;`，`isUserLogin` 字符串是定位锚点。不执行原文中的 APK，不进行重打包操作。

## 变体与关联

- 动态方案：Frida hook `C0261f.a` 强制返回 true（App 有反调试时改包更稳）；或 root 后直接用 `run-as`/备份恢复改写 SharedPreferences XML 把 `isUserLogin` 置 true（合理扩展）。
- 改响应方案：不改包，用 HttpCanary 静态注入把登录失败响应替换为登录成功响应，见 [[mobile-android-httpcanary-static-injection-member-response]]（同一"客户端信任"思路，作用于网络层）。
- 关联：smali 常量相等校验反转（if-ne/if-eq + const-string）见 [[mobile-android-smali-branch-invert-expected-constant-bypass]]；布尔门禁返回 true 解锁 VIP 见 [[mobile-android-smali-vip-check-force-true-repack]]。
- 变体：同类本地标志还有"首次启动""已付费""已实名"，均可按同一方法搜索字符串定位后反转。

## 检测与防御

- 检测（客户端安全）：APK 重签后签名与官方不一致；SharedPreferences 相关判断被改；服务端日志出现无有效 token 的播放/接口请求。
- 防御（开发方）：核心功能必须由服务端校验会话与权限，不能只依赖客户端 SharedPreferences 标志；对关键接口校验签名/设备指纹。
- 防御：APK 加壳、签名校验与完整性检测（SafetyNet/Play Integrity）；对重打包安装包做运行期校验。
- 防御（测试/分析侧）：仅对授权应用进行逆向与改包测试。
