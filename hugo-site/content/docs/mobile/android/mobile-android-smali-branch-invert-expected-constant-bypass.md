---
id: mobile-android-smali-branch-invert-expected-constant-bypass
title: smali 改比较分支并给寄存器赋期望常量：if-ne 改 if-eq 绕过客户端输入相等校验
type: scenario
domain: mobile
path: mobile/android
technique: apk-smali-branch-invert-constant-bypass
tags:
- android
- apk
- smali
- repack
- reverse
- client-side-check
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V575
  verified_at: '2026-11-12T11:10:08+08:00'
  notes: 已对照原文与全部13张图核对：图04 Manifest debuggable=true；图05 aapt 启动 Activity com.moible.r15.main；图06 jadx 定位 main.this.info.getText()=="66.666s"；图07 getit 方法；图08 原始 smali const-string v2,"66.666s" + if-ne v0,v2,:cond_1；图09 原指令截图；图10 改为 if-eq v0,v2,:cond_1；图11 check-cast 后插入 const-string v5,"66.666s"，再 invoke-virtual {v4,v5}, Lcom/moible/r15/main;->getit；图12 应用显示 NSSCTF{1a74ee530fafa690dcddd0ce38260755}。卡片 PoC 的类名/寄存器结构与截图一致（类名做了占位替换）。已修正原理：if-ne 为不相等跳走，改 if-eq 后原本不相等（校验失败）的输入落入成功分支；比较的是引用而非内容。dedup 首候选为卡片自身，其余候选（VIP/实名/货币 smali 改包）场景与改法不同，无同链重复；dup-scan 无涉及本卡 pair。原文未标 APK/组件版本，未设 affected_versions；PoC 未在本机复跑。
url: /docs/mobile/android/mobile-android-smali-branch-invert-expected-constant-bypass/
draft: false
kb_aliases:
- smali if-ne 改 if-eq
- 跳转条件取反
- 给比较寄存器赋值
- APK 输入校验绕过
- Android Killer 改 smali
---

## 一句话结论

当 APK 的输入相等校验在客户端用 smali 的 `if-ne`/`if-eq` 分支实现时，用 apktool/Android Killer 反编译后把 `if-ne` 改成 `if-eq`（或反之），并在调用目标方法前用 `const-string` 直接给参数寄存器赋期望常量，重打包重签即可让原本不满足的校验通过并进入输出 flag/解锁功能的路径。

## 原理

- Dalvik smali 的条件分支指令 `if-ne vA, vB, :label`（不相等则跳转）与 `if-eq vA, vB, :label`（相等则跳转）决定控制流；把指令改成相反条件即可反转校验结果，不需要理解完整业务逻辑。
- 在 smali 中寄存器是显式的：Java 里 `getText() == "66.666s"` 这类比较在 smali 里表现为先 `move-result-object v0` 拿到对象，再 `const-string v2, "66.666s"`，最后 `if-ne v0, v2, :cond_x` 比较引用——不相等则跳到 `:cond_x` 跳过成功分支。把 `if-ne` 改成 `if-eq` 后变为相等才跳走，原本不相等（校验失败）的输入不再跳走，而是落入成功分支。
- 本题比较的是引用而不是内容（`getText()` 返回的 CharSequence 与字符串常量通常不是同一对象），所以校验几乎总是失败，仅靠分支取反就足以让任意输入落入成功路径。
- 若校验成功后调用的目标方法接收该字符串参数（如 `getit(String)` 从字符串中解出 flag），还需要在 `invoke-virtual` 前把参数寄存器显式赋值为期望常量（如 `const-string v5, "66.666s"`），避免传入用户输入或空值。
- 重打包可行的前提是 APK 未加固、无签名/完整性自校验；修改 smali 后需 apktool 重编译并用任意密钥重签才能安装。
- 该手法只改客户端判断，若服务端二次校验输入或返回真实结果，客户端绕过只影响本地展示。

## 触发条件

- APK 未加固，Java/Kotlin 逻辑可反编译为 smali，且关键校验未下沉到 native/服务端。
- 校验逻辑在 smali 中表现为可定位的条件跳转（`if-ne`/`if-eq`/`if-eqz`/`if-nez` 等）。
- 应用无签名校验或可绕过，允许重打包重签安装。
- 目标方法/输出路径可由本地构造的输入触发。

## 利用步骤

1. 用 jadx 反编译定位校验逻辑（如点击回调里的字符串比较与后续 `getit` 调用），记录对应类与方法。
2. 用 apktool/Android Killer 反编译 APK，打开对应 `.smali` 文件，定位比较处的 `const-string` 与 `if-ne` 指令。
3. 把 `if-ne v0, v2, :cond_x` 改为 `if-eq v0, v2, :cond_x`（按需要反转分支方向）。
4. 在调用目标方法前插入 `const-string vX, "<期望值>"`，把参数寄存器直接赋为期望常量（注意不要覆盖后续还要用的寄存器）。
5. apktool 重新编译、重新签名并安装，触发原入口观察是否进入成功分支/输出 flag。
6. 如仍不通过，检查寄存器编号与 `.locals` 范围、比较的是引用还是内容、以及是否有服务端二次校验。

## PoC

```smali
# 改前：getText() 与常量比较，不相等则跳走
const-string v2, "66.666s"
if-ne v0, v2, :cond_1

# 改后：条件取反，并在调用目标方法前直接给参数寄存器赋期望常量
const-string v2, "66.666s"
if-eq v0, v2, :cond_1
# ...
const-string v5, "66.666s"
invoke-virtual {v4, v5}, Lcom/example/main;->getit(Ljava/lang/String;)Ljava/lang/String;
```

说明：原文在 Android Killer 中把 `if-ne` 改为 `if-eq` 并把 `v5` 赋值为 `"66.666s"` 后重编译安装，点击按钮输出 flag；本库未复跑。

## 变体与关联

- 变体：直接改返回值常量（`const/4 v0, 0x0` → `0x1`）或删掉校验调用，适用于返回布尔的方法。
- 变体：`if-eqz`/`if-nez` 判空校验同样可以取反；多条件串联时逐条定位失败分支。
- 关联：[[mobile-android-smali-vip-check-force-true-repack]]（强制返回 true 绕过会员校验）、[[mobile-android-realname-antiaddiction-smali-bypass]]（实名门禁分支取反）、[[mobile-android-local-save-currency-smali-patch-repack]]（改 getter 常量）。
- 边界：native 层校验、服务端二次校验、签名自校验、加固壳会使改 smali 失效。

## 检测与防御

- 检测：APK 签名与官方不一致；dex 中出现与官方不同的分支指令/常量；重打包特征（zip 对齐、签名证书变化）。
- 防御：关键校验放服务端或 native 并做完整性/签名校验；使用加固与反调试；对客户端结果不信任，服务端二次验证。
