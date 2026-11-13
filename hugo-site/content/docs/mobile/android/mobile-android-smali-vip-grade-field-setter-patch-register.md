---
id: mobile-android-smali-vip-grade-field-setter-patch-register
title: smali 改 VIP 字段 vip_grade="1" 解锁会员：setter 参数寄存器 p1 与 const-string p/v 陷阱
type: scenario
domain: mobile
path: mobile/android
technique: android-smali-vip-field-setter-patch
tags:
- android
- apk
- smali
- repack
- vip
- entitlement-bypass
- register
- reverse
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:12:00+08:00'
  notes: 对照原文与13张本地截图：img11/12 显示 UserInfo 的 getVip_grade/p setVip_grade、isVip() 返回 getIntVipLevel()>0、getIntVipLevel() 返回 getVipLevelInt(this.vip_grade)，与卡片判定链一致；img13 为 isVip 的 smali if-lez + :cond_8 const/4 v0,0x1 改法。原文关于 const-string 写入 p0 覆盖 this 导致闪退、改用参数寄存器 p1 的寄存器陷阱描述与卡片一致（该 setter 补丁原文仅文字描述、无截图，卡内 PoC 为按文字重建）。原文仅确认修正后可正常安装，未附 VIP 功能解锁截图，卡内 confidence medium 并注明边界，合理。原文未标版本，affected_versions 为空正确。与 mobile-android-smali-vip-check-force-true-repack（布尔方法返回值补丁）补丁点不同且新增寄存器陷阱要点，按 append_scenario 保留。
url: /docs/mobile/android/mobile-android-smali-vip-grade-field-setter-patch-register/
draft: false
kb_aliases:
- smali 改 vip_grade
- setVip_grade 赋值
- UserInfo vip_grade
- smali 参数寄存器 p1
- const-string p0 闪退
- 重打包解锁 VIP
---

## 一句话结论

当 VIP 等级是 `UserInfo` 里的字符串字段 `vip_grade`，且 `isVip()` 通过 `getIntVipLevel() > 0` 间接判断时，可在 `setVip_grade(String)` 的 smali 开头强制写入 `"1"` 使 VIP 判定恒真；关键坑是实例方法中 `p0` 是 `this`、第一个参数在 `p1`，把 `const-string` 写进 `p0`（或让工具改写成 `const-string p0`）会破坏 `this` 导致安装后闪退，正确写法是 `const-string p1, "1"` 再 `iput-object p1, p0, ...->vip_grade`。

## 原理

- **字段与判定链**：`UserInfo` 有 `private String vip_grade`，`getVip_grade()/setVip_grade(String)` 只是普通 getter/setter；`isVip()` 返回 `getIntVipLevel() > 0`，而 `getIntVipLevel()` 返回 `getVipLevelInt(this.vip_grade)`（把字符串等级转成整数）。因此只要 `vip_grade` 落在正整数区间（如 `"1"`），`isVip()` 就为 true。
- **改 setter 为什么有效**：登录/注册返回 UserInfo 后，框架会调用 `setVip_grade` 把服务端下发的等级写入对象；在 setter 入口把字段固定写成 `"1"`，后续无论服务端返回什么，内存中的 VIP 等级都是非 0，所有读取该字段的客户端判定都会被满足。
- **smali 寄存器模型坑**：实例方法 `.method public setVip_grade(Ljava/lang/String;)V` 的寄存器分配里 `p0 = this`、`p1 = 第一个参数`。写 `const-string v0, "1"; iput-object v0, p0, ...` 时若 `v0` 是合法局部寄存器则可用；但不少编辑器/工具在保存时会把它重写成 `const-string p0, "1"`，随后 `iput-object p0, p0, ...` 先把 `this` 覆盖成字符串，再访问字段直接抛异常/闪退。原文的修正就是改用参数寄存器 `p1`。
- **为什么必须用 p 寄存器而不是随便借 v 寄存器**：setter 本身只有一个参数且常用于赋值，直接复用参数寄存器 `p1` 最安全；借 `v` 寄存器时要注意 `.locals` 声明数量，超出或覆盖后续要用的局部寄存器同样会崩。
- **替代改法**：直接改 `isVip()` 的判断跳转（如 `if-lez v0, :cond_8` 的方向或 `:cond_8` 下的 `const/4 v0, 0x0` 改为 `0x1`），或改 `getIntVipLevel()` 返回值；两者与改 setter 等价，但影响面不同。
- **边界**：原文只确认修正寄存器后可以正常安装，未给出 VIP 功能解锁的截图；若功能接口在服务端二次校验权益、或 VIP 状态还依赖其它字段（到期时间、购买记录），仅改 `vip_grade` 可能只解锁 UI。客户端字段修改无法绕过服务端鉴权。

## 触发条件

- APK 未加固或可脱壳，`UserInfo`/VIP 判定方法可反编译为 smali。
- VIP 等级由客户端字段/方法决定，功能门禁读取本地判定，服务端未对每个受限动作二次校验。
- 允许重打包重签安装（无签名/完整性校验，或可绕过）。

## 利用步骤

1. jadx 打开 APK，搜索 `vip_grade`、`isVip`、`getIntVipLevel`、`getVipLevelInt`，确认字段类型与判定链（string → int → >0）。
2. 记录 `setVip_grade` 的签名与 smali 方法头，确认 `.locals` 数量与寄存器分配（`p0=this`、`p1=String`）。
3. `apktool d target.apk`，打开 `UserInfo.smali`，在 `setVip_grade` 方法开头插入：
   ```smali
   const-string p1, "1"
   iput-object p1, p0, Lcom/<pkg>/entity/bean/UserInfo;->vip_grade:Ljava/lang/String;
   ```
   保留原有赋值逻辑亦可（新值会被覆盖为 `"1"`）。
4. 若还有其它等级 setter（如 `setVip_level`），按同样方式处理；或改 `isVip()` 的失败分支 `const/4 v0, 0x0` → `0x1`。
5. `apktool b` 回编译、重签、`zipalign`、卸载重装；验证应用能启动（不闪退）且 VIP 相关界面/功能是否放开。
6. 若闪退，检查是否是 `const-string p0` 覆盖了 `this`、`.locals` 不足或寄存器冲突；若功能仍受限，检查服务端二次校验与其它 VIP 字段。

## PoC

```smali
# UserInfo.smali —— setVip_grade 方法内（示意）
.method public setVip_grade(Ljava/lang/String;)V
    .locals 0          # 按样本；若用 v 寄存器需相应增大

    const-string p1, "1"
    iput-object p1, p0, Lcom/example/entity/bean/UserInfo;->vip_grade:Ljava/lang/String;

    # 原赋值逻辑
    iput-object p1, p0, Lcom/example/entity/bean/UserInfo;->vip_grade:Ljava/lang/String;
    return-void
.end method
```

```smali
# 替代：isVip() 失败分支强制返回 true（示意）
:cond_8
const/4 v0, 0x1
```

```text
预期：应用正常启动；isVip()/getIntVipLevel() 读到 vip_grade="1" 返回 true，客户端 VIP 门禁放开。
（原文只验证“修正寄存器后可正常安装”，未附 VIP 功能解锁截图；本卡按代码重建，未在真实应用复现。）
```

## 变体与关联

- 关联：[[mobile-android-smali-vip-check-force-true-repack]]（同类场景：改布尔成员方法 `u()/a()` 的失败分支返回 true，本卡改字段 setter，两处可组合）。
- 关联：[[mobile-android-local-save-currency-smali-patch-repack]]（同样在对象字段/getter 上写常量并重打包）。
- 变体：改 `getVipLevelInt()` 直接把任意字符串映射成 1；或 hook `UserInfo` 构造器/`setVip_grade` 动态赋值（有注入条件时）。
- 边界：服务端权益校验、VIP 到期时间字段、签名派生密钥会让本地改字段失效或仅剩 UI 效果。

## 检测与防御

- 检测：APK 签名/证书与官方不一致；`UserInfo` setter 中出现额外 `const-string ... "1"`/`iput-object`；VIP 状态与购买记录、服务端下发不一致。
- 防御：权益判断放服务端并在每次受限操作时校验；启动时做签名/完整性校验（Play Integrity、证书指纹）；不要用纯客户端字符串字段承载付费等级；代码加固与混淆提高定位成本。
