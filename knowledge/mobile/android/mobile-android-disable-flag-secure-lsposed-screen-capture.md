---
id: mobile-android-disable-flag-secure-lsposed-screen-capture
title: Android 防录屏绕过：LSPosed DisableFlagSecure 解除 FLAG_SECURE
type: scenario
domain: mobile
path: mobile/android
technique: disable-flag-secure-lsposed
aliases:
- DisableFlagSecure
- FLAG_SECURE
- 防录屏
- 禁止截屏
- LSPosed 模块
tags:
- android
- lsposed
- flag-secure
- screen-capture
- anti-forensics
- mitm
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:20:08+08:00'
  notes: 已对照原文核对：LSPosed 安装 DisableFlagSecure 解决目标应用防录屏，与原文描述一致。未验证点：原文未给出具体应用/Android 版本，未实测截屏恢复；模块 Hook 实现细节为通用描述。
---

## 一句话结论

目标应用设置 `WindowManager.LayoutParams.FLAG_SECURE` 后，系统会阻止截屏/录屏；在已 root 且安装 LSPosed 的设备上启用 `DisableFlagSecure` 模块并勾选目标应用，重启应用后即可正常截屏/录屏，便于记录测试过程。

## 原理

- **FLAG_SECURE**：应用给窗口设置 `FLAG_SECURE` 后，Android 会在合成层阻止该窗口被截屏/录屏，`MediaProjection` 也拿不到内容；这是银行、支付、DRM、隐私类应用的常见防护。
- **模块 Hook**：`DisableFlagSecure` 是 LSPosed/Xposed 模块，在目标进程里 Hook `Window.setFlags`/`WindowManager.LayoutParams` 相关路径，移除 `FLAG_SECURE` 位，使窗口恢复可截屏。
- **前置条件**：设备已 root（APatch/Magisk/KernelSU）并启用 LSPosed/Vector；模块作用域勾选目标应用；重启目标应用/设备。
- **限制**：如果应用使用 native/secure surface、DRM、或自行检测截屏状态，模块可能无效；部分应用会检测 LSPosed/root。

## 触发条件

- 目标应用设置 `FLAG_SECURE`，截屏/录屏黑屏或报错。
- 设备已 root 且 LSPosed 可用。
- 能安装并启用 `DisableFlagSecure` 模块。
- 目标未使用更强的 native 安全显示/DRM。

## 利用步骤

1. 确认目标应用截屏黑屏/录屏失败，判断为 `FLAG_SECURE`。
2. 在 LSPosed 中安装/启用 `DisableFlagSecure`，作用域勾选目标应用。
3. 重启目标应用（或重启设备）。
4. 再次截屏/录屏验证；若仍失败，检查模块是否生效、是否有其他窗口/子进程设置 FLAG_SECURE。
5. 若应用检测 root/LSPosed，结合 Shamiko/HideMyApplist 等隐藏环境。

## PoC

```text
1) LSPosed → 安装 DisableFlagSecure
2) 作用域勾选目标 APP
3) 强制停止/重启 APP
4) adb exec-out screencap -p > screen.png 验证
```

## 变体与关联

- **模块变体**：DisableFlagSecure、FLAG_SECURE 移除类 Xposed 模块、Frida Hook `setFlags`。
- **检测变体**：应用检测截屏/录屏状态、检测 LSPosed/root；需要隐藏环境或 Hook 检测函数。
- **限制变体**：DRM/secure surface/native 渲染可能无法绕过。
- **关联卡片**：[[mobile-android-anti-detection-root-emulator-proxy]]（隐藏 root/LSPosed）、[[mobile-android-pixel-apatch-root-boot-img-slot]]（root 前置）、[[mobile-android-ssl-pinning-bypass-cert-frida]]（抓包环境）。
- **边界**：模块只对标准 `FLAG_SECURE` 有效；对硬件安全显示/DRM 无效；重启应用后仍无效需检查作用域/框架。

## 检测与防御

- **防御**：敏感页面使用 `FLAG_SECURE` + native secure surface/DRM；检测 root/LSPosed/截屏状态；不要仅依赖 `FLAG_SECURE`。
- **检测信号**：设备安装 DisableFlagSecure/LSPosed；目标应用窗口 flags 异常；截屏行为与正常设备不同。
- **测试建议**：先验证模块对普通应用生效，再测目标；记录测试过程时注意合规与授权。
