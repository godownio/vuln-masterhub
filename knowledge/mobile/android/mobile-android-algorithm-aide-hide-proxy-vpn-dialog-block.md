---
id: mobile-android-algorithm-aide-hide-proxy-vpn-dialog-block
title: 算法助手（Xposed）隐藏 WiFi 代理/VPN 状态 + 关键词屏蔽检测弹窗，绕过手游反抓包并抓到实名请求
type: scenario
domain: mobile
path: mobile/android
technique: android-xposed-hide-proxy-vpn-keyword-dialog-block
aliases:
- 算法助手
- 隐藏Wifi代理
- 隐藏VPN
- justTrustMe升级版
- 关键词屏蔽弹窗
- 反抓包绕过
- 游戏抓包
tags:
- android
- xposed
- lsposed
- proxy-detection
- vpn
- anti-capture
- traffic-analysis
- ssl-pinning
- game
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V561
  verified_at: '2026-11-12T07:40:39+08:00'
  notes: 已对照原文13005逐图核对：代理检测'信息确认中'弹窗、算法助手作用域(com.fingersoft.hillclimb.noncmcc 1.48.18)、网络环境三项开关、关键词'重试,系统提示'、从模块内启动、HttpCanary 抓到实名 POST JSON 均与截图一致；未本机复现。
---

## 一句话结论

手游在检测到系统代理/VPN 时会弹"信息确认中，请稍等或重新尝试"并阻止进入游戏；在已 Root 的 Android 12 上用 LSPosed 加载"算法助手"模块并对目标 App 勾选辅助，开启"隐藏Wifi代理""隐藏VPN""justTrustMe升级版"，再配置弹窗关键词（如"重试,系统提示"）自动屏蔽，从模块内重启 App 后检测框不再出现，可从模块内启动后用 HttpCanary/小黄鸟正常抓包（作者成功抓到实名认证 POST 请求）。

## 原理

- **反抓包检测点**：应用可读取系统代理设置（`ProxySelector`/`System.getProperty("http.proxyHost")`）、判断是否存在 VPN Transport 网络、检查驻留的 CA 证书或做 SSL Pinning；命中后弹出"信息确认中"对话框并阻断启动流程，旧版本中取消弹窗后仍卡在进入页。
- **Xposed 模块的作用**：
  - 隐藏 WiFi 代理/VPN：hook 代理与网络状态相关 API，向目标返回"无代理/无 VPN"的结果；
  - justTrustMe 升级版：hook 系统 TrustManager/证书校验相关实现，绕过 SSL Pinning，使 HttpCanary 用户 CA 能解包；
  - 关键词屏蔽弹窗：拦截并取消包含指定关键词的对话框（本例配置"重试,系统提示"），让检测提示不阻塞流程。
- **为什么必须从模块内启动**：Xposed hook 需要在目标进程启动时注入；从模块内启动可保证类加载前 hooks 已生效，普通启动可能错过部分检测时机。
- **边界**：这类方案依赖目标用 Java 层 API 做检测；若应用使用 native 层检测（如 dlopen 监控、pthread_create 反调试）或更强的证书固定，需要更底层的 Frida/内核方案。

## 触发条件

- 目标 App 通过系统代理/VPN 状态或证书固定检测抓包，并弹窗阻断；
- 设备已 Root，安装了 LSPosed/Xposed 框架；
- 目标未使用不可绕过的 native 反调试/反注入方案；
- 需抓取的请求走应用自身 HTTPS（能通过 justTrustMe 解锁用户 CA）。

## 利用步骤

1. 安装"算法助手"（`com.junge.algorithmAide`）并在 LSPosed 中启用模块，作用域勾选目标游戏（本例 `com.fingersoft.hillclimb.noncmcc` 1.48.18），必要时也勾选系统框架。
2. 打开算法助手进入目标 App 的辅助设置：设备环境可勾选"隐藏Xposed""隐藏Root"；网络环境（屏蔽防抓包专题）勾选"隐藏Wifi代理""隐藏VPN""justTrustMe升级版"。
3. 在该设置的弹窗屏蔽处填写关键词（如 `重试,系统提示`），使检测弹窗自动取消。
4. 强制停止目标 App，然后从算法助手界面启动（不要从桌面图标启动），确认不再弹出"信息确认中"。
5. 打开 HttpCanary/小黄鸟开始抓包，正常操作到实名认证页面，即可在抓包记录中看到 POST JSON（如 `{"name":"测试","rin":"<身份证号>"}`）。

## PoC

操作配置即 PoC（无代码）；关键证据：

- 未处理时：开启代理后游戏弹"系统提示 / 信息确认中，请稍等或重新尝试"，HttpCanary 显示"抓包中..."但游戏无法进入；
- 算法助手网络环境三个开关（隐藏Wifi代理、隐藏VPN、justTrustMe升级版）开启；
- 弹窗关键词配置 `重试,系统提示`；
- 从模块内启动后正常进入实名页面，HttpCanary 抓到发往实名认证接口的 POST 请求。

## 变体与关联

- 用 SagerNet 规则代理只让目标流量进 Burp、规避系统代理检测，见 [[mobile-android-sagernet-rule-proxy-avoid-system-proxy-detection]]；
- Shamiko/HideMyApplist/PlayIntegrityFork + iptables 透明代理的反检测环境，见 [[mobile-android-anti-detection-root-emulator-proxy]]；
- 系统证书迁移 + TrustMe/objection 的 SSL Pinning 绕过，见 [[mobile-android-ssl-pinning-bypass-cert-frida]]；
- Hook 强制 SPDY 降级 HTTP 的抓包绕过，见 [[mobile-android-frida-spdy-switch-disable-force-http-capture]]。

## 检测与防御

- 应用侧检测 Xposed/LSPosed 框架、root、hook 痕迹（类加载器、方法体篡改、`XposedBridge` 特征），检测到即降级或阻断；
- 代理/VPN 检测不要只看系统 API，结合网络接口、路由表、证书链与 native 层校验；
- 关键请求使用证书固定并把校验放在 native 层，提高 justTrustMe 类 hook 的成本；
- 服务端风控：检测同一证书/设备指纹异常、请求来源与设备网络环境不一致；
- 弹窗屏蔽类 hook 会让 UI 流程异常，可通过关键 UI 元素/事件缺失做二次校验（仅提高门槛）。
