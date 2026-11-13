---
id: mobile-android-blackdex-tencent-yushan-stubshell-unpack-repack
title: 腾讯御安全（StubShell）加固 APK 脱壳回填：BlackDex dump + dex 修复改名 + WrapperProxyApplication 真实入口替换 + 壳特征清理
type: scenario
domain: mobile
path: mobile/android
technique: blackdex-tencent-yushan-entry-repair-repack
aliases:
- 腾讯御安全脱壳
- StubShell 脱壳修复
- BlackDex 腾讯加固
- WrapperProxyApplication 真实入口
- MyWrapperProxyApplication
- 御安全加固重打包
- dexDump 回填
tags:
- android
- apk
- unpacking
- blackdex
- tencent
- yushan
- stubshell
- repack
- np-manager
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:11:05+08:00'
  notes: 已对照原文与全部23张截图核对：图01 tencent.StubShell、图02 MT加固状态腾讯御安全/版本651、图04 dexDump路径、图05原包classes.dex 62.42K与classes2-4 2.38K对应dump中同大小cookie_63916/cookie_2436/hook_63916、图06仅修复头部、图07 WrapperProxyApplication.className静态字段(截图截断)、图08b MyWrapperProxyApplication入口、图09/10 classes5-10回填、图11壳特征文件清单、图12-14校验不通过->NP去校验V1+V2->未加固安装、图15安装登录均一致；与SecShell脱壳卡壳厂商/入口/特征不同非同链；未验证点：未实际脱壳复现
---

## 一句话结论

对腾讯御安全（tencent.StubShell / 加固状态显示“腾讯御安全”）的 APK，用 BlackDex dump 出真实 dex 后，按原包大小剔除重复壳 dex、用 NP 管理器“仅修复头部”修复并重命名为 `classesN.dex` 回填原包，从原 `WrapperProxyApplication` 的静态字段 `className` 读出真实 Application 并替换 Manifest 的 `android:name`，删除 `libshell*`、assets 下 `00000111111`/`o0ooo0OOooOo.dat`/`t86`/`tosversion` 等壳特征，最后用 NP 管理器去除签名校验，重打包后应用可正常安装使用。

## 原理

- **腾讯御安全的代理入口**：加固后 Manifest 的 `<application android:name>` 指向壳的包装类（本例 `MyWrapperProxyApplication`，混淆名可变）；壳的真实 Application 全名保存在 `com.wrapper.proxyapplication.WrapperProxyApplication` 的静态字段 `className` 中。脱壳后壳的 dex/so 被替换或删除，若入口仍指向壳类会启动失败，必须改为 `className` 里的真实类。
- **BlackDex 的内存 dump 定位**：BlackDex 在应用运行时把已解密的 dex 从内存 dump 到 `/storage/emulated/0/Download/dexDump/<包名>`，输出常见 `cookie_*.dex` 与 `hook_*.dex`。其中一部分是原 APK 中壳入口 dex 的副本（大小与原 `classes.dex`/`classesN.dex` 相同），另一部分才是真实业务 dex。
- **按大小去重**：原包的 `classes.dex` 很小（本例 62.42K，`classes2..4.dex` 约 2.38K）是壳入口/占位；dump 结果里大小相同的 `cookie_*.dex`/`hook_*.dex` 是重复壳 dex，删除；显著更大的 `cookie_9059720.dex`（8.64M）、`hook_9032564.dex`（8.61M）等才是真实业务代码。
- **dex 修复与回填**：dump 出的 dex 头部校验可能不完整，NP 管理器的“Dex 修复 → 仅修复头部”重算头部字段（产生的 `.bak` 备份删除），再按 `classes5.dex`…`classesN.dex` 命名放进原 APK；保存时不能自动签名，否则后续去校验/重签流程会被提前破坏。
- **壳特征清理**：`lib/` 下带 shell 的 so（本例 `libshell-super.2019.so`、`libshella-4.1.0.31.so`）与 assets 下的 `00000111111`、`o0ooo0OOooOo.dat`、`t86`、`tosversion` 是御安全运行时组件；保留它们会让应用继续走壳逻辑或触发完整性检查。清理后 MT 管理器显示“未加固”。
- **签名校验**：改包后原签名失效，MT 显示“签名状态：校验不通过”；用 NP 管理器“去除签名校验”（V1+V2）重签后即可正常安装，说明该应用只做了客户端签名校验、未做服务端强校验。

## 触发条件

- 目标 APK 为腾讯御安全加固：jadx 目录出现 `tencent.StubShell`，MT 应用信息“加固状态”显示腾讯御安全，`lib`/`assets` 存在 shell 特征文件。
- 可在 root 设备或虚拟环境运行 BlackDex 完成运行时 dump。
- 能用 MT/NP 管理器或 apktool 修改 APK、修复 dex、重签名；应用未做严格完整性校验或校验可被 NP 去除。
- 仅限授权测试环境。

## 利用步骤

1. 查壳：jadx 打开 APK 看到 `tencent.StubShell` 目录、代码不可读；MT 查看应用信息确认“腾讯御安全”，记录包名与版本（本例 `com.dalongtech.cloud`，651）。
2. BlackDex 脱壳：选择目标应用执行，完成后提示 dex 存放在 `/storage/emulated/0/Download/dexDump/<包名>`。
3. 过滤 dex：对比原包 `classes.dex`/`classesN.dex` 大小，删除 dump 结果中大小相同的重复壳 dex；保留明显更大的业务 dex。
4. 修复：NP 管理器对保留的 dex 执行“Dex 修复 → 仅修复头部”，删除生成的 `.bak` 文件。
5. 重命名并回填：按 `classes5.dex`…`classesN.dex` 命名，加入原 APK 根目录；保存时**不要自动签名**。
6. 找真实入口：在原壳 dex 中定位 `com.wrapper.proxyapplication.WrapperProxyApplication`，读取静态字段 `className` 的值（本例为 `com.dalongtech.cloud...`，截图被截断，需按目标实际值读取），把 Manifest 的 `application android:name="MyWrapperProxyApplication"` 改成该真实 Application。
7. 清理壳特征：删除 `lib` 下带 shell 的 so（`libshell-super.2019.so`、`libshella-4.1.0.31.so` 等）及 assets 下 `00000111111`、`o0ooo0OOooOo.dat`、`t86`、`tosversion`。
8. 去签名校验：MT 显示“未加固 / 校验不通过”后，用 NP 管理器“去除签名校验”（V1+V2）重签。
9. 安装验证：卸载原应用后安装；能正常启动、登录即脱壳回填完成。

## PoC

无独立脚本（MT/NP/BlackDex 均为 GUI 操作）。关键检查点：

```text
1) 查壳: jadx 目录 tencent.StubShell; MT 加固状态=腾讯御安全
2) BlackDex 输出: /Download/dexDump/com.dalongtech.cloud/
   原包 classes.dex 62.42K、classes2..4.dex 2.38K（壳入口，保留）
   dump 中同大小 cookie_63916.dex 62.42K / cookie_2436.dex 2.38K / hook_63916.dex 62.42K（删）
   真实业务 dex: cookie_9059720.dex 8.64M、hook_9032564.dex 8.61M 等（保留）
3) NP: Dex 修复 -> 仅修复头部; 改名为 classes5..N.dex 放回原包; 不自动签名
4) 入口: com.wrapper.proxyapplication.WrapperProxyApplication.className
   Manifest: android:name="MyWrapperProxyApplication" -> <className 的真实值>
5) 删除: libshell-super.2019.so、libshella-4.1.0.31.so、
   assets/00000111111、assets/o0ooo0OOooOo.dat、assets/t86、assets/tosversion
6) NP 去除签名校验(V1+V2) -> 重签安装
```

## 变体与关联

- **其他加固**：BB/SecShell 的同类流程见 [[mobile-android-blackdex-secshell-unpack-entry-repair-repack]]（改 `SecShell.H.APPNAME`、删 `appComponentFactory`）；腾讯加固另一案例见 [[mobile-android-blackdex-tencent-packer-hook-bmz-native-md5-key-sign]]（BlackDex + 逆向 st/sn 风控参数）；通用查壳/tool 路线见 [[mobile-android-packer-apkid-frida-dexdump-jadx]]。
- **入口定位差异**：御安全的真实入口在 `WrapperProxyApplication.className` 静态字段；其他壳可能在 `attachBaseContext` 加载 dex 后动态替换 ClassLoader（见 [[mobile-android-first-gen-dex-packer-attachbasecontext-classloader]]）。
- **脱壳后的二次修改**：应用正常启动后可继续改 Manifest 入口跳过广告页（见 [[mobile-android-apk-manifest-launcher-vip-charge-bypass]]）、patch 强制更新取消按钮等。
- **边界**：若目标使用 VMP/函数抽取或 native 反调试，dump 出的 dex 可能不完整，回填后崩溃；若存在服务端完整性校验，去签名校验只能解决客户端安装。

## 检测与防御

- 检测：APK 的 `application android:name` 指向 `wrapper.proxyapplication` 壳类、`libshell*`/`assets` 非常规文件被删除但 dex 数量异常增多；重打包证书与官方不一致；客户端出现 BlackDex/NP 管理器特征。
- 防御：启用服务端完整性/签名校验与 Play Integrity，关键逻辑放服务端；使用 VMP/抽取提高 dump 成本；检测 root/虚拟环境与调试器。
