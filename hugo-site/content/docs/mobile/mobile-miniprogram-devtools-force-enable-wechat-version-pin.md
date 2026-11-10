---
id: mobile-miniprogram-devtools-force-enable-wechat-version-pin
title: 小程序开不了 devtools：用 WeChatOpenDevTools 打补丁 + 把微信降到工具支持的版本（3.9.10.19）后才能断点
type: scenario
domain: mobile
path: mobile
technique: miniprogram-force-enable-devtools-wechat-version-pin
tags:
- mobile
- miniprogram
- wechat
- devtools
- debugging
- reverse
- tooling
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片；WeChatOpenDevTools 打补丁开小程序 devtools、RadiumWMPF 插件目录确认版本、新版不支持需降级到 3.9.10.19、版本对了仍失败则删插件目录下两个残留文件后退出微信重进、建议用小号，均与正文一致；工具支持版本列表原文是截图，未读图故卡内只写「本例 3.9.10.19」而不断言支持区间；这是工具链/调试环境流程卡（无漏洞 PoC），severity 已标 low，affected_versions 不设（3.9.10.19 是目标环境版本而非受影响版本）
url: /docs/mobile/mobile-miniprogram-devtools-force-enable-wechat-version-pin/
draft: false
kb_aliases:
- 微信小程序开 devtools
- WeChatOpenDevTools
- RadiumWMPF 插件目录
- 微信降版本
- 小程序断点调试
- 小程序反编译后动态验证
---

## 一句话结论

小程序只能反编译、不能断点时，用 `WeChatOpenDevTools` 这类工具给微信打补丁可以强制打开小程序 devtools 做断点调试；但工具只支持特定微信版本（本例 3.9.10.19），新版微信上工具会失效，需要先到插件目录（`%APPDATA%\Tencent\WeChat\XPlugin\Plugins\RadiumWMPF`）确认当前小程序运行时版本、再降级微信安装包，必要时删掉插件目录里的残留文件后重启微信——打开 devtools 之后，加密/签名函数才能下断点读实参，静态看不懂的逻辑才验得动。

## 原理

- **小程序代码是被压缩混淆的 JS**：反编译只能拿到打包产物，函数名与调用关系被抹平，纯静态读起来非常吃力；devtools 能给出原始（或近似原始）作用域、实参与调用栈，是把"猜"变成"确认"的关键手段。
- **官方 devtools 只对开发者自己的小程序开放**：正常途径无法 attach 到别人的小程序，所以社区工具用内存补丁/协议劫持的方式在微信进程里把调试通道打开。
- **补丁依赖微信版本的内部结构**：`RadiumWMPF` 是小程序运行时插件，其版本与微信主程序版本绑定；工具针对特定版本偏移做 patch，版本一变偏移就错，于是"打不开"或"打开了但白屏"。
- **因此这就是一条版本固定（version pinning）链**：查当前版本 → 装工具支持的那一版微信 → 清理旧插件缓存 → 重开微信 → 开 devtools；顺序错了（如没清缓存）经常表现为"版本对了仍失败"。
- **代价与风险**：降级微信会影响日常使用、可能与账号安全策略冲突，故实践里建议用小号；工具本身是第三方二进制，需要在隔离环境里运行。

## 触发条件

- 目标是微信小程序，且已经完成反编译、需要动态验证（断点读 key/iv、改内存参数试算）。
- 运行环境是 Windows（本文工具链为 Windows 微信 + Python 工具）。
- 允许降级微信版本（有可用的小号/测试机），且能找到该版本的安装包。
- 目标小程序未做额外的反调试（如检测 devtools 协议、校验运行时完整性），否则即使打开也会被踢。

## 利用步骤

1. 先反编译小程序包，定位疑似加密/签名的函数与关键字符串（本例 `Encryptkey`），作为断点目标。
2. 到 `C:\Users\<user>\AppData\Roaming\Tencent\WeChat\XPlugin\Plugins\RadiumWMPF` 看当前小程序运行时插件版本，确认微信主程序版本是否落在工具支持范围内。
3. 若版本过新：卸载微信，安装工具支持的历史版本（本例 3.9.10.19）。
4. 运行 `WeChatOpenDevTools`（`-a` 等参数按工具 README），再用小号登录并打开目标小程序。
5. 若"版本对了但仍未开起来"：删除插件目录下残留的两个缓存文件，完全退出微信（含托盘/后台进程）后重进，再试一次。
6. devtools 打开后，在加密函数、签名函数上下断点，读实参（key/iv/公钥/私钥/拼接顺序），必要时在断点处改值验证猜想。
7. 把断点得到的事实写成可复现脚本（Python/Node）后离线生成参数，脱离 devtools。

## PoC

无 PoC（工具链操作流程，不含可执行利用代码）。要点记录：

```text
1) 版本确认目录：C:\Users\<user>\AppData\Roaming\Tencent\WeChat\XPlugin\Plugins\RadiumWMPF
2) 工具：WeChatOpenDevTools（社区项目，按 README 传参启动）
3) 打不开时：清 RadiumWMPF 下残留文件 -> 完全退出微信 -> 重进
4) 目标版本示例：微信 3.9.10.19
```

## 变体与关联

- 变体：Android 侧改用 `frida` hook 小程序运行时（`WMPF` 相关 so）来打印/改写加解密入参，无需降级桌面微信。
- 变体：不打开 devtools，改用「代理 + JS 注入」在页面上下文里包一层 `encrypt`/`sign` 直接把明文与密文打出来。
- 关联：[[mobile-miniprogram-aes-cbc-rsa-wrapped-iv-key-sign-replay]]（本篇服务的目标：在 devtools 里断出 AES/RSA/签名三段逻辑后重造参数）、[[pentest-recon-wechat-builtin-browser-debug-access]]（微信内置浏览器/WebView 的调试接入，属另一条调试通道）、[[mobile-miniprogram-charles-burp-upstream-proxy-capture]]（小程序抓包侧的前置准备）。
- 边界：目标小程序若启用了代码加固/运行时完整性校验，devtools 打开后也可能立刻断开；微信后续版本可能彻底堵住该补丁路径。

## 检测与防御

- 检测（防守视角）：小程序运行时检测调试协议是否被附加、检测 `RadiumWMPF` 文件被替换、检测进程内存被 patch。
- 修复（开发者）：不要把密钥与签名私钥放到前端；关键逻辑上移服务端并做设备/会话绑定。
- 加固（平台侧）：升级微信版本即修复已知补丁点；企业环境可用 MDM 固定微信版本并禁用第三方注入工具。
