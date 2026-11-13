---
id: mobile-miniprogram-wxapkg-extract-unpack-toolchain
title: 微信小程序 wxapkg 落盘位置提取与 wxappUnpacker 解包（UnpackMiniApp 解密）
type: scenario
domain: mobile
path: mobile
technique: miniprogram-wxapkg-extract-unpack
tags:
- mobile
- miniprogram
- wechat
- wxapkg
- reverse
- unpack
- nodejs
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V602
  verified_at: '2026-11-12T18:17:28+08:00'
  notes: 已对照原文与32张截图核对：img16 /data/data/com.tencent.mm/MicroMsg/e594472a09487567540796a08a51a24f/appbrand/pkg 下多个.wxapkg（10文件）；img17 UnpackMiniApp判断'文件未加密，无需解密'；img18 node v18.14.2运行wuWxapkg.js输出Header info firstMark 0xbe/infoListLength 1439/dataLength 549002/lastMark 0xed、fileCount 38，与卡片PoC说明逐项一致；img19输出目录含app-service.js/app.json/app-config.json/pages/components等。npm依赖清单与原文一致。原文无组件版本，不设affected_versions。dedup：与ctf-reverse-miniprogram-wxapkg-ror-xor-hardcoded-array、wxapkg-aes-cbc-sorted-sign-replay、sm-crypto-protocol、unpack-test-domain-fofa等候选均为'已解包后下游分析'，本卡为落盘提取+解密+解包前置工具链，非同链，保留。dup-scan.json不涉及。skipped的反射大师/AppMessager/MobSF项确被mobile-android-reflection-master-xposed-dex-dump、frida-dexdump卡或MobSF一句话介绍覆盖。
url: /docs/mobile/mobile-miniprogram-wxapkg-extract-unpack-toolchain/
draft: false
kb_aliases:
- wxapkg 提取
- 小程序包解包
- UnpackMiniApp
- wxappUnpacker
- wuWxapkg.js
- appbrand pkg 目录
- 小程序反编译
---

## 一句话结论

微信小程序运行后会把打包文件缓存在 Android 存储 `/data/data/com.tencent.mm/MicroMsg/<32位hash>/appbrand/pkg/` 下（`*.wxapkg`，主包与分包）；清空旧包后重新把目标小程序各页面走一遍得到新包，用 UnpackMiniApp 判断并解除加密，再用 wxappUnpacker 的 `wuWxapkg.js`（Node.js 环境）解包，即可得到 `app-service.js`、`app.json`、页面目录等可读源码，用于审计客户端加密/签名算法。

## 原理

- 小程序代码（JS/WXML/WXSS/配置）被打包进 wxapkg 文件；微信在本地运行小程序时会把包缓存到磁盘，Android 上路径为 `/data/data/com.tencent.mm/MicroMsg/<user-hash>/appbrand/pkg/`，其中 `<user-hash>` 随微信账号变化。
- wxapkg 格式：文件头 `firstMark=0xbe`、`infoListLength`、`dataLength`、`lastMark=0xed`，随后是文件索引表与数据区；解包器按索引把每个文件还原并做 JS 美化/配置补全。
- 部分环境（尤其 PC 微信）下载的包是加密的，需要 UnpackMiniApp 之类工具按包尾/密钥判断并解密；已解密的包也可以让工具先判断“是否加密”再决定是否处理。
- 主包之外还有分包（文件名带 `_pages_xxx_` 等前缀），功能分散在多个包中，解包时要逐个处理。
- 为什么可复用：后端把签名/加密逻辑放在小程序 JS 里时，反编译是还原算法、伪造请求的前置步骤；小程序包对持有设备的人没有保密性。

## 触发条件

- Android 设备/模拟器已登录微信，并完整使用过目标小程序（各页面都打开过）。
- 能访问 `/data/data/com.tencent.mm/`（root、文件管理器 root 模式或 adb）。
- 本地有 Node.js 环境（wxappUnpacker 依赖 esprima、css-tree、cssbeautify、vm2、uglify-es、js-beautify）。
- 目标小程序未使用运行时完整性校验/代码虚拟化，否则反编译结果可能不完整。

## 利用步骤

1. 打开微信进入目标小程序，把所有功能页面走一遍，让包完整落盘。
2. 用 root 文件管理器/ADB 进入 `/data/data/com.tencent.mm/MicroMsg/<32位hash>/appbrand/pkg/`，确认出现多个 `*.wxapkg`。
3. 为排除旧包干扰：删除该目录下已有 wxapkg，重新打开小程序并走一遍页面，新生成的文件即目标包（含主包与分包）。
4. 把包拉到本地，用 UnpackMiniApp（“PC 微信小程序一键解密”）选择加密小程序包，工具自动判断是否加密并解密。
5. 在 wxappUnpacker 目录执行依赖安装：
   ```bash
   npm install
   npm install esprima css-tree cssbeautify vm2 uglify-es js-beautify
   ```
6. 对主包执行 `node wuWxapkg.js <主包.wxapkg>`；若报错可能选错包（不是主包）或包未解密，但通常仍会输出部分文件。输出目录包含 `app-service.js`、`app.json`、`app-config.json`、`pages/`、`components/` 等。
7. 在 `app-service.js` 中搜索 `sign`、`encrypt`、`AES`、`key`、`iv`、`nonce`、`timestamp` 等关键词，定位客户端加密/签名逻辑，转入协议复现与改包重放。

## PoC

```bash
# 设备侧：定位并拉取最新 wxapkg（路径中的 hash 随账号变化）
adb shell "ls /data/data/com.tencent.mm/MicroMsg/*/appbrand/pkg/"
adb pull /data/data/com.tencent.mm/MicroMsg/<hash>/appbrand/pkg/<pkg>.wxapkg ./

# 本地：解密（GUI 选择加密包，输出解密后的 wxapkg）
# UnpackMiniApp.exe -> 选择加密小程序包

# 本地：解包（Node.js）
cd wxappUnpacker
npm install && npm install esprima css-tree cssbeautify vm2 uglify-es js-beautify
node wuWxapkg.js <pkg>.wxapkg
# 输出：app-service.js / app.json / pages/ 等
```

说明：原文在夜神模拟器（Android 9）实测，包位于 `/data/data/com.tencent.mm/MicroMsg/e594472a.../appbrand/pkg/`；wuWxapkg.js 输出 `Header info: firstMark 0xbe, infoListLength 1439, dataLength 549002, lastMark 0xed` 后生成 38 个文件，解包目录与图 19 一致。原文未给工具版本，依赖以实际 npm 安装为准。

## 变体与关联

- 变体：PC 微信的 wxapkg 缓存目录在 `%APPDATA%` 下的 `WeChat Files`/`Applet` 相关路径，可用同类工具解包；`UnpackMiniApp` 本身就是按 PC 微信包设计。
- 变体：分包 `_pages_xxx_.wxapkg` 单独解包后合并目录；主包缺失的模块常在分包里。
- 变体：不落盘反编译，改用微信 devtools/WeChatOpenDevTools 断点读加密函数（见关联卡）。
- 关联：[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（解包后定位 webpack 模块与国密协议）；[[mobile-miniprogram-wxapkg-aes-cbc-sorted-sign-replay]]（解包后还原 AES/签名改包重放）；[[mobile-miniprogram-devtools-force-enable-wechat-version-pin]]（静态看不懂时开 devtools 断点）；[[mobile-android-anti-detection-root-emulator-proxy]]（root 模拟器环境准备）。
- 边界：小程序代码虚拟化/加固、wxapkg 强加密且工具不支持、运行时完整性校验会导致解包失败或源码不完整；解包仅解决“看得见”，业务漏洞仍需单独验证。

## 检测与防御

- 开发者：不要把密钥、签名 secret、加解密逻辑放在小程序前端；关键逻辑上移服务端并绑定会话/设备。
- 平台/加固：代码混淆、虚拟化、运行时完整性校验、反调试；wxapkg 加密并轮换密钥。
- 检测（防守视角）：设备上出现 wxapkg 批量复制/删除行为、root 文件管理器访问 `/data/data/com.tencent.mm`、PC 端调试工具连小程序 runtime。
