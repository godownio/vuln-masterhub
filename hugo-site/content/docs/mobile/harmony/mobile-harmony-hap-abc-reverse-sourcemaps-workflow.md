---
id: mobile-harmony-hap-abc-reverse-sourcemaps-workflow
title: HarmonyOS HAP 逆向流程：sourceMaps 泄露源码树 + modules.abc 反编译 + ArkTS 字节码阅读
type: scenario
domain: mobile
path: mobile/harmony
technique: hap-abc-reverse-sourcemaps-arkts-bytecode
tags:
- harmonyos
- mobile
- reverse
- hap
- abc
- arkts
- sourcemaps
- stage-model
- bytecode
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:19:53+08:00'
  notes: 已对照原文与图02/04/06/08核对：HAP=ZIP、ets/modules.abc、sourceMaps.map 泄露源码树、module.json5/main_pages.json、Stage 生命周期、newlexenvwithname/asyncfunctionenter/suspendgenerator 伪指令、JADX ABC 插件、N-API 均与原文一致。未验证点：图04 实际目录显示 module.json（非 module.json5），原文正文写 module.json5，解包时需按实际文件名适配；PoC 未本机执行；原文未标注组件版本。
url: /docs/mobile/harmony/mobile-harmony-hap-abc-reverse-sourcemaps-workflow/
draft: false
kb_aliases:
- HAP 解包
- sourceMaps.map
- modules.abc
- 方舟字节码
- Stage 模型
- newlexenvwithname
- asyncfunctionenter
- suspendgenerator
- ArkTS 反编译
---

## 一句话结论

HarmonyOS 的 `.hap` 本质是 ZIP，解压后 `ets/modules.abc` 是 ArkTS 编译后的方舟字节码，`ets/sourceMaps.map` 若未在发布构建中剥离会泄露完整源码文件树；用带 ABC 插件的 JADX 反编译，结合 `module.json5`/`main_pages.json`、Stage 生命周期和方舟伪指令（`newlexenvwithname`、`asyncfunctionenter`、`suspendgenerator`、`resumegenerator`）即可还原业务逻辑与密钥派生链。

## 原理

- **HAP 结构**：`.hap` 是 ZIP，典型目录包含 `ets/modules.abc`（ArkTS 字节码）、`ets/sourceMaps.map`（源码映射）、`resources/base/`、`resources/rawfile/`（不编译的原始资源）、`module.json5`（模块配置）、`pack.info`、`libs/arm64-v8a/`（Native 库）。一个应用可由多个 HAP（Entry/Feature）、HSP（动态共享包）、HAR（静态共享包）组成。
- **配置与路由**：`module.json5` 的 `mainElement` 指定入口 Ability，`pages` 指向 `resources/base/profile/main_pages.json`；入口 `EntryAbility.onWindowStageCreate` 的 `windowStage.loadContent('pages/...')` 决定首屏。`AppStorage`/`LocalStorage` 是进程级/页面级全局键值存储，跨页面传递的 token/用户信息常在这里。
- **sourceMaps 泄露**：`sourceMaps.map` 是 JSON，键为源码路径（如 `entry/src/main/ets/model/FlagUtil.ets`），值为 `version/file/sources/mappings`；正常发布应剥离，保留它通常意味着 debug 构建或未配置 `sourceMap`。它直接给出模块划分、类名与文件路径，是逆向的“代码地图”。
- **ABC 字节码**：ArkTS 经方舟编译器前端（TypeScript AST）与后端生成 `.abc`，内部包含文件头、类/方法定义、字符串常量池、字节码指令区。公开格式文档有限，常用带 ABC 插件的 JADX 反编译；输出会保留方舟伪指令，需要按语义还原。
- **伪指令语义**：
  - `newlexenvwithname([n, "name0", slot0, ...], n)` 创建词法环境，`_lexenv_X_Y_` 中 X 是嵌套层级、Y 是槽位；数组格式为 `[总数, 名称, 槽位, ...]`。
  - `asyncfunctionenter` + `suspendgenerator` + `resumegenerator` + `getresumemode` 是 `async/await` 的展开；`asyncfunctionresolve/reject` 对应 Promise 的 resolve/reject。
  - `ldlocalmodulevar`、`createobjectwithbuffer`、`ldobjbyvalue` 等用于模块变量、对象字面量和属性访问。
- **Native 层**：若存在 `libs/arm64-v8a/*.so`，通过 N-API（`napi_define_properties`/`DECLARE_NAPI_FUNCTION`）向 ArkTS 暴露函数；`import xxx from 'libxxx.so'` 对应 native 模块，需 IDA/Ghidra 分析。
- **为什么可逆向**：ArkTS 是 TypeScript 超集，编译后保留较多语义信息（闭包变量名、字符串常量、类结构），相比 Dex 更容易还原高级逻辑；sourceMaps 与未混淆的字符串进一步降低门槛。

## 触发条件

- 目标为 HarmonyOS HAP/APP 包，且未加壳/未重度混淆。
- `ets/sourceMaps.map` 未剥离，或 `module.json5`/`main_pages.json` 可读。
- 有 ABC 反编译工具（带插件的 JADX、ArkAnalyzer、abc2ets 等）。
- 业务逻辑主要在 ArkTS/ABC 中，或 Native 库可通过 N-API 定位。

## 利用步骤

1. 把 `.hap` 改后缀为 `.zip` 解压，列出 `ets/`、`resources/`、`module.json5`、`libs/`。
2. 读 `module.json5` 的 `mainElement`/`pages`，读 `main_pages.json` 得到页面列表；从 `EntryAbility.onWindowStageCreate` 确认首屏。
3. 检查 `ets/sourceMaps.map`：提取所有 `sources` 路径，按 `model/`、`pages/`、`entryability/` 分类，推断各模块职责（登录、数据库、加解密、Bridge）。
4. 用带 ABC 插件的 JADX 打开 `modules.abc`，按 `func_main_0` 的 `newlexenvwithname` 建立 `_lexenv_X_Y_` → 函数名映射。
5. 按 `asyncfunctionenter/suspendgenerator/resumegenerator` 模式跳过 async/await 模板，定位真实业务调用；跟踪 `AppStorage` 读写、字符串常量、硬编码密钥/哈希/密文。
6. 若逻辑进入 `libs/*.so`，搜索 `napi_` 注册函数，定位导出方法与参数；结合 IDA/Ghidra/Unicorn 分析。
7. 检查 `resources/rawfile/` 下的 H5/JSON/配置，区分展示层与真实逻辑（可能是障眼法）。

## PoC

```bash
# 1) 解包
unzip Bridge.hap -d Bridge_hap
ls Bridge_hap/ets Bridge_hap/resources Bridge_hap/libs

# 2) 看配置与路由
cat Bridge_hap/module.json5
cat Bridge_hap/resources/base/profile/main_pages.json

# 3) 看 sourceMaps 泄露的源码树
python - <<'PY'
import json
m = json.load(open('Bridge_hap/ets/sourceMaps.map'))
for k in m: print(k)
PY

# 4) 用带 ABC 插件的 JADX 反编译
jadx-gui Bridge_hap/ets/modules.abc
```

```text
# 字节码模式 → ArkTS 语义
newlexenvwithname([2, "reject", 0, "resolve", 1], 2)
  -> 闭包/词法环境，_lexenv_0_0_=resolve, _lexenv_0_1_=reject
asyncfunctionenter + suspendgenerator + resumegenerator + getresumemode
  -> let x = await someAsyncCall()
```

## 变体与关联

- 包类型变体：多 HAP（Entry/Feature）、HSP 动态共享包、HAR 静态共享包；逻辑可能跨包，需同时解包。
- 保护变体：ABC 混淆（`#~@0>#` 符号）、字符串加密、Native 加壳、反调试；需先脱壳/解密常量。
- Native 变体：N-API 导出、JNI 风格封装、Unicorn 黑盒执行；见 [[mobile-harmony-arkts-napi-obfuscated-constants-sm4-vm-flag]]、[[mobile-harmony-hap-arkts-native-sbox-affine-unicorn]]。
- 关联：[[mobile-android-webview-jsbridge-arbitrary-origin-credential-theft]]（WebView/JSBridge 信任边界）、[[ctf-reverse-android-arm64-jni-unicorn-offline-oracle]]（移动端 native 逆向）。

## 检测与防御

- 检测：发布包中存在 `sourceMaps.map`、未混淆的类名/字符串、硬编码密钥/哈希/密文；HAP 内 `rawfile` 含敏感配置；WebView 暴露敏感 JSBridge 方法。
- 防御：发布构建剥离 `sourceMaps.map`；启用 ABC 混淆/字符串加密；密钥与凭据放服务端或安全存储，不要硬编码在客户端；WebView 做域名白名单与 JSBridge 鉴权。
- 加固：HAP 加壳/完整性校验；敏感逻辑下沉到服务端；对 `rawfile` 与 WebView 加载内容做审计。
