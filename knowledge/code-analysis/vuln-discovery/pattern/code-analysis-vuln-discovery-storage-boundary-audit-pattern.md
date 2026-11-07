---
id: code-analysis-vuln-discovery-storage-boundary-audit-pattern
title: 存储抽象层边界审计：校验调用点、条件化 sanitize 与可热写安全配置
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: storage-boundary-audit-pattern
aliases:
- 存储层路径边界审计
- 校验函数覆盖审计
- 条件化 sanitize 反模式
- 安全配置可写域审计
- path.join jail 检查
- 配置热加载信任域
tags:
- code-audit
- storage
- path-traversal
- validation-coverage
- config-integrity
- security-invariant
- grep
- nodejs
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:44:27+08:00'
  notes: 已对照原文核对；四类审计要点、grep 命令、ONLYOFFICE 判读示例与原文 0x08/0x09 一致，属审计方法卡，不含可利用性断言，边界准确。
---

## 一句话结论

审计带“存储抽象层 + 运行时可改配置”的服务时，优先检查四件事：全链路唯一的路径拼接口有没有根目录 jail、守卫函数的调用点是否覆盖所有写入路径、归一化是否被请求可控的条件包住、以及安全开关/可执行路径是否来自可热写配置；这四类缺陷通常比单个注入点更能解释“每环都补过却仍然串起来”。

## 原理

### 1）边界应在层，不在调用点

- 若所有写入最终都经过同一个 `path.join(storageRoot, key)`，那么路径边界必须放在这个函数里；放在各个 Controller/Service 调用点，覆盖率就等于“还有人记得再调一次”。
- 典型缺陷形状：存在 `utils.checkPathTraversal(ctx, docId, rootDirectory, filename)`，但全仓只有两处调用，且都在另一条业务线；实际写入路径一次都没调用。
- 更便宜的判据：**守卫函数的调用点数明显少于写入路径数**，它就已经站在错的那一侧。再看它的形参是否被使用——形参存在、实现里从未使用，说明写它的人知道这个输入与穿越有关，但没有真正处理。

### 2）`if (<请求可控>) { sanitize() }` 等于没 sanitize

- 安全属性不能挂在业务分支上。比如 `if (SAVE_TYPE_COMPLETE_ALL !== saveType) { filename = basename(...) + saveIndex + ext; }`，`saveType` 来自请求体，攻击者把它设成枚举值即可整段跳过归一化。
- 同族形状：`if (!cmd.getSaveKey()) { cmd.setSaveKey(...) }`——body 自带 `savekey` 时安全赋值不执行。
- 判据：归一化/校验语句外层是否有 `if`/`&&`，条件是否来自请求。

### 3）拼接 key 的每个字段都当作攻击者可控

- key 常由 `id + saveKey + '/' + filename` 三段拼成；只收敛其中一段（哪怕是最“显然”的 `format`）不够，层数够就能出去。
- 校验对象与实际使用的变量必须一致：URL 段 `:docid` 过了正则，不代表 body 里的 `id` 也过了；`getDocId()` 可能返回 body 字段并覆盖 URL 值。
- 白名单字符集是否包含 `.`/`..` 只有在该白名单真正作用到拼路径的字段上时才重要；先证明“校验作用在这个字段上”，再讨论“字符集松不松”。

### 4）编码/归一化 helper 可能是穿越放大器

- 为跨平台兼容把 `\` 统一替换成 `/` 的代码，在 Linux 上会把 `path.join` 原本当作字面文件名的 `..\..\x` 变成真正的 `../../x`。
- 任何“看起来只是格式化”的 `replace`/`normalize`/`decode` 都要检查它是否改变了路径语义；要跑对照组（替换 vs 不替换）才能下结论。

### 5）安全开关与可执行路径不得住在可写域

- 典型形状：生产配置默认 `runtimeConfig.filePath = Data/runtime.json`，该文件被热加载并与基础配置深合并；`token.enable.browser`、JWT secret、`x2tPath`/`args` 都可被覆盖。
- 后果分层：默认部署的鉴权开关本来就是 false，问题不在“降级”；已加固部署（`local.json` 里开了 JWT）会被 runtime 层静默改回 false，这是**对安全加固的回退**，且无告警。
- 必须数清注入通道：一条是 per-request 的 `ctx.getCfg` 合并；另一条是启动期读取 runtime 文件、替换全局 `config` 单例（`process.env.NODE_CONFIG` + `reloadNpmModule('config')`）。只堵一条等于只堵一半。
- 配置内容没有 schema/key 白名单时，`deepMergeObjects`/`extendDeep` 还可能被 `__proto__`/`constructor` 污染。

### 6）“修复以参数补丁沉积”是层缺失的信号

- 仓库里可能散落多片正确但局部的修复：调用者级 `checkPathTraversal`、字段级 `parseInt(saveIndex)`、字段级 `setSaveKey`、另一条路的 `DOC_ID_REPLACE_REGEX`、新 helper `resolveConverterPath`。每片都对，但都不构成边界。
- 看到多片“同一问题、不同参数”的修复，应直接去找那个所有路径共用的层入口，而不是再加第六片。

## 触发条件

- 目标为带存储抽象层（本地/对象存储统一 `putObject`）的服务，或运行时配置可热加载的服务。
- 代码可读（源码/反编译），能定位 Controller → Service → storage → 文件系统/配置读取的调用链。
- 审计者能运行 grep/静态分析，必要时用 harness 直接调用真实函数验证路径落点。

## 利用步骤（审计流程）

1. 找唯一穿盘口：`grep -rn "path\.join(" --include=*.js src/ | grep -iE "storage|disk|fs|save"`，确认是否有根目录 jail。
2. 数校验覆盖：`grep -rn "checkPathTraversal\|validatePath\|sanitizePath" --include=*.js src/`，对比写入路径数量；检查守卫函数的形参是否被使用。
3. 找条件化 sanitize：`grep -rn -B2 "basename(\|normalize(\|replace(.*REPLACE_REGEX" --include=*.js src/ | grep -E "if *\(|!==|==="`；逐条确认条件是否请求可控。
4. 找安全配置可写通道：`grep -rn "getCfg\|getConfig(" --include=*.js src/ | grep -iE "token|auth|enable|secret"`；确认这些 key 是否来自运行时文件合并。
5. 找可执行路径热改：`grep -rn "spawn\|execFile\|fork(" --include=*.js src/ | grep -iE "cfg|config"`；检查绝对路径是否被原样接受。
6. 用 harness 直接调用真实函数，把“字段被某个校验挡住了”翻译成一条用例，观察文件实际落点；只读代码无法证明“防护缺失也不会出事”。

## PoC

无 PoC（审计方法）。可直接复用的检查片段：

```bash
# 1) 唯一穿盘口有没有 jail
grep -rn "path\.join(" --include=*.js src/ | grep -iE "storage|disk|fs|save"

# 2) 校验函数调用点数 vs 写入路径数
grep -rn "checkPathTraversal\|validatePath\|sanitizePath" --include=*.js src/

# 3) 归一化有没有被请求可控条件包住
grep -rn -B2 "basename(\|normalize(" --include=*.js src/ | grep -E "if *\(|!==|==="

# 4) 安全开关是否走运行时可写配置
grep -rn "getCfg\|getConfig(" --include=*.js src/ | grep -iE "token|auth|enable|secret"

# 5) 可执行文件位置是否可热改
grep -rn "spawn\|execFile\|fork(" --include=*.js src/ | grep -iE "cfg|config"
```

判读示例（ONLYOFFICE 审计）：`checkPathTraversal` 全仓 2 个调用点、storage 写入路径未调用；`saveParts` 的 `basename` 在 `if (saveType !== 3)` 内；`runtime.json` 默认位于 `Data/` 且被两个进程热加载；`resolveConverterPath` 对绝对路径原样返回。四项共同构成“边界缺失”而非“某个参数没过滤”。

## 变体与关联

- 变体：Java/Spring 的 `ResourceUtils`/`Paths.get`、Go 的 `filepath.Join`、Python 的 `os.path.join` 都有同类“唯一拼接口无 jail”问题。
- 变体：配置热加载可换成 feature flag、CI 变量、应用可写的 `local.json`；核心判据仍是“安全开关是否住在写原语够得到的域”。
- 关联：[[web-java-component-onlyoffice-storage-key-path-traversal-file-write]]、[[web-java-component-onlyoffice-runtime-config-hot-reload-downgrade]]。
- 关联：[[code-analysis-sast-codeql-custom-taint-steps]]（用 CodeQL 补污点传播，适合自动化发现同类路径）。

## 检测与防御

- 边界下沉：在 storage 层统一 `resolve + normalize + startsWith(root + sep)`，越界拒绝或收敛；所有写入路径共用。
- 无条件校验：归一化/白名单不放在请求可控的 `if` 分支里；所有拼接字段使用同一套严格字符集/枚举。
- 安全配置分域：`token.enable.*`、secret、可执行路径只从启动期只读基线读取；runtime 层按 key 白名单过滤；runtime 文件只读挂载。
- 补不变量测试：断言“任意 storage key 都不能逃出 folderPath”；对配置合并断言安全 key 不被 runtime 覆盖。
- 监控：FIM 盯配置文件、进程派生告警（可执行文件不在安装根）、搜索守卫函数日志（但要认识到“无日志≠无穿越”）。
- 代码评审清单：守卫调用点是否覆盖全部写入路径、守卫形参是否被使用、每个拼接字段是否都被约束、配置读取入口是否运行时可写。
