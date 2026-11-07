---
id: cloud-cicd-gradle-wrapper-jar-backdoor-webp-classloader-llvm-vm
title: Gradle Wrapper jar 供应链后门：.webp 伪装 class 自定义 ClassLoader + LLVM IR 解释器加密外传源码
type: scenario
domain: cloud
path: cloud/ci-cd
technique: gradle-wrapper-jar-backdoor-webp-classloader-llvm-ir-exfiltration
tags:
- supply-chain
- ci-cd
- gradle
- wrapper
- classloader
- steganography
- llvm
- exfiltration
- reverse
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:15:14+08:00'
  notes: 已对照 Thief 段核对：GradleWrapperMain 加载 .webp class、i.l.L.run 递归 .java、3 文件/批、序列化格式、LLVM IR 解释器 algo2/algo3 均吻合；PoC 未执行
url: /docs/cloud/ci-cd/cloud-cicd-gradle-wrapper-jar-backdoor-webp-classloader-llvm-vm/
draft: false
kb_aliases:
- Gradle Wrapper 后门
- gradle-wrapper.jar 植入
- .webp 伪装 class
- 自定义 ClassLoader
- LLVM IR 解释器
- 构建期源码外传
- Thief
---

## 一句话结论

在 `gradle-wrapper.jar` 的 `GradleWrapperMain` 中植入后门：Gradle Wrapper 启动时遍历 `app/src/main/res/mipmap-hdpi`，把 `.webp` 文件当作 `.class` 字节码用自定义 ClassLoader 加载并执行 `i.l.L.run`；后门递归收集项目 `.java` 源码，按 3 个一批压缩/加密/序列化后发往攻击者服务器，加密由内嵌的 LLVM IR 解释器执行（algo3 为固定 LFSR，algo2 为状态型 XOR，可用已知明文恢复初始状态）。

## 原理

- **Wrapper jar 是构建入口**：`gradle-wrapper.jar` 通常随项目提交并被 CI/开发者执行；修改其中的 `GradleWrapperMain` 即可在任何 `./gradlew` 调用时执行恶意代码，且不易被源码审计发现（二进制 jar）。
- **`.webp` 伪装字节码**：后门从 `res/mipmap-hdpi` 读取 `.webp`（正常图片资源），排除 `ic_launcher.webp`/`ic_launcher_round.webp`；自定义 `ClassLoader.defineClass(null, bytes, 0, len)` 把图片内容当 class 加载，`findClass` 命中后返回。这样恶意 class 不以 `.class`/`.jar` 形式出现，绕过简单的文件类型扫描。
- **分批外传**：`i.l.L.run` 从项目上一级目录递归查找 `.java`，跳过 `build`/`.gradle`/`.git`/`.idea`/`target` 等目录；每 3 个文件一个 batch，压缩、加密、序列化后发送到 `127.0.0.1:8889`（题目模拟 C2），处理 9 个文件后停止。
- **序列化格式**：magic `0x89 'a' 'l' 'i'`、batch ID（4 字节 LE）、加密 key 长度、RSA 加密的 key、文件数、ToC（文件名长度、XOR 233 的文件名、data offset）、加密数据块。
- **LLVM IR 解释器**：`i.l.Runner.encrypt` 不是普通加密函数，而是一个 LLVM IR 字节码解释器入口；第一个参数按 batch ID 选择不同 bytecode，因此有 2 套算法。解释器类 `$___` 被虚假控制流等混淆；它只支持少量 LLVM IR 指令（ADD/SUB/MUL/UDIV/SDIV/UREM/SREM/SHL/LSHR/ASHR/AND/OR/XOR/ICMP/ALLOCA/LOAD/STORE/BR/SWITCH/GETELEMENTPTR/CAST/PHI/SELECT 等），可以写转换器把自定义 bytecode 还原为标准 LLVM IR 分析。
- **algo2（状态型 XOR）**：`state[16]` 由 key 前 16 字节 XOR 0x3C 初始化；每字节 `k=state[0]^state[1]`，`out=in^k`，`feedback=state[0]^state[5]`，state 左移，`state[15]=feedback`。key 在序列化头里被 RSA 加密，攻击者不能直接解密；但 batch 的第一个文件是 Android 项目自身代码（已知明文），可用“明文+密文”反推初始 state，再解密后续数据。
- **algo3（固定 LFSR）**：`state=0x125e`；每 bit 输出 `state&1`，`feedback_mask=(state&1)?0xB400:0`，`state=(state>>1)^feedback_mask`，按位组装 keystream，`out=in^keystream`。未使用 key，可直接实现解密。
- **flag 还原**：解密出的 `flagImage` 为 6 张图片，拼接/OCR 即得 flag。

## 触发条件

- 项目使用 Gradle Wrapper，且 `gradle-wrapper.jar` 被替换/植入恶意 `GradleWrapperMain`；开发者或 CI 执行 `./gradlew`。
- 项目包含 `app/src/main/res/mipmap-hdpi` 目录与 `.webp` 资源（Android 项目常见）；恶意 class 以 `.webp` 形式随资源提交。
- 后门可访问项目源码与网络；目标允许向 C2 外联（题目为本地 127.0.0.1:8889）。
- 分析者需获取 wrapper jar、资源与样本，能反编译 Java/LLVM bytecode；algo2 需要已知明文（项目源码）。

## 利用步骤

1. **植入**：修改 `gradle-wrapper.jar` 中的 `GradleWrapperMain`，加入 `.webp` 加载与 `i.l.L.run` 调用；把恶意 class 字节码命名为合法 `.webp` 放入 `res/mipmap-hdpi`。
2. **执行**：开发者/CI 运行 `./gradlew`，Wrapper 启动即加载 `.webp` class 并执行。
3. **收集**：`run` 递归查找 `.java`，每 3 个一批，压缩后按 batch ID 选择 algo2/algo3 加密，序列化并发送到 C2。
4. **分析（防御/取证）**：解包 wrapper jar，定位 `GradleWrapperMain` 的异常文件遍历/ClassLoader 代码；提取 `.webp`，用 `defineClass` 逻辑还原 class；反编译 `i.l.L.run` 与 `Runner.encrypt`。
5. **还原加密**：把 `$___` 的 bytecode 转成 LLVM IR，识别 2 套算法；algo3 直接实现 LFSR 解密；algo2 用第一个已知源码文件的明文/密文恢复 state，再解密其余数据。
6. **取 flag**：拼接解密出的 6 张图片。

## PoC

```java
// 后门加载 .webp 为 class 的关键逻辑（示意）
File dir = new File(wrapperJar().getParentFile().getParentFile().getParentFile(),
                    "app/src/main/res/mipmap-hdpi");
for (File f : dir.listFiles()) {
    if (f.getName().endsWith(".webp")
        && !f.getName().equals("ic_launcher.webp")
        && !f.getName().equals("ic_launcher_round.webp")) {
        byte[] b = Files.readAllBytes(f.toPath());
        Class<?> c = defineClass(null, b, 0, b.length);   // 自定义 ClassLoader
        // 调用 i.l.L.run
    }
}
```

```python
# algo3：固定 LFSR 解密
def algo3_decrypt(data):
    state = 0x125e
    out = bytearray()
    for c in data:
        ks = 0
        for bit in range(8):
            out_bit = state & 1
            state = (state >> 1) ^ (0xB400 if (state & 1) else 0)
            ks |= out_bit << bit
        out.append(c ^ ks)
    return bytes(out)
```

algo2 的初始 state 需用已知明文反推；完整样本的 bytecode/序列化字段需按目标样本解析。本卡不执行 PoC。

## 变体与关联

- **其它构建包装器**：`maven-wrapper.jar`、`npm` postinstall、`pip` build backend、`gradle` init script 都可植入同类后门；核心是“构建入口 + 资源伪装 + 外传”。
- **伪装载体**：`.webp`、`.png`、`.so`、测试资源、 licence 文件；自定义 ClassLoader 也可从任意资源加载。
- **加密/解释器**：LLVM IR 解释器、WASM、Lua VM、自定义字节码都可增加逆向难度；已知明文/选择明文是常见突破口。
- **关联**：[[cloud-cicd-jlink-java-base-jmod-backdoor]]（构建产物后门）、[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（安装脚本后门）、[[ai-security-supply-chain-agent-skill-unicode-tag-hidden-instruction-rce]]（供应链投毒）。
- **边界**：需要执行被篡改的 wrapper jar且资源目录存在；若 CI 校验 wrapper 哈希、使用系统 Gradle、或禁止网络外联，后门失效/受限。

## 检测与防御

- **完整性校验**：对 `gradle-wrapper.jar` 做哈希/签名校验（Gradle 官方 checksum），CI 固定版本；不要把 wrapper jar 当作不可审计的二进制。
- **构建隔离**：CI 在无源码/无网络的沙箱中运行构建，限制构建脚本访问项目外文件；使用最小权限账号。
- **资源扫描**：检查 `res/` 下非图片格式的 `.webp`（class 魔数 `CAFEBABE`、异常熵/大小）；扫描自定义 ClassLoader/`defineClass`/`Files.readAllBytes` 模式。
- **网络监控**：构建期出现到陌生 IP/端口的连接、序列化 magic `0x89 'a' 'l' 'i'`；限制 CI 出网白名单。
- **响应**：轮换构建凭据/密钥、重建构建环境、审计所有使用该 wrapper 的项目、检查源码是否外泄。
