---
id: web-java-deser-fastjson-basicdatasource-bcel-no-egress
title: Fastjson 不出网利用：BasicDataSource DriverClassName $$BCEL$$ + BCEL ClassLoader 动态加载字节码
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-basicdatasource-bcel-classload
aliases:
- fastjson BCEL
- BasicDataSource BCEL
- $$BCEL$$
- DriverClassLoader
- fastjson 不出网
tags:
- java
- fastjson
- deserialization
- bcel
- classloader
- dbcp
- no-egress
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: fastjson < 1.2.24（原文分节标记 FastJson<1.2.24）
verification:
  verified_by: verifier-V692
  verified_at: '2026-11-13T17:50:35+08:00'
  notes: 已对照原文与36张图逐张核对：图01-09 JSON.parseObject→DefaultJSONParser/@type LoadClass→JavaBeanInfo.build；图10-15 JdbcRowSetImpl.connect lookup 与 setDataSourceName/setAutoCommit 可控；图16-21 BCEL ClassLoader.loadClass indexOf($$BCEL$$)→createClass→Utility.decode(...,true)→ClassParser.parse→defineClass，BasicDataSource.getConnection→createDataSource→createConnectionFactory→Class.forName(driverClassName,true,driverClassLoader)，setDriverClassName/setDriverClassLoader 可控；图22-33 1.2.47 缓存/MiscCodec 调试；图34-36 1.2.43 [ 变体报错与成功。卡内按图16把'以 $$BCEL$$ 开头'修正为'类名包含 $$BCEL$$（indexOf>=0）'。三处 dedup 合并（JdbcRowSetImpl JNDI→jdbc-rowset、1.2.47 缓存→1247-class-cache-bypass、描述符绕过→autotype-descriptor-bypass-evolution）目标卡均存在且同链，rejected/index.jsonl 有记录，理由成立；原文'FastJson1.4.43'按 1.2.43 笔误处理恰当（fastjson 无 1.4.43 版本，正文自述 1.2.43 修改 checkAutoType，且既有演进卡已按 1.2.43 核对）。affected_versions 按原文分节标题 FastJson<1.2.24 设置；注意原文示例依赖 fastjson 1.2.24（图17 pom）与标题差一版本，实际为 <=1.2.24 惯用简写。未验证点：PoC 未本机复跑；JDK 8u251 移除内置 BCEL 的时间点未独立复核。
---

## 一句话结论

在无法出网或 JDK 限制远程 codebase 时，可用 fastjson 实例化 `org.apache.tomcat.dbcp.dbcp2.BasicDataSource`，把 `DriverClassLoader` 设为 `com.sun.org.apache.bcel.internal.util.ClassLoader`、`DriverClassName` 设为 `$$BCEL$$<Utility.encode 的字节码>`；随后 `getConnection()` → `createDataSource()` → `createConnectionFactory()` → `Class.forName(driverClassName, true, driverClassLoader)` 使 BCEL ClassLoader 解析类名并 `defineClass`，执行内嵌字节码（不出网）。

## 原理

- `BasicDataSource` 的 `driverClassName`/`driverClassLoader` 均有 setter；`getConnection()` 触发 `createDataSource()`，其中 `createConnectionFactory()` 用 `Class.forName(this.driverClassName, true, this.driverClassLoader)` 加载驱动。
- `com.sun.org.apache.bcel.internal.util.ClassLoader.loadClass` 对类名中包含 `$$BCEL$$`（`indexOf("$$BCEL$$") >= 0`）的请求走 `createClass`：`Utility.decode(base64, true)` 解码出 class 字节，`ClassParser.parse()` 后 `defineClass` 定义并初始化——类名本身就是载荷载体，不需要远程访问。
- 触发加载需要反序列化阶段能调用到 `getConnection()`：fastjson 的 parse→toJSON 会调用符合条件的 getter（如 `getConnection` 被 JSONObject 序列化触发），或配合 `$ref`/属性引用间接调用（1.2.47 缓存变体常见写法）。
- 依赖 JDK 内置 BCEL（JDK <= 8u251 保留在 rt.jar）与 tomcat-dbcp/dbcp2 依赖存在。

## 触发条件

- fastjson 可控 `@type`（旧版本 AutoType 开放，或结合 1.2.47 等缓存绕过）；
- classpath 有 dbcp/dbcp2（如 Tomcat 自带）与 JDK 内置 `com.sun.org.apache.bcel`（JDK <= 8u251）；
- 能构造 `Utility.encode` 后的 $$BCEL$$ 类名并让解析流程调用到 BasicDataSource 的 getConnection。

## 利用步骤

1. 编写恶意类 Demo（静态块/构造器执行命令），编译得到 .class 字节。
2. `com.sun.org.apache.bcel.internal.classfile.Utility.encode(bytes, true)` 得到 BCEL 字符串。
3. 构造 JSON：`@type` 为 `org.apache.tomcat.dbcp.dbcp2.BasicDataSource`，`DriverClassName` 为 `$$BCEL$$...`，`DriverClassLoader` 嵌套 `@type` 为 BCEL ClassLoader。
4. 让 fastjson 解析并触发 getConnection（parseObject 的 toJSON 或 $ref 引用 connection 属性）。
5. BCEL ClassLoader 定义类并执行静态代码，得到代码执行。

## PoC

```json
{"@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource","DriverClassName":"$$BCEL$$<Utility.encode(bytes,true)>","DriverClassLoader":{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader"}}
```

## 变体与关联

- 1.2.47 场景需先用 `java.lang.Class` 把 BasicDataSource 与 BCEL ClassLoader 写入缓存再引用（见已有卡）。
- 类似不出网 gadget：C3P0 `userOverridesAsString`、H2 `INIT` 别名、TemplatesImpl。
- 依赖差异：tomcat-dbcp 7 的 `dbcp.BasicDataSource`、commons-dbcp2 等类名不同。

## 检测与防御

请求体含 `$$BCEL$$`、BCEL ClassLoader 类名、`driverClassName` 异常；升级 fastjson/开启 SafeMode、移除 BCEL 内部类依赖（JDK 8u251+ 默认不再可用）、限制 @type 白名单。
