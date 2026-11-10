---
id: web-java-deser-objectstreamclass-private-readobject-hook
title: Java 自定义序列化钩子：ObjectStreamClass 只识别 private 的 readObject/writeObject/readObjectNoData，public 版本不执行
type: scenario
domain: web
path: web/java/deserialization
technique: objectstreamclass-private-serialization-hooks
tags:
- java
- deserialization
- serialization
- objectstreamclass
- readobject
- writeobject
- readobjectnodata
- mechanism
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:39:52+08:00'
  notes: 已对照原文与全部13张图片核对：public readObject 不被调用、ObjectInputStream.readObject 为 public final、Person 父类 Object 无 readObject、Serializable Javadoc 精确 private 签名、ObjectStreamClass 494-507 行 getPrivateMethod 查找 writeObject/readObject/readObjectNoData、hasReadObjectMethod 与 readSerialData 1892-1900 调用点，均与卡一致。修正：原文'抛不同受检异常导致不匹配'表述不准确（getDeclaredMethod 只匹配方法名+参数，private/返回类型另行校验），已改为'多一个参数、返回非 void 等签名差异'。dedup top 候选（自定义 readObject 利用/rmiconnector/signedobject）均 related 不同链，判新增成立；无版本/CVE/sources/URL，路径 web/java/deserialization 合法。
url: /docs/web/java/deserialization/web-java-deser-objectstreamclass-private-readobject-hook/
draft: false
kb_aliases:
- readObject 为什么必须是 private
- public readObject 不执行
- 自定义序列化 readObject
- ObjectStreamClass getPrivateMethod
- readObject 不是重写
- readObjectNoData 签名
---

## 一句话结论

反序列化时被调用的自定义 `readObject` 并不是对父类方法的重写：`Serializable` 是空接口，`ObjectInputStream.readObject()` 是 `public final` 不可重写，`Person` 的父类 `Object` 也没有 `readObject`；真正发生的是 `ObjectStreamClass` 在建立类的序列化描述符时用 `getPrivateMethod` 查找本类中签名为 `private void readObject(ObjectInputStream)` 的方法，只有找到（`hasReadObjectMethod()` 为真）`ObjectInputStream.readSerialData` 才会调用它，否则执行 `defaultReadFields` 读取默认字段——所以把 `readObject` 写成 `public` 时它不会被识别和执行。

## 原理

- **“重写”是误解**：`ObjectInputStream.readObject()` 在 JDK 源码中是 `public final Object readObject()`，`final` 方法不能被子类重写；`ObjectInputStream` 也不是业务类的父类；业务类只实现 `Serializable` 空接口，父类是 `Object`，而 `Object` 没有 `readObject`。因此所谓“重写 readObject”实际上是按约定签名实现的**序列化回调钩子**。
- **Serializable 的官方约定**：Javadoc 明确写出需要特殊处理序列化的类必须实现以下精确签名：`private void writeObject(java.io.ObjectOutputStream out)`、`private void readObject(java.io.ObjectInputStream in)`、`private void readObjectNoData()`；签名中的 `private` 是约定的一部分，不是风格问题。
- **ObjectStreamClass 的查找**：`ObjectStreamClass` 是类的序列化描述符（包装 `Class` 的字段/`serialVersionUID` 等信息）。非 `Externalizable` 分支中执行：
  - `writeObjectMethod = getPrivateMethod(cl, "writeObject", new Class<?>[]{ObjectOutputStream.class}, Void.TYPE)`
  - `readObjectMethod = getPrivateMethod(cl, "readObject", new Class<?>[]{ObjectInputStream.class}, Void.TYPE)`
  - `readObjectNoDataMethod = getPrivateMethod(cl, "readObjectNoData", null, Void.TYPE)`
  其中 `getPrivateMethod` 用 `getDeclaredMethod` 找方法并检查 `Modifier.isPrivate`；不满足 private 或签名不符时返回 null。
- **调用点**：`ObjectInputStream.readSerialData` 遍历类层次中每个 `ClassDataSlot`：`if (slotDesc.hasReadObjectMethod()) { ... slotDesc.invokeReadObject(obj, this); } else { defaultReadFields(obj, slotDesc); }`。`hasReadObjectMethod()` 即 `readObjectMethod != null`。public 版本使 `readObjectMethod` 为 null，于是走默认字段读取，自定义逻辑被静默跳过。
- **类层次行为**：序列化按类层次从父到子处理，每个类各自的 private 钩子只在该类的 slot 被调用；子类不会“继承”父类的 readObject 回调来替代自己的。`readObjectNoData` 在流中缺少对应类数据时调用；`readResolve` 是另一个独立钩子（在 readObject 之后、替换返回值）。
- **为什么容易踩坑**：把 `readObject` 写成 public 编译完全通过、代码看起来正确，但序列化框架按反射签名匹配，不会报错也不会调用；同样，多一个参数、返回非 void 等签名差异都会导致不匹配（`getDeclaredMethod` 只按方法名与参数类型匹配，private 与返回类型另行校验）。

## 触发条件

- 使用 Java 原生序列化（`ObjectOutputStream`/`ObjectInputStream`）并希望自定义某类的反序列化行为（补默认字段、校验、触发 gadget）。
- 类实现 `Serializable`（非 `Externalizable` 时不走 `readExternal`）。
- 需要理解/编写 gadget、payload 类或防御性校验时的钩子签名。

## 利用步骤

1. 定义 `class Person implements Serializable`，写 `private void readObject(ObjectInputStream in)`，内部先 `in.defaultReadObject()` 再打印/校验。
2. 序列化后反序列化，观察自定义逻辑被调用（打印出现）。
3. 把修饰符改为 `public` 再测：自定义逻辑不再执行，对象字段仍按默认机制恢复——证明钩子未被识别。
4. 用反射或调试查看 `ObjectStreamClass.lookup(Person.class)` 内部的 `readObjectMethod` 是否为 null（public 时为 null，private 时非 null）。
5. 编写 gadget/payload 类时确保钩子为 `private` 且签名为 `(ObjectInputStream)` 返回 void；需要 no-data 行为时同时实现 `private void readObjectNoData()`。

## PoC

```java
import java.io.*;

public class Person implements Serializable {
    public String name;
    private int age;

    // 正确：private，反序列化时会被 ObjectStreamClass 识别并调用
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        System.out.println("custom readObject called");
    }

    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) { oos.writeObject(new Person()); }
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
            ois.readObject();   // 输出 custom readObject called
        }
    }
}
```

把 `private` 改为 `public` 后同一程序不再输出该行，字段仍被默认读取；`ObjectInputStream.readObject()` 本身是 `public final`，与业务类的钩子无关。

## 变体与关联

- 变体：`writeObject(ObjectOutputStream)` 在序列化时同理必须是 private；`readObjectNoData()` 处理流中缺少类数据；`readResolve()` 用于替换反序列化结果（枚举/单例常见）；`Externalizable` 则实现 public 的 `writeExternal/readExternal`，走另一条路径。
- 关联卡片：[[web-java-deser-readobject-reflection-rmiconnector-secondary]]（利用自定义 readObject 反射调用构造二次反序列化链）；[[web-java-deserialization-app-readobject-controlled-put-aspectj-file-write]]（readObject 内可控 put 的 gadget）；建议在编写任何自定义 Serializable gadget 时先确认钩子签名。
- 边界：JDK 9+ 模块封装影响反射访问内部类，但不改变钩子必须 private 的规则；`ObjectInputFilter`/JEP290 是在此之前的上层过滤，不改变签名匹配。

## 检测与防御

- 代码审计：搜索 `void readObject(ObjectInputStream`、`void writeObject(ObjectOutputStream`、`readObjectNoData`，确认修饰符为 private；public 版本是死代码（不会被执行），若业务依赖其逻辑则是隐蔽 bug。
- 安全视角：readObject/readResolve 等钩子会在不可信数据上自动执行，是反序列化 gadget 的常见入口；对不可信流使用 `ObjectInputFilter` 白名单/JEP290，并审计钩子中的危险操作（反射调用、JNDI、文件写、方法句柄）。
- 开发规范：自定义序列化钩子严格按 `Serializable` Javadoc 的 private 签名实现，并在钩子内校验字段合法性。
