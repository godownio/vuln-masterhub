---
id: hessian-deserialization-serializerfactory-getdeserializer-hook-blacklist
title: Hessian 反序列化通防：匿名 SerializerFactory 重写 getDeserializer(String) 按类名黑名单拦截（对比 resolveClass 原生 hook）
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-serializerfactory-getdeserializer-hook
tags:
- java
- hessian
- deserialization
- defense
- blacklist
- hook
- awd
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-30
  verified_at: '2026-11-08T15:50:14+08:00'
  notes: 已对照原文核对：匿名 SerializerFactory 重写 getDeserializer(String) 的 hook 方式与原文代码一致；img03 断点证实 type 即反序列化类名（com.sun.syndication.feed.impl.EqualsBean），img04 控制台证实 hook 输出类名可拦截；setSerializerFactory 指定工厂、与 resolveClass 原生 hook 对比均符原文；4.0.38 仅为文中 Maven 测试环境版本，affected_versions 保持空正确；防御类卡无攻击链要求，无 sources/source_url（全库现状）
url: /docs/web/java/deserialization/hessian/hessian-deserialization-serializerfactory-getdeserializer-hook-blacklist/
draft: false
kb_aliases:
- Hessian 反序列化 hook
- Hessian 通防
- SerializerFactory getDeserializer 黑名单
- Hessian2Input setSerializerFactory
---

## 一句话结论

对 Hessian2Input 反序列化入口做类名级拦截，可通过 `setSerializerFactory` 传入匿名 SerializerFactory 并重写 `getDeserializer(String type)` 检查每个反序列化到的类名实现黑名单通防，无须修改 Hessian 包源码；相比 WAF 对 base64 解码串做子串检测，该方式不受 Hessian UTF-8 Overlong Encoding 类名混淆绕过影响。

## 原理

Hessian2Input#readObject 的各 case 分支（读 list/map/object 等）都会调用 `findSerializerFactory()` 获取 SerializerFactory——它是 Hessian 各类反序列化器（Deserializer）的管理工厂。`SerializerFactory.getDeserializer(String type)` 在按类型名取反序列化器时，type 参数正是流中出现的类名（调试可见如 com.sun.syndication.feed.impl.EqualsBean）；因此重写该方法即可像原生反序列化重写 ObjectInputStream#resolveClass 一样拿到每个类的类名做匹配。又因 Hessian2Input 提供 `setSerializerFactory(SerializerFactory)` 公开 setter，可用匿名内部类替换工厂而不必改包内字节码；未命中黑名单时调用 `super.getDeserializer(type)` 保持原语义。原生的 resolveClass hook 则是在 ObjectInputStream 匿名子类中比对 ObjectStreamClass#getName。

## 触发条件

防御方视角：应用使用 Hessian（如 com.caucho:hessian 4.0.x）反序列化外部数据；在反序列化调用点部署本 hook。攻击视角：该防御可被绕过的方式是黑名单外的 gadget 节点类（黑名单需覆盖如 java-chains 项目中各链的关键节点）。

## 利用步骤

防御部署步骤（无攻击步骤）：

1. 定位应用中 `new Hessian2Input(...).readObject()` 的反序列化入口；
2. 调用 `ois.setSerializerFactory(new SerializerFactory(){ public Deserializer getDeserializer(String type){ ...黑名单比对，命中抛 SecurityException；否则 return super.getDeserializer(type); } })`；
3. 黑名单按 java-chains 覆盖各链关键节点：java.lang.Runtime、java.lang.ProcessBuilder、javax.management.BadAttributeValueExpException、TemplatesImpl、java.security.SignedObject、com.sun.jndi.ldap.LdapAttribute、com.sun.rowset.JdbcRowSetImpl、javax.naming.InitialContext、InvokerTransformer、JdkDynamicAopProxy、JSONArray/POJONode/ToStringBean/EqualsBean/XString/UIDefaults/SwingLazyValue/ProxyLazyValue、groovy、sun.print.UnixPrintService 等；避免加入集合类以防误伤；
4. 原生反序列化入口同理：匿名子类重写 resolveClass 比对 desc.getName()。

## PoC

```java
Hessian2Input ois = new Hessian2Input(new ByteArrayInputStream(arr));
ois.setSerializerFactory(new SerializerFactory() {
    public Deserializer getDeserializer(String type) throws HessianException, HessianProtocolException {
        Set<String> BLACKLISTED_CLASSES = new HashSet<>();
        BLACKLISTED_CLASSES.add("java.lang.Runtime");
        BLACKLISTED_CLASSES.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        BLACKLISTED_CLASSES.add("com.sun.syndication.feed.impl.ToStringBean");
        // ...按 java-chains 补全
        if (BLACKLISTED_CLASSES.contains(type)) {
            throw new SecurityException("");
        }
        return super.getDeserializer(type);
    }
});
return ois.readObject();
```

原文实测：hook 后反序列化含 EqualsBean/ToStringBean/SignedObject 的恶意流时，getDeserializer 依次打印出各恶意类名，可成功阻拦。无攻击侧 PoC（防御卡）。

## 变体与关联

- hook 点变体：重写 `getDeserializer(Class cl)` 同样可行，readObject 内多处均经 findSerializerFactory；
- 原生反序列化对应 hook 为 ObjectInputStream#resolveClass 黑名单（匿名内部类最小化改动，AWD 常用）；
- WAF 直接对 base64 解码结果做类名子串检测的方案已被 Hessian UTF-8 Overlong Encoding（类名字节混淆）绕过，见 jdk 路径的 UTF-8 Overlong 卡；
- 黑名单类需随 java-chains 等 gadget 库更新，防不住黑名单外新链。

## 检测与防御

- 本卡即防御手段；落地要点：黑名单放行集合类避免误伤、命中抛 SecurityException 快速失败、线上版本可改为白名单更稳。
