---
id: web-java-deserialization-filter-rootchecked-first-class-bypass
title: Java 反序列化过滤器 rootChecked 短路：只校验首个白名单类导致 gadget 绕过
type: scenario
domain: web
path: web/java/deserialization
technique: deser-filter-rootchecked-whitelist-bypass
tags:
- java
- deserialization
- filter-bypass
- whitelist
- blacklist
- u8cloud
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:26:27+08:00'
  notes: 已对照原文核对：FilteredObjectInputStream.resolveClass 代码、rootChecked 短路、unserializeBlacklist.conf 内容、5.1 doAction、POST /service/FileManageServlet 序列化请求、Jackson BeanPropertyWriter/Xalan 栈与 calc 截图均一致；原文仅以 5.1 为测试环境未给影响版本区间，故清空 versions；未验证点：未实际复现 PoC
url: /docs/web/java/deserialization/web-java-deserialization-filter-rootchecked-first-class-bypass/
draft: false
kb_aliases:
- FilteredObjectInputStream 绕过
- rootChecked 绕过
- 只校验第一个类
- 反序列化白名单短路
- 用友 U8Cloud FileManageServlet
---

## 一句话结论

自定义 `ObjectInputStream.resolveClass()` 实现白名单时，若在首个白名单类匹配后设置 `rootChecked=true` 并对后续类直接放行，攻击者只要让序列化流的第一个对象是白名单类（如 `HashMap`），其内部任意 gadget 类都会绕过白名单；黑名单不全会进一步放大影响。

## 原理

- Java 反序列化每遇到一个类描述都会调用 `resolveClass()`。安全实现必须对**每一个**类做白名单校验。
- 该实现逻辑：
  ```java
  if (!fullMatch) {
      if (blackList.contains(clazz.getName())) throw ...;
      if (rootChecked) return clazz;      // 首个白名单类通过后直接放行后续所有类
  }
  if (whiteList != null) {
      for (Class white : whiteList) {
          if (white.isAssignableFrom(clazz)) { rootChecked = true; return clazz; }
      }
      throw ...;
  }
  ```
  第一次匹配到白名单类（本例 `HashMap`）就置位 `rootChecked`，之后不再执行白名单循环，任意类都返回。
- 黑名单只包含少量类（`java.net.URL`、CommonsCollections 的 `InvokerTransformer`/`InstantiateTransformer`、Spring `ObjectFactory` 等），攻击者换用不在黑名单的 gadget（如 Jackson `BeanPropertyWriter` + Xalan `TemplatesImpl` 等）即可通过。
- 根因是“只校验根对象类型”的安全假设：以为根是 HashMap 就安全，但 HashMap 的键/值可以引用任意对象，反序列化过程会递归构造它们。

## 触发条件

- 应用对不可信输入使用 `ObjectInputStream.readObject()`，并叠加了上述“首类白名单/rootChecked”式过滤；
- 白名单包含可承载任意对象的容器类（HashMap、ArrayList、POJO 等）；
- classpath 存在未被黑名单覆盖的可用 gadget；
- 攻击者可发送任意序列化字节到该接口。

## 利用步骤

1. 审计 `resolveClass`/`ObjectInputFilter`，确认白名单是否只对首个类生效（rootChecked、计数、提前 return 等）。
2. 读取黑名单文件/配置，列出被禁类，选择绕开它们的 gadget 链。
3. 构造以白名单类（如 `HashMap`）为根的序列化对象，把 gadget 放在键/值中；首个类通过后 rootChecked=true，后续类不再受限。
4. 发送到反序列化接口，触发 `readObject` 链执行命令。
5. 若无回显，用 DNS/HTTP 或写文件等方式带外。

## PoC

过滤逻辑（原文关键片段）：

```java
protected Class<?> resolveClass(ObjectStreamClass arg0) throws IOException, ClassNotFoundException {
    Class<?> clazz = super.resolveClass(arg0);
    if (clazz == null) return clazz;
    if (!fullMatch) {
        if (blackList != null && blackList.size() > 0 && blackList.contains(clazz.getName())) {
            throw new IllegalArgumentException("####### class::" + clazz);
        }
        if (rootChecked) {
            return clazz;             // 首个白名单类之后全部放行
        }
    }
    if (whiteList != null) {
        for (Class white : whiteList) {
            if (white.isAssignableFrom(clazz)) {
                rootChecked = true;
                return clazz;
            }
        }
        throw new IllegalArgumentException("####### class::" + clazz);
    }
    return clazz;
}
```

构造思路（根对象必须是白名单类）：

```java
HashMap<String, Object> head = new HashMap<>();
head.put("operType", "download");
// 将未命中黑名单的 gadget 对象放入 value；序列化后首个类为 HashMap，通过 rootChecked
```

原文使用改造后的 POJO/Jackson 链（栈中出现 `com.fasterxml.jackson.databind.ser.BeanPropertyWriter` 与 Xalan `TemplatesImpl`），通过 POST `/service/FileManageServlet` 发送序列化字节，成功弹出计算器。

## 变体与关联

- 任何“首类检查”式过滤器都可绕过：`rootChecked`、`checked` 布尔、只检查 `readObject` 返回对象类型、只校验 `getClass().getName()`。
- 黑名单绕过思路：换 gadget 家族（CommonsBeanutils、Jackson、Groovy、Spring 等），或用不在名单的 Transformer 变体。
- 若过滤器允许 `HashMap` 但业务逻辑会读取其字段，可不依赖 gadget 直接滥用业务功能（见同文章的 HashMap 业务字段文件读取场景）。
- 关联：JEP 290 ObjectInputFilter 配置错误、ysoserial gadget、Fastjson AutoType 绕过。

## 检测与防御

- 使用 JEP 290 `ObjectInputFilter`（`ObjectInputFilter.Config.setObjectInputFilter`）并对每个类、数组长度、深度、引用数做限制；不要注释掉过滤器。
- 白名单必须对每个类生效：删除 `rootChecked` 短路，或使用 `fullMatch` 全量匹配；容器类本身不能视为“安全根”，应限制其元素类型。
- 黑名单只能作为补充，不能作为主防线；优先移除危险 gadget 依赖（CommonsCollections 等）。
- 禁止反序列化不可信输入；需要跨进程传输时改用 JSON/Protobuf 等数据格式并做 schema 校验。
- 监控反序列化接口的异常、`resolveClass` 拒绝日志与异常大的序列化请求。
