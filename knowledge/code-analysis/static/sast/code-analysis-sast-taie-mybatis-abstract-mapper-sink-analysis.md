---
id: code-analysis-sast-taie-mybatis-abstract-mapper-sink-analysis
title: Tai-e 指针分析支持 MyBatis 抽象 Mapper：MockObj 补调用边 + 抽象方法空 IR + SinkHandler 收集注解 SQL
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-mybatis-abstract-mapper-sink-analysis
aliases:
- Tai-e MyBatis 支持
- 抽象 Mapper 方法分析
- DependencyInjectionMapperObj
- MockObj 补调用边
- 抽象方法空 IR
- onCallMybatisMethod
- Mapper 接口指针分析
tags:
- sast
- taie
- pointer-analysis
- mybatis
- java
- mock-object
- abstract-method
- taint-analysis
- sink
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:24:30+08:00'
  notes: 已对照原文 0x02 核对：Spring DI 唯一 @Mapper 候选字段造 DependencyInjectionMapperObj MockObj、processCall 中 resolveCallee 为 null 时改 callSite.getMethodRef().resolve() 并补调用边、JMethod.getIR 对 abstract 返回 IRBuildHelper.buildEmpty()、SinkHandler.onCallMybatisMethod 过滤 recv 描述符并扫描 @Select/@Delete/@Insert/@Update value 收集 SQL，均与原文一致。未验证点：补丁为按文重写示意，未编译进 Tai-e 运行；原文未给 Tai-e 受影响版本，未设 versions；无 sources/URL。与 taie-java-taint-audit-toolchain 卡为通用工程化 vs MyBatis 抽象 Mapper 专项，非重复。
---

## 一句话结论

MyBatis Mapper 接口方法是抽象的：Tai-e 的指针分析在 `processCall` 里用 `resolveCallee` 解析抽象方法会得到 null，调用边建不出来；随后 `JMethod.getIR()` 对 abstract 方法直接抛异常。解决办法是给注入的 Mapper 字段创建一个专门描述符的 MockObj（如 `DependencyInjectionMapperObj`），在解析失败时改用 `invoke.getMethodRef().resolve()` 并手工补调用边，再为抽象方法返回一个空 IR；同时在插件新增回调 `onCallMybatisMethod` 中读取 `@Select/@Delete/@Insert/@Update` 注解里的 SQL 收集 MyBatis sink，使污点分析能真正走到 Mapper 方法。

## 原理

- **Mapper 是接口**：MyBatis 只为 Mapper 接口生成 JDK 动态代理/映射，业务代码注入的字段声明类型是接口，方法没有 Java 实现；Soot/Tai-e 的 IR 只存在于有方法体的类上。
- **调用边建不出来**：`CallGraphs.resolveCallee(recvObj.getType(), callSite)` 对接口方法通常返回 null（没有可解析的实现），PTA 于是走 `plugin.onUnresolvedCall(...)`，Mapper 方法不在调用图中，后续 sink 匹配 `edgesInTo(sinkMethod)` 为空。
- **Mock 描述符识别注入点**：在解决 Spring `@Autowired` 注入时，如果字段类型唯一且标注了 MyBatis `@Mapper`，就给该字段分配一个 MockObj，并在其描述符里写入 `DependencyInjectionMapperObj`。这个描述符是后续所有特判的“标签”。
- **解析回退**：`processCall` 遇到 callee 为 null 且接收者对象是上述 MockObj 时，调用 `callSite.getMethodRef().resolve()` 直接按方法引用解析出抽象 `JMethod`；再正常做 context selection、创建 CSMethod 并 `addCallEdge`，抽象方法于是进入调用图。
- **空 IR 兜底**：PTA 遍历方法语句时会调用 `getIR()`；`JMethod.getIR()` 对 `isAbstract()` 抛 `AnalysisException`。改为返回 `new IRBuildHelper(this).buildEmpty()`，让抽象方法有一个空函数体，遍历时不会崩。
- **回调收集注解 sink**：普通 sink 在 `SinkHandler.collectTaintFlows` 阶段匹配；但注解 SQL 的 sink 需要在解析到 Mapper 调用时收集。可在插件接口新增 `onCallMybatisMethod(CSObj recv, Invoke invoke)`，在 `processCall` 的 MyBatis 分支里调用；方法内过滤 `recv` 描述符、扫描 `@Select/@Delete/@Insert/@Update` 的 `value`，套用 `${}` 与参数映射逻辑（见 MyBatis sink 提取卡）后加入 `mybatisSinks` 集合。
- **为什么必须自定义匹配**：即使把 Mapper 方法加入 sink 配置，Tai-e 默认匹配也只针对有方法体/正常参数的调用；MyBatis 的抽象方法没有方法体，且参数常是 JavaBean/集合，默认逻辑无法按字段判断污点，因此需要单独的 `MybatisSink` 集合与匹配逻辑（见字段级匹配卡）。

## 触发条件

- 待分析项目用 MyBatis（接口 + XML/注解），且 Spring 注入的 Mapper 字段在 PTA 中表现为接口类型。
- 使用可扩展的 Tai-e 版本（可修改/扩展 `DefaultSolver.processCall`、`JMethod.getIR`、`SinkHandler` 或通过插件接口挂接）。
- 已能在 Tai-e 的 `World`/`JClass` 中解析 Mapper 接口与方法签名。
- 接受二次开发：需要编译修改后的 Tai-e/插件，而不是仅用官方发行版默认配置。

## 利用步骤

1. **Mock 注入字段**：在依赖注入求解逻辑里，对唯一候选且带 `@Mapper` 注解的字段 `heapModel.getMockObj(...)`，描述符设为 `DependencyInjectionMapperObj`，类型设为字段接口类型。
2. **补调用边**：在 `processCall` 中，`resolveCallee` 返回 null 且 `recvObj` 是 `DependencyInjectionMapperObj` 时，`callee = callSite.getMethodRef().resolve()`；随后照常执行 `selectContext`、`addCallEdge`、把接收者对象 points-to 传给 callee 的 `this`。
3. **空 IR**：修改 `JMethod.getIR()`，`isAbstract()` 分支不再抛异常，返回空 IR（`new IRBuildHelper(this).buildEmpty()`）；native 方法仍走 native model。
4. **新增回调**：在插件接口加入 `onCallMybatisMethod`，在 `processCall` 的 MyBatis 分支里调用（时机在 resolve 出抽象方法之后）。
5. **收集注解 sink**：回调内过滤 `recv.getObject()` 描述符，取 `invoke.getMethodRef().resolve()`，扫描 `org.apache.ibatis.annotations.(Select|Delete|Insert|Update)` 注解的 `value`，正则提取 `${...}`，按参数形态生成 `MybatisSink(method, index, field)` 加入集合。
6. **跑分析验证**：用包含 XML/注解 `${}` 注入的样例项目跑 PTA，确认调用图包含 Mapper 方法、`mybatisSinks` 非空、后续能产出 `TaintFlow`；对无 `${}` 的项目确认 sink 为空。

## PoC

关键改动示意（按原文思路重写）：

```java
// 1) 注入字段：给 @Mapper 接口字段一个可识别的 MockObj
if (candidates.size() == 1 && candidates.get(0).hasAnnotation("org.apache.ibatis.annotations.Mapper"))
    return heapModel.getMockObj(() -> "DependencyInjectionMapperObj",
                                field.getRef(), candidates.get(0).getType());

// 2) processCall：抽象 Mapper 方法解析失败时回退并补边
JMethod callee = CallGraphs.resolveCallee(recvObj.getObject().getType(), callSite);
if (callee == null && recvObj.getObject() instanceof MockObj mo
        && "DependencyInjectionMapperObj".equals(mo.getDescriptor().string())) {
    plugin.onCallMybatisMethod(recvObj, callSite);       // 收集注解 SQL sink
    callee = callSite.getMethodRef().resolve();          // 抽象方法也能解析出 JMethod
}
if (callee != null) { /* selectContext + addCallEdge + 传递 this */ }
else plugin.onUnresolvedCall(recvObj, context, callSite);

// 3) JMethod.getIR：抽象方法返回空 IR
if (isAbstract()) return new IRBuildHelper(this).buildEmpty();

// 4) 插件回调：从注解 SQL 提取 sink
@Override
public void onCallMybatisMethod(CSObj recv, Invoke invoke) {
    if (recv.getObject() instanceof MockObj mo
            && "DependencyInjectionMapperObj".equals(mo.getDescriptor().string())) {
        JMethod m = invoke.getMethodRef().resolve();
        for (Annotation a : m.getAnnotations())
            if (a.getType().matches("org\\.apache\\.ibatis\\.annotations\\.(Select|Delete|Insert|Update)")
                    && a.hasElement("value"))
                mybatisSinks.addAll(toSinks(a.getElement("value").toString(), m));
    }
}
```

## 变体与关联

- **仅 XML 的 Mapper**：不经过注解收集；由“遍历 Mapper XML 提取 sink”模块在分析前生成 sink 集合，再注入 `TaintConfig`。
- **MyBatis-Spring 的 `MapperScannerConfigurer`**：字段类型可能是代理接口，注入逻辑需在 Spring bean 解析阶段识别；若无法识别 MockObj，可退化为把所有接口方法都当 sink 源（提高召回、增大误报）。
- **Diamond/Dubbo 等接口调用**：同样的“抽象方法无 IR + resolve 失败”问题，可复用本卡的回退与空 IR 思路，但需区分哪些接口是真正的 SQL sink。
- **关联**：本卡只解决“分析能走到 Mapper 方法并收集注解 sink”；sink 的 `${}` 语义与字段/集合参数匹配见 MyBatis sink 提取与字段级匹配卡。

## 检测与防御

- **工程验证**：在扫描结果中检查命中 Mapper 方法的 `TaintFlow` 是否带正确 source；若一条 MyBatis 结果都没有，优先排查 MockObj 描述符、`processCall` 回退分支与空 IR 是否生效。
- **覆盖度回归**：构造 XML `${}` 与注解 `@Select("... ${x} ...")` 两个最小样例，确认都能产生 sink；再构造 `#{}` 样例确认不误报。
- **限制与边界**：该改造只影响 Tai-e 内部模型，不改变目标应用；分析器升级时要重新合并补丁（`processCall`、`getIR`、插件接口均为内部 API，版本间可能变化）。
- **替代路径**：若不想改 Tai-e 源码，可先用独立解析器把 MyBatis sink 导出为外部清单，再用 Tai-e 支持的 `call` sink/插件机制尽量表达；抽象方法调用图问题仍需要某种回调/桥接。
- **防御视角**：对使用 MyBatis 的应用，静态扫描应将 Mapper 接口方法视为“无方法体的 SQL 边界”，不能因为接口无实现就跳过；审计规则需覆盖 XML 与注解两种 SQL 来源。
