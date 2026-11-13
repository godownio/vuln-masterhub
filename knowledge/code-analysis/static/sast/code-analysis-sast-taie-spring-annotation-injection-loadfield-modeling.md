---
id: code-analysis-sast-taie-spring-annotation-injection-loadfield-modeling
title: Tai-e 精确建模 Spring 注解注入：@Resource/@Autowired/@Inject 注入点 + @Service/@Component 实现类 + LoadField 返回值指向集
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-spring-annotation-injection-loadfield-modeling
aliases:
- Tai-e Spring 注解注入
- 注入点识别 LoadField
- '@Resource @Autowired @Inject'
- '@Service @Component 实现类'
- 依赖注入精确建模
- Spring DI 污点分析
tags:
- java
- sast
- tai-e
- pointer-analysis
- taint-analysis
- spring
- annotation
- dependency-injection
- loadfield
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:51:41+08:00'
  notes: 已对照原文与9/9图核对：@Resource/@Autowired/@Inject 字段识别、@Service/@Component 实现类集合、字段类型子类∩实现类、按声明类可达方法筛 LoadField 并给左值变量 addPointsTo MockObj 的代码与原文一致（图7调试显示 implementor=HttpServiceImpl、var=$r4）；覆盖边界（@Repository/@Controller/@Bean/XML未纳入）已如实标注。未在本机编译运行 Tai-e 验证。
---

## 一句话结论

相比按类层次（CHA）把所有实现类都塞进接收者指向集的粗粒度做法，可以先用注解精确识别 Spring 注入关系：扫描所有类的字段，带 `javax.annotation.Resource`、`org.springframework.beans.factory.annotation.Autowired`、`javax.inject.Inject` 的字段即注入点；扫描所有类，带 `org.springframework.stereotype.Service`/`Component` 的即候选实现类；再对每个注入点，取字段声明类型的全部子类/实现类与候选实现类集合的交集，在该声明类的可达方法里找到读取该字段的 `LoadField` 语句，把交集实现类的 `MockObj` 加到 `LoadField` 返回值的指向集中，即可让后续 `invokeinterface` 精确解析到真实实现类，避免多实现类接口的误报。

## 原理

- **注入点在 IR 中的形态**：使用类字段时，Tai-e IR 会先从 `%this` 取字段，例如 `$r4 = %this.<org.joychou.controller.SSRF: org.joychou.service.HttpService httpService>;`，随后 `$r5 = invokeinterface $r4.<HttpService: String RequestHttpBanRedirects(...)>`。只要让 `$r4` 的指向集包含 `HttpServiceImpl`，调用就能被解析。
- **注入点识别**：`World.get().getClassHierarchy().allClasses()` 遍历所有类的 `getDeclaredFields()`，按 `field.hasAnnotation(...)` 判断是否为三种注入注解之一，收集 `List<JField> injectedFields`。
- **实现类识别**：遍历所有类，保留带 `@Service` 或 `@Component` 的类作为候选实现类集合（`@Repository`/`@Controller` 等未纳入，属该实现的覆盖边界）。
- **关联规则**：对每个注入字段 `field`：
  1. 取字段声明类 `jClass`，以及字段类型 `field.getType()` 的全部子类/实现类（`getAllSubclassesOf`）；与候选实现类集合求交集，得到该接口可能的注入实现。
  2. 通过 `solver.getCallGraph().reachableMethods()` 过滤出声明类为 `jClass` 的上下文方法。
  3. 遍历这些方法的 IR 语句，筛出 `LoadField` 且 `getFieldAccess().getFieldRef().resolve()` 等于该注入字段的语句，取其左值 `Var`。
  4. 对交集里的每个实现类，用 `getHeapModel().getMockObj(() -> "DEPENDENCY_INJECTION", impl.getName(), impl.getType())` 并 `addPointsTo` 到该 `Var` 的指向集。
- **为什么更精确**：CHA 版本对每个“指向集为空”的接口调用都注入所有直接实现类；注解版本只在真正声明了注入注解的字段被读取的位置补点，且用“字段类型子类 ∩ @Service/@Component 类”收敛候选，多个实现类时也能按字段类型过滤掉无关实现，减少错误调用边。
- **XML 配置同理**：解析 `<bean id/class>` 与 `<constructor-arg ref>`/`<property ref>` 得到注入关系后，同样在对应 `LoadField`（或构造参数变量）上补点即可；文章未展开实现。
- **效果**：该精确建模在 java-sec-code 上同样检出 SSRF 的 `RestTemplateUrl`/`RestTemplateUrlBanRedirects` 到 `RestTemplate.exchange` 的污点流（与 CHA 版结果一致），并可用于其它经接口注入的 sink（SQL 注入等）。
- **边界**：注解扫描只覆盖三类注入注解与两类组件注解；`@Bean` 工厂方法、`@Qualifier`、条件装配、XML、构造器注入、字段在多处被赋值等场景需要扩展；`LoadField` 只覆盖“字段读取”这一种使用方式。

## 触发条件

- 使用 Tai-e（文章为 0.5.1-SNAPSHOT）分析 Spring Boot/Spring 应用，已能构建调用图与指针分析。
- 目标代码以字段注解（`@Resource`/`@Autowired`/`@Inject`）方式注入依赖，实现类带 `@Service`/`@Component`。
- 插件可在 Tai-e 源码中编译（文章将 `DependencyInjectionHandler.java` 放入 `pascal.taie.analysis.pta.plugin.taint` 并重新打包）或通过自定义插件机制注册。
- 已配置污点 source/sink（如 `RestTemplate#exchange` 为 SSRF sink）。
- 仅用于授权代码审计。

## 利用步骤

1. 遍历 `World.get().getClassHierarchy().allClasses().map(JClass::getDeclaredFields)`，按三种注解收集注入点字段。
2. 遍历所有类，收集带 `@Service`/`@Component` 的实现类集合。
3. 对每个注入字段，取字段类型的全部子类/实现类并与实现类集合取交集。
4. 取字段声明类的全部可达上下文方法，筛出读取该字段的 `LoadField` 语句及其左值变量。
5. 将交集实现类的 MockObj 加入这些变量的指向集。
6. 在 `onPhaseFinish`（或合适的插件阶段）执行上述逻辑，重新编译并运行 Tai-e，检查调用图与 TaintFlow。
7. 对照 Spring 配置人工复核命中的实现类是否符合运行时注入。

## PoC

文章核心代码（整理）：

```java
// 1) 注入点识别
List<JField> injectedFields = new ArrayList<>();
World.get().getClassHierarchy().allClasses()
    .map(JClass::getDeclaredFields).flatMap(Collection::stream)
    .forEach(field -> {
        boolean isInjected = field.hasAnnotation("javax.annotation.Resource")
            || field.hasAnnotation("org.springframework.beans.factory.annotation.Autowired")
            || field.hasAnnotation("javax.inject.Inject");
        if (isInjected) injectedFields.add(field);
    });

// 2) 实现类识别
List<JClass> implementationClasses = World.get().getClassHierarchy().allClasses()
    .filter(cls -> cls.hasAnnotation("org.springframework.stereotype.Service")
        || cls.hasAnnotation("org.springframework.stereotype.Component"))
    .collect(Collectors.toList());

// 3) 注入点与实现类关联（压缩）
injectedFields.forEach(field -> {
    JClass jClass = field.getDeclaringClass();
    Collection<JClass> subClasses = World.get().getClassHierarchy().getAllSubclassesOf(
        World.get().getClassHierarchy().getClass(field.getType().getName()));
    List<JClass> implementors = new ArrayList<>(subClasses);
    implementors.retainAll(implementationClasses);

    Set<CSMethod> csMethodSet = solver.getCallGraph().reachableMethods()
        .filter(m -> m.getMethod().getDeclaringClass().equals(jClass))
        .collect(Collectors.toSet());
    csMethodSet.forEach(csMethod -> {
        List<Var> vars = csMethod.getMethod().getIR().getStmts().stream()
            .filter(stmt -> stmt instanceof LoadField lf &&
                lf.getFieldAccess().getFieldRef().resolve().equals(field))
            .map(stmt -> (LoadField) stmt).map(AssignStmt::getLValue).toList();
        implementors.forEach(impl -> vars.forEach(var -> solver.addPointsTo(
            solver.getCSManager().getCSVar(csMethod.getContext(), var),
            solver.getHeapModel().getMockObj(() -> "DEPENDENCY_INJECTION",
                impl.getName(), impl.getType()))));
    });
});
```

说明：以上为文章代码的最小整理，未在本机运行；原实验在 java-sec-code 上检出 SSRF 污点流。

## 变体与关联

- **粗粒度对照**：CHA 版本不解析注解，直接在“指向集为空”的调用点注入所有实现类，见 [[code-analysis-sast-taie-spring-di-cha-mockobj-callgraph]]；两卡可组合使用（先注解精确补点，再对剩余空点用 CHA 兜底）。
- **入口与 source**：Spring Controller 入口注入见 [[code-analysis-sast-taie-java-taint-audit-toolchain]]；Servlet 容器入口见 [[code-analysis-sast-taie-servlet-container-entrypoint-taint]]。
- **Sink 建模**：MyBatis SQL sink 见 [[code-analysis-sast-taie-mybatis-dollar-sink-inject-taintconfig]]、[[code-analysis-sast-taie-mybatis-abstract-mapper-sink-analysis]]、[[code-analysis-sast-taie-mybatis-field-taint-propagation]]。
- **XML/构造器变体**：解析 `<bean>` 的 `property ref`/`constructor-arg ref` 后，在对应字段 `LoadField` 或构造参数变量上补点；`@Bean` 工厂方法返回对象也需类似建模。
- **边界**：`@Qualifier`、`@Primary`、profile 条件、多个同名实现会让交集仍含多个候选；注解覆盖不全（`@Repository`/`@Controller`）会漏掉实现类。

## 审计与防御

- **审计用法**：适合以字段注入为主的 Spring 项目；对每个 TaintFlow 核对字段声明类型与实现类是否唯一，必要时结合运行时 bean 定义（`@Bean`/XML）确认。
- **误报/漏报**：交集为空或实现类未带注解会漏报；字段被多次赋值、注入到父类、代理（AOP）场景可能偏离真实调用；建议把注解扫描扩展到 `@Repository`/`@Controller`/`@Bean` 并记录未解析字段。
- **对被测系统**：统一使用构造器注入与明确实现、减少动态代理与条件装配，可提高静态分析的精度与可审计性。
