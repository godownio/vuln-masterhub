---
id: code-analysis-sast-taie-mybatis-dollar-sink-inject-taintconfig
title: Tai-e 注入自定义 MyBatis ${} sink：在 TaintConfig.deserializeSinks 的 unmodifiableList 包装前 addAll，SinkHandler 内直接 add 会抛异常
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-mybatis-dollar-sink-taintconfig-inject
aliases:
- Tai-e MyBatis sink 注入
- TaintConfig deserializeSinks
- Collections.unmodifiableList 注入点
- AddMybatisSinkHandler
- SinkHandler UnsupportedOperationException
- MyBatis ${} 参数映射
tags:
- code-analysis
- sast
- taie
- java
- mybatis
- sql-injection
- taint-analysis
- sink
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T02:23:34+08:00'
  notes: 已对照原文与 26 张截图核对：@Mapper/@Select 与 ${} SQL(图13/21)、Pattern $\{([^}]+)\} 提取+@Param 匹配参数(图23 handler)、SinkHandler final sinks=context.config().sinks()(图15)、SinkHandler.addAll 抛 UnsupportedOperationException 的完整堆栈(图16)、TaintConfig.deserializeSinks 在 return Collections.unmodifiableList 前 addAll(图20/22/23)、最终 mybatisVuln01 的 TaintFlow→findByUserNameVuln01($username)/0(图26)均有截图佐证；卡片对原文 paramValue 未判空可能 NPE 处补了 null 检查；原文未声明组件受影响版本，affected_versions 置空；未被验证点：未在本机复跑 Tai-e
---

# 一句话结论

给 Tai-e 的 taint 分析增加 MyBatis `${}` sink 时，不能在 `SinkHandler` 里直接往 `sinks` 列表 add——该字段 final 且来自 `TaintConfig`，配置反序列化后被 `Collections.unmodifiableList(sinks)` 包装，`addAll` 会抛 UnsupportedOperationException；正确做法是在 `TaintConfig` 内部 `Deserializer.deserializeSinks(JsonNode)` 返回前先 `sinks.addAll(AddMybatisSinkHandler.AddMybatisSink())` 再包装。MyBatis sink 的识别方法：遍历 `World.getClassHierarchy().applicationClasses()` 中带 `@Mapper` 的类、带 `@Select` 的方法，对注解 value 用 `\$\{([^}]+)\}` 提取 `${}` 参数名，再按 `@Param` 值匹配方法参数，生成 `Sink(method, IndexRef(VAR, i))`。

# 原理

- **MyBatis 的两种参数写法**：`#{name}` 走 PreparedStatement 占位符（预编译，防注入）；`${name}` 是文本拼接（可注入）。Tai-e 默认 sink 规则是"方法签名 + 参数 index"，无法表达"方法参数被 `${}` 拼进 SQL 字符串"这种语义，因此要先把 `${}` 中出现的参数名映射成方法参数 sink。
- **Taint 配置加载流程**：`TaintAnalysis.setSolver` 调 `TaintConfig.loadConfig("taint-config", solver.getHierarchy(), solver.getTypeSystem())`；`loadConfig` 构造 Jackson `ObjectMapper(YAMLFactory)`，注册自定义 `Deserializer(TaintConfig.class)`，`loadSingle` 用 `mapper.readValue(file, TaintConfig.class)` 读 YAML。
- **sink 列表的不可变化**：`Deserializer.deserializeSinks(JsonNode)` 构建 `List<Sink>` 后 `return Collections.unmodifiableList(sinks)`；`SinkHandler` 构造时 `private final List<Sink> sinks; sinks = context.config().sinks();`。因此在 SinkHandler 里 `sinks.addAll(...)` 必然抛 `UnsupportedOperationException`（案例堆栈：`Collections$UnmodifiableCollection.addAll → SinkHandler.<init> → TaintAnalysis.onFinish`）。
- **唯一干净的注入点**：修改 `TaintConfig` 的 `deserializeSinks`，在 `return Collections.unmodifiableList(sinks)` 之前把自定义 MyBatis sink 加入同一个 `sinks` 列表；不用改 final 字段，也不用改 SinkHandler。
- **MyBatis sink 提取**：`World.get().getClassHierarchy().applicationClasses()` → 过滤带 `org.apache.ibatis.annotations.Mapper` 的类；`jClass.getDeclaredMethods()` → 过滤带 `@Select` 的方法（order/in 等暂不处理）；`getValueFromAnnotation` 取注解 `value`；`contains("$")` 后 `Pattern.compile("\\$\\{([^}]+)\\}")` 提取名称；遍历 `jMethod.getParamAnnotations(i)` 的 `@Param` value 匹配，命中则 `new Sink(jMethod, new IndexRef(IndexRef.Kind.VAR, i, null))` 加入列表。
- **验证结果**：案例 java-sec-code 中 `mybatisVuln01` 产生 TaintFlow：`<SQLI: List mybatisVuln01(String)>/0 → invokeinterface findByUserNameVuln01($username)/0`，说明自定义 sink 被 taint 分析正确使用。

# 触发条件

- 使用 Tai-e 0.5.x 源码构建，能修改 `TaintConfig`（或按同样思路扩展配置加载器）。
- 被分析项目使用 MyBatis 注解方式（`@Mapper` + `@Select/@Update/...`）且 SQL 中出现 `${}`。
- 希望 Tai-e 原生 taint 分析能覆盖 MyBatis 注入，而不是只依赖手工 sink 配置。
- 已有可运行的 Tai-e taint 分析配置（sources/transfers 基本可用）。

# 利用步骤

1. 编写 `AddMybatisSinkHandler.AddMybatisSink()`：遍历应用类 → 过滤 `@Mapper` → 过滤 `@Select` 方法 → value 含 `$` → 正则提取 `${name}` → 按 `@Param` 匹配参数下标 → 生成 `Sink` 列表。
2. 在 `TaintConfig` 内部 `Deserializer.deserializeSinks(JsonNode node)` 中，`return Collections.unmodifiableList(sinks);` 之前加入：
   ```java
   List<Sink> mybatisSinks = AddMybatisSinkHandler.AddMybatisSink();
   sinks.addAll(mybatisSinks);
   ```
3. 重新 `gradle fatJar` 构建 Tai-e，运行 options.yml（`appClassPath` 指向目标 classes，启用 pta/taint-config）。
4. 查看 taint 结果，确认 MyBatis `${}` 方法参数被报告；案例成功产生 `mybatisVuln01` 的 TaintFlow。
5. 对 XML 形式的 Mapper 补充按 namespace/id 映射到接口方法的步骤；对 JavaBean/Map/List 参数扩展字段级匹配。

# PoC

```java
public static List<Sink> AddMybatisSink() {
    List<Sink> sinkList = new ArrayList<>();
    List<JClass> list = World.get().getClassHierarchy().applicationClasses().toList();
    for (JClass jClass : list) {
        if (jClass.getAnnotations().stream().filter(a ->
                a.getType().matches("org.apache.ibatis.annotations.Mapper")).toList().isEmpty()) {
            continue;
        }
        jClass.getDeclaredMethods().forEach(jMethod -> {
            if (jMethod.getAnnotations().stream().filter(a ->
                    a.getType().matches("org.apache.ibatis.annotations.Select")).toList().isEmpty()) {
                return;
            }
            String valueFromAnnotation = getValueFromAnnotation(jMethod.getAnnotations());
            if (valueFromAnnotation != null && valueFromAnnotation.contains("$")) {
                Matcher matcher = Pattern.compile("\\$\\{([^}]+)\\}").matcher(valueFromAnnotation);
                while (matcher.find()) {
                    String sink = matcher.group(1);
                    for (int i = 0; i < jMethod.getParamCount(); i++) {
                        String paramValue = getValueFromAnnotation(jMethod.getParamAnnotations(i));
                        if (paramValue != null && paramValue.contains(sink)) {
                            sinkList.add(new Sink(jMethod, new IndexRef(IndexRef.Kind.VAR, i, null)));
                        }
                    }
                }
            }
        });
    }
    return sinkList;
}
```

```java
// TaintConfig.Deserializer#deserializeSinks 内的注入点
List<Sink> sinks = new ArrayList<>();
// ... 解析 YAML 中 sinks ...
sinks.addAll(AddMybatisSinkHandler.AddMybatisSink());   // 必须在下面这行之前
return Collections.unmodifiableList(sinks);
```

# 变体与关联

- **抽象 Mapper 调用边**：MyBatis Mapper 是接口，PTA 默认解析不到实现、`getIR()` 会抛异常，需要 MockObj + 补调用边 + 空 IR，见 [[code-analysis-sast-taie-mybatis-abstract-mapper-sink-analysis]]。
- **字段级污点匹配**：JavaBean/Map/List 参数的字段级 sink 与 SpringMVC 入参造污点见 [[code-analysis-sast-taie-mybatis-field-taint-propagation]]；通用 `${}` sink 提取与参数映射见 [[code-analysis-sast-mybatis-mapper-sql-concat-sink-extraction]]。
- **同一注入模式**：其它有特殊语义的 sink（order by 列名、in 集合、动态表名）也可在 `deserializeSinks` 中注入，避免改 SinkHandler。
- **关联工具链**：[[code-analysis-sast-taie-java-taint-audit-toolchain]]、[[code-analysis-sast-taie-custom-program-analysis-api-extraction]]。

# 检测与防御

- **审计配置侧**：把自定义 sink 注入封装为独立 handler，升级 Tai-e 后便于重放；确认注入发生在 `unmodifiableList` 之前。
- **开发侧**：禁止 `${}` 文本拼接，统一使用 `#{}`；order by/表名等必须走白名单映射。
- **误报控制**：`${}` 出现在静态常量 SQL（无外部输入）时会误报，需结合 source 可达性与参数来源确认。
