---
id: code-analysis-sast-taie-mybatis-field-taint-propagation
title: Tai-e MyBatis 字段级污点匹配与传播补全：JavaBean 字段 sink + SpringMVC 入参字段造污点 + Map/List/setter transfers
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: taie-mybatis-field-taint-propagation
tags:
- sast
- taie
- taint-analysis
- mybatis
- java
- javabean
- transfer
- springmvc
- pointer-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:24:32+08:00'
  notes: 已对照原文 0x03/0x04 核对：collectTaintFlows 按 MybatisSink(method,index,field) 用字段 points-to 判污点、SourceHandler.onNewPointsToSet 对 WebEntryParamObj 字段以 setter ParamSourcePoint 造污点、HashMap.put from=1→base、ArrayList.add from=0→base、TransferHandler.onNewCallEdge 对 set 开头且首参非简单类型的 JavaBean 方法做 VAR0→VAR-1 传播，均与原文一致。未验证点：补丁为示意未编译运行；原文未给 Tai-e 受影响版本；无 sources/URL。dedup 与 taie-java-taint-audit-toolchain、codeql-custom-taint-steps 均 related 非重复。
url: /docs/code-analysis/static/sast/code-analysis-sast-taie-mybatis-field-taint-propagation/
draft: false
kb_aliases:
- MyBatis 字段级污点
- collectTaintFlows 自定义
- WebEntryParamObj
- JavaBean setter 污点传播
- HashMap put transfer
- ArrayList add transfer
- SpringMVC 入参字段污点
---

## 一句话结论

MyBatis sink 的参数经常是 JavaBean/Map/List，而 Tai-e 默认的 sink 匹配只判断“整个实体对象是否含污点”，不会细化到 `${bean.field}` 指向的具体字段；同时 SpringMVC 入口 JavaBean 的字段默认不会被标成污点，Map/List 也只是把污点存在内部数组里而不传播给容器对象本身。要在 Tai-e 中报出 MyBatis 注入，需要三处补丁：自定义 `SinkHandler.collectTaintFlows` 按字段 points-to 判断污点、在 `SourceHandler.onNewPointsToSet` 为 Web 入口 JavaBean 字段生成污点、以及用 transfer 规则（HashMap.put / ArrayList.add / JavaBean setter→base）把字段污点传播到容器和实体对象。

## 原理

- **为什么默认匹配会漏**：`MybatisSink` 记录的是 `(method, argIndex, field)`；Tai-e 默认 sink 匹配拿到的是调用点的参数变量 points-to 集，只做 `manager.isTaint(obj)`。对于 `sink(bean)` 且 SQL 为 `${bean.name}` 的情况，污点挂在 `bean` 实例的 `name` 字段对象上，`bean` 对象本身不一定被标污点，于是匹配不到。
- **字段级匹配**：在 `collectTaintFlows` 中遍历 `result.getCallGraph().edgesInTo(sink.method())` 的调用点，取第 `index` 个实参变量；对其 points-to 集中的每个对象，若 sink.field 非空，则用 `result.getPointsToSet(obj, jField)` 取该对象字段的 points-to 集，逐个判断 `isTaint`，命中则用该字段对象生成 `TaintFlow`；field 为空时退回判断对象本身。
- **Web 入口 JavaBean 字段没有污点**：Tai-e 的 source 通常是“入口方法第 i 个参数”整体（`kind: param`），但 SpringMVC 的 `@RequestBody`/表单绑定会把请求参数映射到 JavaBean 的 setter/字段；分析器若只为参数对象建一个 mock 对象，字段层面是干净的。可在 `SourceHandler.onNewPointsToSet` 里识别描述符为 `WebEntryParamObj` 的 mock 对象，遍历其类声明的字段，为每个可实例化非简单类型字段生成 `ParamSourcePoint(fieldSetter, 0)` 污点，并 `addPointsTo` 到该对象的实例字段上。
- **Map/List 的容器不携带污点**：`HashMap.put(key, value)` 把污点对象存进 `table` 数组，`ArrayList.add(e)` 存进 `elementData`，污点属于被存入的对象/字段，容器对象本身 points-to 集不含污点。需要在 taint 配置里加 transfer：`HashMap.put` 的 from=1（value 参数）to=base（HashMap 对象），`ArrayList.add` 的 from=0 to=base，让容器被标污点，从而匹配“整个集合参数是 sink”的场景。
- **实体先持字段污点、后加入 List 的链路**：常见写法是 `bean.setName(tainted); list.add(bean);`。`bean` 的字段被标污点，但 `bean` 对象本身不含污点，加入 List 后 List 也不会被标污点。可在 `TransferHandler.onNewCallEdge` 中识别 setter 方法（名字以 `set` 开头、参数非简单类型、声明类是 JavaBean），把参数中的污点传播给调用该 setter 的 base 对象（TransferPoint `VAR 0` → `VAR -1`）；这样 `bean` 被标污点，再经 `ArrayList.add` transfer 传播到 List，最终命中集合级 sink。
- **整体链路**：source（入口参数/字段）→ 业务方法 → setter 写入 JavaBean（字段+对象污点）→ List/Map 容器（transfer）→ MyBatis Mapper 抽象方法 → 自定义 sink 匹配（对象或字段级）→ `TaintFlow`。

## 触发条件

- 使用 Tai-e 的 taint 分析与自定义 MyBatis sink（`MybatisSink(method, index, field)`）；sink 参数可能是 JavaBean 字段或 Map/List。
- 应用是 SpringMVC/Spring Boot，入口方法参数是 DTO/JavaBean（`@RequestBody`、表单对象）或集合。
- 需要扩展/修改 `SinkHandler.collectTaintFlows`、`SourceHandler.onNewPointsToSet`、`TransferHandler.onNewCallEdge` 等插件内部 API。
- 业务代码采用 setter 赋值再放入集合的常见写法；若为构造器/直接字段赋值，需要额外的传播规则。

## 利用步骤

1. **自定义字段级 sink 匹配**：在 `collectTaintFlows` 处理 `mybatisSinks`：对每个 sink 取入边调用点，`InvokeUtils.getVar(sinkCall, index)` 取实参；若 `field != null` 则对 points-to 集的每个对象查该字段的 points-to 并判断污点；命中后 `new TaintFlow(sourcePoint, sinkPoint)`。
2. **入口 JavaBean 字段造污点**：为 Web 入口参数建 `WebEntryParamObj` mock 对象；在 `SourceHandler.onNewPointsToSet` 检测到该对象后，遍历其类型声明字段，对每个可实例化、非简单类型字段取 setter（`getFieldSetter`），用 `ParamSourcePoint(setter, 0)` 生成污点对象并 `addPointsTo` 到 `InstanceField(baseObj, field)`。
3. **Map 容器传播**：在 taint 配置加 `java.util.HashMap.put(Object,Object)` 的 transfer（from=1, to=base）。
4. **List 容器传播**：加 `java.util.ArrayList.add(Object)` 的 transfer（from=0, to=base）。
5. **setter→对象传播**：在 `TransferHandler.onNewCallEdge` 中对 `set*` 且首参非简单类型、声明类为 JavaBean 的方法构造 `ConcreteTransfer(VAR 0 → VAR -1)`，把参数污点传给调用 setter 的接收者对象。
6. **回归验证**：构造 `@RequestBody Dto d` → `d.setName(requestValue)` → `list.add(d)` → Mapper `${d.name}` 的样例，确认产生 `TaintFlow`；再构造 Map put 的样例确认容器级 sink 命中；对照 `#{}` 版本确认无误报。

## PoC

关键补丁示意（按原文思路重写）：

```java
// 1) 字段级 sink 匹配
for (MybatisSink sink : mybatisSinks) {
    result.getCallGraph().edgesInTo(sink.method()).forEach(e -> {
        Invoke call = e.getCallSite().getCallSite();
        Var arg = InvokeUtils.getVar(call, sink.index());
        for (Obj obj : result.getPointsToSet(arg)) {
            if (sink.field() != null) {
                JField f = obj.getType().getJClass().getDeclaredField(sink.field());
                if (f != null)
                    for (Obj fo : result.getPointsToSet(obj, f))
                        if (manager.isTaint(fo))
                            flows.add(new TaintFlow(manager.getSourcePoint(fo), new SinkPoint(call, sink.index())));
            } else if (manager.isTaint(obj)) {
                flows.add(new TaintFlow(manager.getSourcePoint(obj), new SinkPoint(call, sink.index())));
            }
        }
    });
}

// 2) SpringMVC 入口 JavaBean 字段生成污点
@Override
public void onNewPointsToSet(CSVar var, PointsToSet pts) {
    for (Obj base : pts) {
        if (base.getObject() instanceof MockObj mo
                && "WebEntryParamObj".equals(mo.getDescriptor().string())
                && base.getType() instanceof ClassType ct) {
            for (JField f : ct.getJClass().getDeclaredFields()) {
                if (isInstantiable(f.getType()) && !isPrimitive(f.getType())) {
                    JMethod setter = getFieldSetter(ct, f);
                    if (setter != null) {
                        Obj taint = manager.makeTaint(new ParamSourcePoint(setter, 0), f.getType());
                        solver.addPointsTo(solver.getCSManager().getInstanceField(base, f),
                                           solver.getContextSelector().getEmptyContext(), taint);
                    }
                }
            }
        }
    }
}
```

```yaml
# 3/4) Map/List 容器传递
transfers:
  - { method: '<java.util.HashMap: java.lang.Object put(java.lang.Object,java.lang.Object)>', from: 1, to: base }
  - { method: '<java.util.ArrayList: boolean add(java.lang.Object)>', from: 0, to: base }
```

```java
// 5) setter 参数 → 接收者对象
@Override
public void onNewCallEdge(Edge<CSCallSite, CSMethod> edge) {
    JMethod m = edge.getCallee().getMethod();
    if (m.getName().startsWith("set") && !isPrimitive(m.getParamType(0))
            && isJavaBean(m.getDeclaringClass().getType())) {
        TaintTransfer tf = new ConcreteTransfer(
            new TransferPoint(TransferPoint.Kind.VAR, 0, null),
            new TransferPoint(TransferPoint.Kind.VAR, -1, null),
            m.getDeclaringClass().getType());
        processTransfer(edge.getCallSite().getContext(), edge.getCallSite().getCallSite(), tf);
    }
}
```

## 变体与关联

- **构造器注入/字段直接赋值**：setter 规则覆盖不到；可为构造器参数→`this` 或字段赋值语句补 transfer，或在 source 阶段直接给 JavaBean 字段造污点。
- **Map 的具体实现**：`HashMap.put` transfer 只覆盖 HashMap；若业务用 `Map.of`、`ConcurrentHashMap`、`LinkedHashMap`，需按实际实现方法签名补规则（可继承/接口方法匹配）。
- **集合嵌套/批量操作**：`List<Bean>` 已被容器级 sink 覆盖；若 SQL 用 `${list[0].name}` 需要更细的索引建模，指针分析对数组下标不敏感，通常只能整体标记。
- **MyBatis-Plus Wrapper**：`QueryWrapper.eq("col", value)` 等 API 的拼接点不在 `${}` 中，需要为 wrapper 方法建立额外 sink/transfer 模型（本卡未覆盖）。
- **关联**：本卡与“MyBatis sink 提取”（产出 `(method,index,field)`）、“Tai-e 抽象 Mapper 分析”（让调用图包含 Mapper 方法）共同构成完整方案；单独启用任何一块都不足以报出字段级注入。

## 检测与防御

- **误报/漏报评估**：字段级匹配能显著降低“整个对象有污点就报”的误报；但 Map/List 仍按容器级 sink，存在整表误报，需要在报告中标注匹配粒度（field / object / container）。
- **回归样例**：至少覆盖四种链路——单参数 JavaBean 字段、`@Param` 多参数、Map put、setter+List add；每种都应有正例（`${}`）与负例（`#{}`）。
- **性能**：字段级 points-to 查询和 setter 传播会增加分析开销；可在 `edgesInTo` 前按方法签名过滤，只处理 MyBatis sink 相关调用。
- **防御视角**：应用侧继续用 `#{}`；对必须动态拼接的场景使用白名单并记录；SAST 规则应把 DTO 字段、集合容器纳入污点传播，否则 MyBatis 业务代码会出现系统性漏报。
- **工具升级**：`SinkHandler`/`SourceHandler`/`TransferHandler` 属于 Tai-e 内部实现，升级后需重新适配；将补丁封装为独立插件模块并保留最小 diff，便于迁移。
