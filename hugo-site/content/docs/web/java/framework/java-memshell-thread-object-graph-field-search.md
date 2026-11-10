---
id: java-memshell-thread-object-graph-field-search
title: 内存马定位：从当前线程对象图按字段名 BFS 搜索框架内部注册表（ChainManager/_router/RouterDefault）
type: scenario
domain: web
path: web/java/framework
technique: thread-object-graph-field-name-bfs-locate
tags:
- java
- memshell
- object-graph
- reflection
- bfs
- threadlocal
- solon
- tooling
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:50:22+08:00'
  notes: 已对照原文核对：以 Thread.currentThread() 为根、Keyword.setField_type 按字段名、SearchRequstByBFS、setMax_search_depth(20)、setReport_save_path 的参数与原文代码一致；引用的对象路径（threadLocals→table→[N]→value=SmHttpContext→attrMap→[ATTR_MAIN_HANDLER]→ActionDefault→bWrap→BeanWrap→context→AppContext→app→SolonApp→_chainManager/_router）与原文搜到的两份报告截图（img/06 的 [13] _chainManager、img/18 的 [6] _router）一致。未验证点：属定位方法论卡，未在原文之外的环境复现；BFS 的耗时/深度上界为原文经验值（20），未量化。
url: /docs/web/java/framework/java-memshell-thread-object-graph-field-search/
draft: false
kb_aliases:
- java-object-searcher 定位
- SearchRequstByBFS
- 线程对象图搜索
- 按字段名找框架内部对象
- 内存马对象定位
---

## 一句话结论

构造内存马时不必逐层猜字段路径：以 `Thread.currentThread()` 为根，用字段名关键字（如 `_chainManager`、`_router`、`router`、`table`）做广度优先遍历（java-object-searcher 的 `SearchRequstByBFS`），就能在运行中的请求线程对象图里直接命中框架的注册表实例（Solon 的 `ChainManager`/`RouterDefault`），取得类名与完整字段路径后再写稳定的逐层反射代码。

## 原理

- **为什么从线程出发有效**：Web 容器把当前请求的所有上下文挂在处理线程上——`Thread.threadLocals` → `ThreadLocalMap.table` → `Entry.value`（如 `SmHttpContext`）→ 请求上下文私有字段 → 框架对象（`ActionDefault`/`BeanWrap`/`AppContext`/`SolonApp`）→ 注册表（`ChainManager` 的 `filterNodes`、`RouterDefault` 的 `table`）。这条链全部是强引用，BFS 必然可达。
- **为什么按字段名而不是按类型**：类型名随版本变化但字段名（`_chainManager`、`_router`）相对稳定；且同一类型可能有多个实例（不同 app/不同 server），按字段名从当前线程命中能得到"当前请求真正使用的那个"。
- **BFS 而非 DFS 的理由**：对象图存在环（集合/父引用/ThreadLocal 回指），DFS 容易陷入循环或先命中无关分支；BFS 层层展开，配 `max_search_depth`（原文 20）与关键字集合可把搜索空间限制到可控范围。
- **产出是"路径"而非对象**：搜索报告给出 `TargetObject = {java.lang.Thread} → threadLocals → table → [13] → value → {...SmHttpContext} → attrMap → [ATTR_MAIN_HANDLER] → {ActionDefault} → bWrap → {BeanWrap} → context → {AppContext} → app → {SolonApp} → _chainManager = {ChainManager}`，其中 Map 用 key（`ATTR_MAIN_HANDLER`）、List 用下标（`[13]`）标注；把它翻译成 `getDeclaredField` + `get(map,key)` 就是最终 PoC 的反射链。
- **局限**：只在当前线程可达的对象上搜索；若注册表被放在静态单例且当前线程没有任何引用指过去，则搜不到（此时要退回类加载器/静态字段扫描）。搜索深度与关键字过宽会放大耗时，线上下发时需控制。

## 触发条件

- 已能在目标 JVM 内执行任意 Java 代码（反序列化、表达式、已有 webshell），且执行点位于处理 HTTP 请求的线程；
- classpath 中有 java-object-searcher（或自行实现等价的 BFS 反射遍历）；也可先用它做离线分析，再把结论硬编码进不依赖该库的 PoC；
- 知道目标框架内部注册表的字段名（可从 jar 反编译得到）。

## 利用步骤

1. 在 jar 里确认注册表字段名（如 `RouterDefault` 的 `table`、`ChainManager` 的 `filterNodes`，Solon 的 `SolonApp` 父类字段 `_chainManager`/`_router`）。
2. 在请求处理线程内运行搜索：
   ```java
   List<Keyword> keys = new ArrayList<>();
   keys.add(new Keyword.Builder().setField_type("_chainManager").build());
   SearchRequstByBFS searcher = new SearchRequstByBFS(Thread.currentThread(), keys);
   searcher.setIs_debug(true);
   searcher.setMax_search_depth(20);
   searcher.setReport_save_path("C:\\Users\\XXX\\Desktop\\demo");
   searcher.searchObject();
   ```
3. 读报告里的对象路径，确认命中对象类型（如 `ChainManager`/`RouterDefault`）与每一跳的字段名/Map key/List 下标。
4. 把路径翻译成逐层反射（`getDeclaredField` + `setAccessible(true)` + `Map.get(key)`），移除对搜索库的依赖。
5. 用得到的实例调用注册 API（`addFilter`、`add`、`addInterceptor` 等）完成内存马注册并验证。

## PoC

```java
// 搜索侧（离线/在线均可）
List<Keyword> keys = new ArrayList<>();
keys.add(new Keyword.Builder().setField_type("_router").build());
SearchRequstByBFS searcher = new SearchRequstByBFS(Thread.currentThread(), keys);
searcher.setMax_search_depth(20);
searcher.setIs_debug(true);
searcher.searchObject();
```

搜索结果示例（原文 Solon 3.0.5 命中 `_chainManager` 与 `_router` 两类）：

```text
TargetObject = {java.lang.Thread}
  --> threadLocals = {java.lang.ThreadLocal$ThreadLocalMap}
    --> table = {class [Ljava.lang.ThreadLocal$ThreadLocalMap$Entry;}
      --> [13] = {java.lang.ThreadLocal$ThreadLocalMap$Entry}
        --> value = {org.noear.solon.boot.smarthttp.http.SmHttpContext}
          --> attrMap = {java.util.Map<java.lang.String, java.lang.Object>}
            --> [ATTR_MAIN_HANDLER] = {org.noear.solon.core.mvc.ActionDefault}
              --> bWrap = {org.noear.solon.core.BeanWrap}
                --> context = {org.noear.solon.core.AppContext}
                  --> app = {org.noear.solon.core.SolonApp}
                    --> _chainManager = {org.noear.solon.core.ChainManager}
```

## 变体与关联

- 变体：关键字用类型名而非字段名（`setField_type` 传 `ChainManager`、`RouterDefault`），命中率更低但更精确。
- 变体：不引入搜索库，手写 BFS（`IdentityHashMap` 去重 + `getDeclaredFields` + 对 `Map`/`List`/数组特殊展开），体积更小、更适合打进内存马字节码。
- 变体：从 `Thread.getAllStackTraces()` 的多个线程同时开搜，覆盖非当前线程注册的对象（如后台线程持有的 Blade/Spring 上下文）。
- 关联：[[web-java-framework-solon-route-memshell-routerdefault-add]]（用本卡的搜索结果翻译成的反射链注册路由）。
- 关联：[[web-java-framework-solon-filter-memshell-chainmanager-reflect]]（同框架 Filter 版本，走逐层 `request`/`serverHandler`/`arg$1` 路径）。
- 关联：[[web-java-framework-blade-route-memshell]]（Blade 版在上下文不可用时同样退回线程对象图遍历找 `Blade` 实例）。
- 边界：搜索结果依赖具体版本与运行状态；线上大堆全量 BFS 可能引发显著 CPU/内存开销（属于分析阶段的成本，不是攻击危害本身），需限制深度与关键字。

## 检测与防御

- 检测：这类搜索会在短时间内大量调用 `Class.getDeclaredFields` 与反射读字段，配合 JVMTI/字节码增强可观测到异常反射风暴；内存马排查工具（java-memshell-scanner、Arthas `sc`/`jad`）本质上也是用同样的对象图遍历，可反向用于发现被注册的恶意 Filter/路由。
- 防御：升级框架使内部字段名/结构变化、启用模块封装限制深层反射；RASP 拦截对框架内部类的 `setAccessible` 批量调用；反序列化与表达式执行白名单（不引入可执行任意 Java 的入口）。
