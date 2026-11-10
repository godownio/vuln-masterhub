---
id: defense-detection-spring-mvc-mapping-registry-controller-memshell
title: Spring Controller 内存马检测：反射遍历 RequestMappingHandlerMapping.mappingRegistry 枚举路由与处理类
type: scenario
domain: defense
path: defense/detection
technique: spring-mvc-mapping-registry-controller-memshell-detection
tags:
- java
- spring
- spring-mvc
- memshell
- detection
- mapping-registry
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V279
  verified_at: '2026-11-08T00:04:20+08:00'
  notes: 已对照原文核对：RequestContextHolder→DispatcherServlet.CONTEXT→RequestMappingHandlerMapping→反射 mappingRegistry/registry→MappingRegistration.handlerMethod→HandlerMethod.description，及 getPatternsCondition/getPathPatternsCondition 双兼容，与正文代码和 img/01 的 /mappings 输出一致。卡内输出示例中的 /shell 行为按内存马场景补的示意（原文输出无该行），已标注为『源码中不存在的运行时注册路由』，非原文事实。该卡是单一检测手法；dedup 首位自身，其余为攻击侧 controller/interceptor 内存马等不同用途，非重复。dup-scan 对本卡仅 related，无删除项。
url: /docs/defense/detection/defense-detection-spring-mvc-mapping-registry-controller-memshell/
draft: false
kb_aliases:
- Controller 内存马检测
- RequestMappingHandlerMapping 排查
- mappingRegistry 枚举
- Spring MVC 路由清单
- 动态 Controller 排查
- HandlerMethod description
---

## 一句话结论

Controller 型内存马不实现 Filter/Servlet 接口、也不继承 HttpServlet，按接口/父类黑名单 dump 类抓不到；但恶意 controller 必须注册进 Spring MVC 的 `RequestMappingHandlerMapping` 才能接收请求，因此可反射读取 `AbstractHandlerMethodMapping.mappingRegistry` 里的 `registry` 映射，枚举每个 `RequestMappingInfo` 的路径与 `MappingRegistration.handlerMethod` 的声明类/方法，得到完整的“URL → 类#方法”清单，再用类名、路径与源码对照发现运行时注册的恶意 controller。

## 原理

- Spring MVC 在启动时扫描 `@Controller`/`@RequestMapping`，把每个 handler 方法登记到 `RequestMappingHandlerMapping`（继承 `AbstractHandlerMethodMapping`）。内部核心是 `mappingRegistry` 字段，其 `registry` 是一个 `Map<RequestMappingInfo, MappingRegistration>`：
  - key `RequestMappingInfo` 保存路径、HTTP 方法等匹配条件；
  - value `MappingRegistration` 持有 `handlerMethod`（`HandlerMethod`），可从中得到声明类、方法名与参数。
- `RequestMappingHandlerMapping` 同时暴露运行期 `registerMapping(RequestMappingInfo, Object handler, Method method)`；Controller 内存马正是调用它（或等价反射写入 registry）把恶意类/方法注册成新路由。只要内存马要工作，就必然在这个映射表里留下条目。
- 该手法解决了“无特征”问题：Controller 内存马可以是一个不实现任何接口、不继承任何 Servlet 类的普通类，基于接口/父类/类名的 dump 黑名单会漏掉它；而路由清单会直接暴露它。
- 获取映射表的路径：当前请求线程通过 `RequestContextHolder.currentRequestAttributes()` 取 `ServletRequestAttributes`，用 `DispatcherServlet.CONTEXT` 属性拿到 `WebApplicationContext`，再 `getBean(RequestMappingHandlerMapping.class)`；反射 `mappingRegistry` → `registry` 即可遍历。
- 路径条件的读取需兼容 Spring 版本：旧版用 `RequestMappingInfo.getPatternsCondition().getPatterns()`，Spring 5.3+ 常用 `getPathPatternsCondition().getPatterns()`（`PathPattern`），两者都读才能覆盖不同注册方式。
- `HandlerMethod` 的 `description` 字段给出 `类名#方法(参数类型)`，可直接和已知 controller 源码/路由文档比对。

## 触发条件

- 目标为 Spring MVC 应用（非纯 WebFlux），classpath 中存在 `spring-webmvc`，且当前线程能拿到 `WebApplicationContext`。
- 排查者能在应用中临时加入一个诊断 controller/JSP，或能通过 Actuator、Arthas 等等价手段执行 Java 代码读取该映射表。
- 反射访问 Spring 私有字段未被模块系统/安全管理器阻断（Spring 通常在应用 classpath 的 unnamed module 中，常规环境可反射）。
- 需要结合应用已知路由基线或源码，才能判断哪些条目是异常注册的。

## 利用步骤

1. 在应用中加入临时诊断 controller（例如 `/mappings`），通过 `RequestContextHolder` 获取 `WebApplicationContext` 与 `RequestMappingHandlerMapping` Bean。
2. 反射读取 `AbstractHandlerMethodMapping.mappingRegistry`，再读取其 `registry` 字段，得到 `Map<RequestMappingInfo, MappingRegistration>`。
3. 遍历条目：读取 `RequestMappingInfo` 的 `patternsCondition`/`pathPatternsCondition` 得到路径；反射 `MappingRegistration.handlerMethod`，取 `HandlerMethod` 的 `description`（类名#方法）。
4. 输出完整“路径 → 类#方法”表，与源码中的 `@RequestMapping`、网关/网关白名单、接口文档比对；重点标记：
   - 源码中不存在的路径或类；
   - 类名陌生、伪装成框架类、带随机后缀；
   - 方法签名只接收 `HttpServletRequest/HttpServletResponse` 且方法体执行命令；
   - 同一路径对应多个 handler 或近期新增的映射。
5. 对可疑类用 sa-jdi ClassDump/Arthas `jad`/ASM 做字节码取证（见关联卡），确认是否存在请求参数到命令执行的数据流。
6. 取证完成后删除临时诊断 controller；对确认的内存马，重启进程或调用 `unregisterMapping` 移除映射，并修复注入入口。

## PoC

```java
@RequestMapping("/mappings")
@ResponseBody
public String mappings() {
    try {
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder
                .currentRequestAttributes()
                .getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        RequestMappingHandlerMapping rmhMapping =
                context.getBean(RequestMappingHandlerMapping.class);

        Field mappingRegistryField =
                AbstractHandlerMethodMapping.class.getDeclaredField("mappingRegistry");
        mappingRegistryField.setAccessible(true);
        Object mappingRegistry = mappingRegistryField.get(rmhMapping);

        Field registryField = mappingRegistry.getClass().getDeclaredField("registry");
        registryField.setAccessible(true);
        Map<Object, Object> registry =
                (Map<Object, Object>) registryField.get(mappingRegistry);

        // 反射取 MappingRegistration.handlerMethod
        Class<?> registrationClass = null;
        for (Class<?> inner : AbstractHandlerMethodMapping.class.getDeclaredClasses()) {
            if (inner.getName().endsWith("$MappingRegistration")) {
                registrationClass = inner;
            }
        }
        Field handlerMethodField = registrationClass.getDeclaredField("handlerMethod");
        handlerMethodField.setAccessible(true);

        StringBuilder sb = new StringBuilder("<pre>| path | info |\n");
        for (Map.Entry<Object, Object> entry : registry.entrySet()) {
            RequestMappingInfo key = (RequestMappingInfo) entry.getKey();
            if (key.getPatternsCondition() != null) {
                sb.append(key.getPatternsCondition().getPatterns()).append("\t-->");
            }
            if (key.getPathPatternsCondition() != null) {
                sb.append(key.getPathPatternsCondition().getPatterns()).append("\t-->");
            }
            HandlerMethod handlerMethod =
                    (HandlerMethod) handlerMethodField.get(entry.getValue());
            Field descField = handlerMethod.getClass().getDeclaredField("description");
            descField.setAccessible(true);
            sb.append(descField.get(handlerMethod)).append("\n");
        }
        sb.append("</pre>");
        return sb.toString();
    } catch (Exception e) {
        e.printStackTrace();
    }
    return "";
}
```

```text
访问 /mappings 输出示例（每行：路径 --> 类#方法）：
/save_user      --> com.example.web.BasicController#saveUser(User)
/user           --> com.example.web.BasicController#user()
/mappings       --> com.example.web.controller.Map#mappings()
/shell          --> com.example.evil.Controller#exec(HttpServletRequest,HttpServletResponse)
# 最后一行是源码中不存在的运行时注册路由，应重点取证
```

## 变体与关联

- 数据源变体：Spring Boot Actuator 的 `/actuator/mappings`（若暴露且未授权）能直接看到类似映射，排查时可作为只读入口；不能执行代码时可用 Arthas/`vmtool` 反射读取 `mappingRegistry` 或 heap dump 搜索 `RequestMappingInfo`。
- 框架变体：Spring WebFlux 使用响应式 handler mapping，字段与 API 不同，需按对应类实现；Spring MVC 旧版（`getPatternsCondition`）与 5.3+（`getPathPatternsCondition`）都要兼容。
- 覆盖范围：Filter/Listener/Valve/Interceptor/内存马不一定出现在 MVC 映射表，需与 `defense-detection-tomcat-memshell-scanner-arthas`、Agent 检测等组合。
- 关联卡片：[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（Controller 内存马攻击链）、[[defense-detection-sajdi-classdump-memshell-bytecode]]（对可疑类做字节码/ASM 取证）、[[defense-detection-tomcat-memshell-scanner-arthas]]、[[defense-forensics-java-memshell-heapdump-bytecode]]。
- 边界：无法在应用内执行代码且 Actuator 不可用时，只能走离线 heap dump/Arthas；映射表只能发现“已注册”的 controller 内存马，若攻击者改用 Filter/Agent 等其他类型则不适用；诊断 controller 本身也是代码注入，操作需授权并事后清理。

## 检测与防御

- 检测：定期导出并基线化路由清单，监控 `RequestMappingHandlerMapping.registerMapping`/`unregisterMapping` 的运行期调用；出现源码/网关白名单之外的路径、陌生类名或伪装成框架类的 handler；同一路径重复注册。
- 防御：限制 Actuator `mappings` 端点暴露并加认证；对动态注册 API 使用 RASP/Java Agent 监控；应用以最小权限运行，禁止 JSP/临时 controller 写入；发现异常映射后重启并修复注入入口。
- 加固：启动时校验 controller 清单完整性；容器/框架升级到受支持版本；对 classpath 与 web 目录做完整性监控，防止攻击者先写入 class 再反射注册。
