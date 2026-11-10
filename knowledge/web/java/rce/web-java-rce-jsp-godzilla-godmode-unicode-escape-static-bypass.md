---
id: web-java-rce-jsp-godzilla-godmode-unicode-escape-static-bypass
title: 哥斯拉上帝模式生成 JSP 马：globalCode/code 全部 stringToUnicode 转义后再嵌入模板，静态关键字扫描难匹配
type: scenario
domain: web
path: web/java/rce
technique: godzilla-godmode-unicode-escaped-jsp-generation
aliases:
- 哥斯拉上帝模式
- Godzilla GodMode
- stringToUnicode 生成马
- JSP 全 Unicode 转义免杀
- 哥斯拉模板替换 {pass} {secretKey}
tags:
- java
- jsp
- godzilla
- webshell
- evasion
- unicode-escape
- static-detection
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:51:20+08:00'
  notes: 已对照原文核对：GenerateShellLoder 读取 (raw|base64)GlobalCode.bin / Code.bin、replace({pass}/{secretKey})、按 suffix 读 shell.<suffix>、jspx 分支把 < > 转成 &lt;/&gt;、isGodMode() 为真时对 globalCode2/code 调用 functions.stringToUnicode、最后去掉 \n\r 输出，均与正文一致；卡内已正确限定为「只绕静态、不改动态」并标出体积膨胀代价；本次核对未读取图片，上帝模式生成马的实际文件与连接截图未核实；未编译/未运行哥斯拉。
---

## 一句话结论

哥斯拉的 `GenerateShellLoder()` 在生成 JSP 马时会把 `{pass}`/`{secretKey}` 替换进 `globalCode` 与 `code`，若开启「上帝模式」（`ApplicationContext.isGodMode()`），这两段代码会先经过 `functions.stringToUnicode()` 变成 `\uXXXX` 转义串再嵌入模板；这样落地文件里几乎看不到 `Runtime`、`exec`、`defineClass`、`base64Decode` 等明文关键字，静态特征扫描与「搜关键字」式的应急排查都会明显失效。

## 原理

- **生成流程**：`GenerateShellLoder(pass, secretKey, isBin)` 从 jar 资源里读 `shell/java/template/(raw|base64)GlobalCode.bin` 与 `Code.bin`，做 `replace("{pass}", pass).replace("{secretKey}", secretKey)`，再按用户选择的 suffix（jsp/jspx）读 `shell/java/template/shell.<suffix>` 模板，最后 `template.replace("{globalCode}", ...).replace("{code}", ...)` 并去掉 `\n\r` 输出。
- **jspx 分支**：suffix 为 jspx 时还会把 `<`/`>` 转成 `&lt;`/`&gt;`，否则 XML 解析失败——说明该模板机制对后缀敏感，生成器要按目标容器选形态。
- **上帝模式**：`isGodMode()` 为真时走 `functions.stringToUnicode(globalCode2)` 与 `stringToUnicode(code)`，把整段 Java 代码逐字符转成 `\u006a\u0061...`。JSP 在编译前由容器做 Unicode 转义处理，因此执行语义不变，但**文件字节层面不再出现任何敏感英文单词**。
- **为什么能绕**：绝大多数 webshell 静态检测（YARA 规则、关键字黑名单、`grep -r "defineClass"`）匹配的是明文 token；全量 Unicode 转义后，规则要么命中不到，要么需要先实现完整的 JSP/Java 转义还原再匹配，成本大幅提高。
- **代价**：文件体积膨胀（每字符变成 6 字节）、可读性丧失；且转义仍是合法 JSP，动态行为（session 写 payload、Base64+AES 通信）完全不变，因此只能绕过静态检查，绕不过流量与内存马检测。

## 触发条件

- 攻击者能获取并运行哥斯拉客户端（或直接调用其 `Generate` 代码），并能把生成的 JSP 落地到目标 Web 目录。
- 目标容器（Tomcat/Jetty 等）按 JSP 解析 Unicode 转义后的源码（标准 JSP 编译器均支持）。
- 防守方静态检测主要依赖明文关键字/正则，未做转义归一化。

## 利用步骤

1. 反编译哥斯拉，定位 `shells/cryptions/JavaAes/Generate.java`（即 `GenerateShellLoder`）。
2. 在客户端设置里开启上帝模式（`ApplicationContext.isGodMode()` 返回真），或在本地代码里直接调用 `functions.stringToUnicode(...)`。
3. 输入连接密码 `pass` 与 16 字节 `key`，选择后缀 `jsp`（XML 场景才用 `jspx`，注意 `&lt;`/`&gt;` 转义），生成马。
4. 检查生成文件：确认 `{globalCode}`/`{code}` 已被替换成 `\uXXXX` 串，文件里搜不到 `Runtime`/`exec`/`defineClass`/`base64Decode` 等明文。
5. 把马写入目标 Web 目录，用同一客户端连接（密码/key 与生成时一致），验证命令执行。
6. 若被拦截，再叠加响应伪装（伪 404 页 / 自定义 findStr 标记）降低流量侧与内容侧的可见性。

## PoC

```java
// 生成侧核心逻辑（等价于 GenerateShellLoder 的关键几步）
String globalCode = readResource("shell/java/template/base64GlobalCode.bin");
String code       = readResource("shell/java/template/base64Code.bin");
globalCode = globalCode.replace("{pass}", pass).replace("{secretKey}", key);
code       = code.replace("{pass}", pass).replace("{secretKey}", key);

String template = readResource("shell/java/template/shell.jsp");
if (ApplicationContext.isGodMode()) {           // 上帝模式
    template = template.replace("{globalCode}", functions.stringToUnicode(globalCode))
                       .replace("{code}",       functions.stringToUnicode(code));
} else {
    template = template.replace("{globalCode}", globalCode)
                       .replace("{code}",       code);
}
byte[] shell = template.replace("\n", "").replace("\r", "").getBytes();
```

```text
生成结果片段对比：
普通模式： if (session.getAttribute("payload") == null) { ... defineClass ... }
上帝模式： \u0069\u0066\u0020\u0028\u0073\u0065\u0073\u0073\u0069\u006f\u006e ...
```

## 变体与关联

- **其它「改写源码形态」的静态绕过**：JSP `pageEncoding` 指定非 UTF-8 让扫描器按错误编码解析、`trimDirectiveWhitespaces` 拼接 scriptlet 片段、特殊闭合符改变 try/catch 结构——这些与上帝模式组合使用，效果叠加。
- **jspx 变形**：suffix 选 jspx 时 `&lt;`/`&gt;` 转义 + 上帝模式，文件里既无尖括号明文也无可读关键字。
- **动态侧仍在**：无论怎么改源码，连接后仍是「首包大（stage-1 payload 入 session）+ 后续小包」的行为，配合标准 AES Base64 流量仍可被流量侧识别；要更隐蔽需同时改 Cryption 与响应外壳。
- 关联：哥斯拉 JSP 伪 404 响应与自定义 findStr 标记（流量侧伪装）、PHP 侧 AES session webshell（同一生成器机制在 PHP 加密器上的形态）。

## 检测与防御

- 静态检测要做**归一化**：先按 JSP 规则还原 `\uXXXX`、`&lt;/&gt;`、八进制/十六进制转义，再做关键字与 AST 匹配；对「整文件几乎全是 `\u` 转义」的文件直接判定可疑。
- 规则层面：检测 `\u0052\u0075\u006e\u0074\u0069\u006d\u0065` 这类转义后的敏感词组合、检测超长单行（生成器会去掉换行，马通常是一行超长文本）。
- 运行层面：JSP 文件写入即告警（正常发布走构建/上传白名单）；结合流量侧 session 首包体积异常、`JSESSIONID` 后续小包打同一路径做交叉验证。
- 应急：命中可疑 JSP 后先做转义还原再判断，不要因为 grep 不到关键字就判定文件干净。
