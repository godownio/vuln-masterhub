# 表达式注入

## 这层是什么

SpEL、OGNL、MVEL、EL 等表达式注入。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- [SpEL](spel/README.md) —— Spring Expression Language 注入与利用。
- [OGNL](ognl/README.md) —— OGNL 注入与 Struts2 利用。
- [MVEL](mvel/README.md) —— MVEL 表达式注入。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Apache Commons Jelly 模板解析注入：jelly:core 危险标签（invoke/invokeStatic/new/set）与标签属性中的 JEXL 表达式都能直接执行 Java 代码](web-java-expression-jelly-core-tag-jexl-injection-rce.md) | verified | high | 2026-11-08 |
| [Apache Commons JXPath 1.3 表达式注入原语：getValue 中 exec(java.lang.Runtime.getRuntime(),'cmd') 调用任意静态方法执行命令（CVE-2022-41852）](web-java-expression-jxpath-static-method-invocation-rce.md) | verified | high | 2026-11-08 |
| [EL 表达式注入回显：反射 BufferedInputStream 的 buf 字段 + String(byte[],charset) 构造器，不引入 Scanner/BufferedReader](web-java-expression-el-injection-bufferedinputstream-buf-echo.md) | verified | high | 2026-11-09 |
| [Flowable class 类型执行监听器 + 反射实例化：给 NoOpServiceTask 的 name Expression 字段注入 ${} 触发表达式求值 RCE](web-java-expression-flowable-class-listener-field-expression-rce.md) | verified | high | 2026-11-09 |
| [Flowable expression/delegateExpression 监听器：implementation 直接作为 JUEL 表达式求值，流程启动即 RCE](web-java-expression-flowable-expression-listener-juel-rce.md) | verified | high | 2026-11-09 |
| [Java ScriptEngine 的 isJson 校验直接 eval 字符串：_json 参数经 BaseResult 构造器直达 Nashorn 代码执行](web-java-expression-scriptengine-isjson-eval.md) | verified | medium | 2026-11-05 |
| [JellyContext.compileScript 直接接收远程 URL：服务端按攻击者给的地址拉取 XML 脚本，getXMLReader().parse 解析后 Script.run 执行 jelly:core 危险标签导致 RCE](web-java-expression-jelly-compilescript-remote-url-script-rce.md) | verified | medium | 2026-11-09 |
| [jetbrick-template 表达式注入：Class::method 反射 + 字符串拼接绕黑名单加载内存马](web-java-expression-jetbrick-template-class-static-injection-rce.md) | verified | high | 2026-11-07 |
| [JEXL new() 任意文件读写：Scanner 读文件、FileOutputStream.write(int) 逐字节写文件](web-java-expression-jexl-file-read-write-scanner-fileoutputstream.md) | verified | high | 2026-11-09 |
| [JEXL new() 实例化 ProcessBuilder 命令执行：数组字面量或 split 构造 String[]](web-java-expression-jexl-new-processbuilder-command-exec.md) | verified | high | 2026-11-09 |
| [JEXL new() 触发反序列化：ObjectInputStream(FileInputStream).readObject() 读取本地 payload](web-java-expression-jexl-objectinputstream-deserialization.md) | verified | high | 2026-11-09 |
| [JEXL new() 调 SnakeYAML.load 组件 gadget：!!JdbcRowSetImpl 属性注入触发 JNDI lookup](web-java-expression-jexl-snakeyaml-load-gadget.md) | verified | high | 2026-11-09 |
| [JEXL 无引号/关键字过滤 bypass：用数字方法链 1.toString().charAt(0).toChars(N) + String.valueOf 构造任意字符串](web-java-expression-jexl-no-quote-string-construction-bypass.md) | verified | high | 2026-11-09 |
| [JSP EL 表达式注入的 WAF 绕过与 Scanner 回显](web-java-expression-el-injection-waf-bypass-scanner-echo.md) | verified | high | 2026-11-05 |
| [JustEL 表达式注入 + 配置路径穿越写 plugins.txt + HotInstallPlugin 热加载：addCart 参数到任意类实例化 RCE](web-java-expression-justel-plugin-hotload-config-path-traversal.md) | verified | high | 2026-11-07 |
| [定时任务 invokeTarget 白名单子串 + 黑名单遗漏：ELProcessor#eval EL 注入 RCE](web-java-expression-invoketarget-whitelist-substring-elprocessor-el-rce.md) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
