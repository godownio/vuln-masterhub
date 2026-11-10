---
id: tools-burp-montoya-pyro-python-hot-reload-bridge
title: 自研 Burp Montoya + PyRO 桥接插件：ProxyRequestHandler 拦截加解密 + watchdog 热加载 Python + config 分项目
type: scenario
domain: tools
path: tools/burp
technique: montoya-pyro-python-hot-reload-bridge
tags:
- burp
- montoya
- java
- python
- pyro
- pyrolite
- watchdog
- hot-reload
- encryption
- decryption
- tooling
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V425
  verified_at: '2026-11-09T17:23:04+08:00'
  notes: 已完整阅读原文并逐张核对14张图片：ProxyRequestHandler handleRequestReceived/ToBeSent(图01/02)、initialize 注册 api.proxy().registerRequestHandler 与 http_decorate/copyPyroServiceFile/launchPyroServer(图03)、pyrolite 5.1 依赖(图04)、PyroProxy(host,port,obj)(图05)、burp.call("invoke_method",{method,base64})(图06)、BurpyServicePyro.invoke_method getattr/b64d/http/build(图07)、Burpy 方法名 proxy_request_received/tosent/request_decorate(图08)、importlib spec_from_file_location+exec_module(图09)、watchdog on_modified 热加载与独立线程(图10)、config.json 四键 pythonPath/burpyPath/servicePort/domain(图11/12)、ContextMenuItemsProvider 选区 base64→encrypt_or_decrypt→setRequest 替换(图13)、Burpy.encrypt/decrypt 模板(图14)均与原文一致。卡片作为单插件开发配方（桥接+热加载+配置+选区）为原文五问的完整方案，不拆分；与现成 Burpy 卡、Montoya 骨架卡为不同工程/路线。未验证点：未编译 jar、未运行 PyRO/Python 服务（原文代码本身不完整）。原文未给受影响版本，affected_versions 已 --clear。路径 tools/burp 合法，无文章 ID/URL/长段摘录。
url: /docs/tools/burp/tools-burp-montoya-pyro-python-hot-reload-bridge/
draft: false
kb_aliases:
- http_decorate 插件
- decoraterequestHandler
- Montoya ProxyRequestHandler
- pyrolite 5.1
- BurpyServicePyro
- watchdog exec_module 热加载
- Burp 插件 config.json 分项目
- Burp 插件选区加解密
---

## 一句话结论

用 Montoya API 的 `ProxyRequestHandler` 在 Burp 代理的请求接收/发送、响应接收/发送各节点拦截流量，Java 端通过 `pyrolite`（Pyro RPC）把 Base64 编码的报文发给本地 Python 服务，由 Python `Burpy` 类的方法完成解密/改包/重加密；`watchdog` 监听 Python 脚本变化并用 `exec_module` 热加载、`config.json` 按项目切换 `pythonPath/burpyPath/servicePort/domain`，编辑器里选中的报文片段也能右键发往 Python 处理后原地替换。

## 原理

- **Burp 数据包生命周期与 Montoya 钩子**：请求从客户端进入 proxy 模块 → 请求引擎 → 目标；响应反向经过响应引擎 → proxy → 客户端。Montoya API 在 proxy、http.handler 等模块提供对应接口：实现 `ProxyRequestHandler` 的 `handleRequestReceived`/`handleRequestToBeSent`（响应侧同理）即可在报文进出 Burp 时改写；在 `BurpExtension.initialize(MontoyaApi api)` 中调用 `api.proxy().registerRequestHandler(handler)` 注册，`initialize` 返回后 handler 生效。
- **Java→Python 的 PyRO 桥**：Java 端引入 `net.razorvine:pyrolite:5.1`，用 `new PyroProxy(serviceHost, servicePort, serviceObj)` 连接本地 Python 服务；调用统一走 `burp.call("invoke_method", new Object[]{"proxy_request_received", base64_request})`，其中 `invoke_method` 相当于 RPC 方法名、第二个字符串是 Python 侧要调用的具体方法名，报文用 Base64 编码保证二进制/换行安全。Python 侧 `BurpyServicePyro.invoke_method(self, method_name, data)` 用 `getattr(burpy_instance, method_name)` 取方法、`http(b64d(data))` 还原报文，更新 `first_line` 后调用 `func(headers, body)`，再 `data.build()` 返回。
- **Python 处理层**：Python 脚本实现 `Burpy` 类，方法名与 Java 侧传入的 `method_name` 对应（如 `proxy_request_received`、`proxy_request_tosent`、`request_decorate`、`response_decorate`、`encrypt`、`decrypt`），在方法里写具体加解密/签名/改包逻辑；返回 `(headers, body)`。
- **热加载调试**：Python 服务启动时用 `importlib.util.spec_from_file_location` + `module_from_spec` + `exec_module` 加载脚本；`watchdog` 的 `FileSystemEventHandler.on_modified` 检测到脚本文件变化后再次 `exec_module` 并重建 `burpy_instance = burpy.Burpy()`，避免每次改脚本都重启 PyRO 服务。watchdog 在单独线程运行，避免与服务阻塞。
- **按项目分流**：`config.json` 保存 `pythonPath`、`burpyPath`、`servicePort`、`domain`；Java 的 `readSettings()` 读取后，handler 先判断请求 `Host` 是否等于配置域名、路径是否匹配正则，只对目标项目流量调用 Python，避免误改其它流量；不同项目换配置文件/脚本即可。
- **编辑器选区处理**：实现 `ContextMenuItemsProvider`，在 Repeater/编辑器中获取用户选中的文本与 selection offsets，Base64 后调用 `encrypt`/`decrypt` 对应方法，再把返回文本替换原选区（`setRequest`/`setResponse`），适合手工改单个加密字段。
- **为什么这样做**：Burp 负责抓包/重放/可视化，Java 插件负责生命周期集成，Python 负责快速迭代的加解密与签名逻辑；热加载与配置化把“改算法→重编译→重启”缩短为“改脚本即生效”，对加密接口测试效率提升明显。作者也指出 pyrolite 在高并发扫描场景可能丢包，通信机制需要重构，说明该方案适合手工/低并发测试而非大规模扫描。

## 触发条件

- Burp Suite 支持 Montoya API（新版本），本机有 JDK 与 Maven/Gradle 可编译扩展。
- 本地 Python 3 环境，装有 Pyro5（Python 服务端）与目标加解密依赖；Java 端有 pyrolite 5.1。
- 配置文件 `http_decorate/config.json` 指向正确的 `pythonPath`、`burpyPath`、端口与目标域名。
- 目标接口的加密/签名逻辑已还原或可在 Python 中复刻；测试在授权范围内。

## 利用步骤

1. 建 Maven/Gradle 工程，加入 `montoya-api` 与 `net.razorvine:pyrolite:5.1` 依赖。
2. 实现 `BurpExtension.initialize(MontoyaApi api)`：保存 api、`readSettings()` 读配置、`api.extension().setName("http_decorate")`、复制 PyRO 服务文件、启动 Python PyRO 服务、`api.proxy().registerRequestHandler(new decoraterequestHandler(api))`。
3. Java handler 在 `handleRequestReceived`/`handleRequestToBeSent` 中过滤 Host/路径，Base64 报文后 `burp.call("invoke_method", new Object[]{"proxy_request_received", base64_request})`，把返回字符串替换回请求。
4. Python 服务端实现 `BurpyServicePyro.invoke_method` 与 `Burpy` 类方法（解密、改包、加密、签名），返回 `header, body`。
5. 加入 watchdog 热加载：`on_modified` 时 `exec_module` 并重建实例；单独线程启动 observer。
6. 配置文件按项目拆分（域名/端口/脚本路径），Java 只处理匹配域名与正则的流量。
7. 注册 `ContextMenuItemsProvider`，在编辑器中选中文本右键调用 Python `encrypt`/`decrypt` 并替换选区。
8. 在 Burp 中加载 jar，先关闭自动处理、用右键/选区手动验证，再开启生命周期 handler；观察扩展 Output 与 Python 日志。

## PoC

以下为按原文截图重写的关键骨架（端口、域名、路径为占位符，未编译/未运行）：

```xml
<dependency>
    <groupId>net.razorvine</groupId>
    <artifactId>pyrolite</artifactId>
    <version>5.1</version>
</dependency>
```

```java
public class HttpDecorate implements BurpExtension {
    private MontoyaApi api;
    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        readSettings();                                   // 读 config.json
        api.extension().setName("http_decorate");
        copyPyroServiceFile();                            // 部署 Python 服务端
        launchPyroServer();                               // 启动 PyRO
        api.proxy().registerRequestHandler(new decoraterequestHandler(api));
    }
}

public class decoraterequestHandler implements ProxyRequestHandler {
    @Override public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {
        if (!BurpExtender.domain.equals(req.header("Host").value())) return ProxyRequestReceivedAction.continueWith(req);
        if (!Pattern.matches(regex, req.pathWithoutQuery())) return ProxyRequestReceivedAction.continueWith(req);
        String b64 = api.utilities().base64Utils().encodeToString(req.toByteArray());
        String out = burp.call("invoke_method", new Object[]{"proxy_request_received", b64}).toString();
        return ProxyRequestReceivedAction.continueWith(buildRequestFrom(out));
    }
    @Override public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) { /* 同理 */ }
}
```

```json
{
  "pythonPath": "python39.exe",
  "burpyPath": "/rpc/call_burpy.py",
  "servicePort": "10999",
  "domain": "example.com"
}
```

```python
class BurpyServicePyro:
    def invoke_method(self, method_name, data):
        global burpy_instance
        data = http(b64d(data))
        data.headers.update({"first_line": data.first_line})
        data.headers, data.body = getattr(burpy_instance, method_name)(data.headers, data.body)
        return data.build()

def on_modified(event):                     # watchdog 热加载
    if event.src_path.endswith(burpy_name):
        spec.loader.exec_module(burpy)
        global burpy_instance
        burpy_instance = burpy.Burpy()
```

```python
class Burpy:
    def proxy_request_received(self, header, body):
        return header, body                 # 在此实现解密/改包/重加密
    def encrypt(self, data):
        return data
    def decrypt(self, data):
        return data
```

说明：原文为开发过程记录，代码片段不完整（部分 import/注册行未展示）；本卡按截图重写骨架，未编译加载，也未连接任何目标。

## 变体与关联

- [[tools-burp-burpy-pyro-python-auto-encrypt-decrypt]]：现成 Burpy 插件路线（Burp 经 PyRO 调 Python、`Burpy` 类接口与三类报错）；本卡是自研 Montoya 插件实现同一桥接，并增加热加载、配置分流与选区处理，PoC 与工程结构不同。
- [[tools-burp-montoya-extension-skeleton-suite-tab-context-menu]]：Montoya 扩展最小骨架（BurpExtension/Suite Tab/右键菜单）；本卡在其上加入 ProxyRequestHandler 与 Python 桥。
- [[tools-burp-galaxy-http-hook-dynamic-key-capture]]：Galaxy 插件的 Montoya HttpHook 四段拦截与动态密钥捕获，现成插件路线；本卡是自研路线。
- [[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]、[[tools-burp-js-hook-bridge-traffic-encrypt-decrypt]]：其它“Burp 外部加解密”方案（Flask 接口、JS Hook 桥），可按团队偏好选型。
- 变体：PyRO 可换成 gRPC/HTTP/ZeroMQ；热加载可换成重启服务或 Java 侧脚本引擎（Jython/GraalJS）；配置可换成 Burp 项目选项或环境变量；生命周期钩子可换成 `HttpHandler`（更适合统一改写）。
- 边界：pyrolite 在高并发扫描下可能丢包；PyRO 端口暴露/冲突；Python 脚本语法错误会让 handler 抛异常；Burp 与 Montoya API 版本不匹配可能运行期报错；不同 Burp 版本 proxy handler 语义略有差异。

## 检测与防御

- 本卡是自研测试工具，无对目标的远程攻击面；“防御”主要是工具供应链与使用合规。
- 合规：只在授权测试中使用；插件/脚本会接触全部代理流量（Cookie/Token），只加载自己编写或审计过的代码。
- 安全：PyRO 服务只监听 `127.0.0.1`，不要把端口暴露到公网；config 中不要硬编码生产凭据；日志避免打印敏感报文。
- 可靠性：高并发扫描时改用更稳的通信机制；脚本异常要捕获并回退原报文，避免 Burp 流量被插件破坏；升级 Burp 后重新编译并对齐 montoya-api 版本。
