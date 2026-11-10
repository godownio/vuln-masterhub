---
id: tools-burp-jython-request-dropper-http-listener
title: Burp Jython 插件按域名/路径丢弃请求（Request Dropper）：IHttpListener 过滤 + ITab 配置面板 + 空请求替换
type: scenario
domain: tools
path: tools/burp
technique: burp-jython-request-dropper
aliases:
- Burp 请求丢弃插件
- Request Dropper
- IHttpListener 拦截
- Burp 屏蔽上报请求
- Jython Burp 扩展
tags:
- burp
- jython
- extension
- http-listener
- request-drop
- proxy-filter
- pentest
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444
  verified_at: '2026-11-09T23:04:40+08:00'
  notes: 已对照原文核对：IBurpExtender/IHttpListener/ITab 三接口、registerHttpListener/addSuiteTab、processHttpMessage 仅处理请求方向、analyzeRequest 取 URL 后对 host/path 做子串匹配、setRequest(buildHttpMessage([], b"")) 空报文替换实现丢弃、Update/Reset/Swing 配置面板，均与原文完整代码一致；图 01-04（配置页/更新弹框/tools 与 apis 命中标红）一致。PoC 为原文代码的最小骨架并已注明 UI 从简；工具卡无组件版本，affected_versions 保持空。与既有 Montoya/PyRO 插件卡用途与 API 不同，dedup 全 new，不重复。dup-scan.json(11-08) 早于建卡(11-09)。
---

## 一句话结论

用 Jython 实现 Burp 的 `IBurpExtender`/`IHttpListener`/`ITab` 三个接口，在 `processHttpMessage` 中把请求 URL 的 host/path 与配置列表做子串匹配，命中时用 `messageInfo.setRequest(helpers.buildHttpMessage([], b""))` 将请求替换为空消息，即可按域名/路径丢弃指定请求；配置通过 Swing 选项卡维护，适合屏蔽被测系统持续上报 IP、设备信息之类的噪声流量。

## 原理

- **扩展入口**：Burp（legacy 扩展 API）通过 `IBurpExtender.registerExtenderCallbacks(callbacks)` 加载扩展；`callbacks.getHelpers()` 提供 HTTP 报文分析/构造工具，`callbacks.registerHttpListener(self)` 把实现 `IHttpListener` 的对象注册为 HTTP 监听器，`callbacks.addSuiteTab(self)` 注册自定义选项卡（`ITab` 的 `getTabCaption`/`getUiComponent`）。
- **拦截回调**：每个经过 Burp 的请求/响应都会进入 `processHttpMessage(toolFlag, messageIsRequest, messageInfo)`；仅当 `messageIsRequest` 为真时处理请求，`helpers.analyzeRequest(messageInfo).getUrl()` 取出 `java.net.URL`，用 `url.getHost()` 与 `url.getPath()` 分别与配置的域名、路径列表比对。
- **丢弃方式**：命中后调用 `messageInfo.setRequest(helpers.buildHttpMessage([], b""))`，把请求替换为不带任何 header/body 的空报文，Burp 不再转发原始请求；原文注释即“Replace the request with an empty request / Drop the request”。这不是连接级 abort，而是报文级替换，效果上让匹配的请求无法到达服务端。
- **配置管理**：Swing `JPanel` + `GridBagLayout` 放两个 `JTextArea`（每行一个域名/路径）、Update 与 Reset 按钮；Update 把文本 `splitlines()` 存入列表并弹 `JOptionPane` 提示，Reset 清空文本框。匹配使用 `in` 子串判断，因此填 `tools` 会命中所有路径含 `tools` 的请求，填 `example.com` 会命中 host 中包含该串的所有子域。
- **为什么用于渗透测试**：被测系统常通过前端脚本持续上报 IP、设备指纹等数据，制造大量无关流量；在代理层按域名/路径丢弃这些请求，可让 Proxy History 和后续扫描聚焦业务请求，同时避免上报数据污染测试环境。

## 触发条件

- Burp Suite 已配置 Jython 运行环境（加载 Jython standalone jar，Extender → Options → Python Environment）；
- 扩展代码按 Jython（Python 2 语法）编写，并实现 `IBurpExtender`、`IHttpListener`、`ITab`；
- 已知需要屏蔽的域名/路径特征（可按子串配置）；
- 仅影响经过该 Burp 代理的流量；直接连接目标或使用其他代理的请求不受影响。

## 利用步骤

1. 在 Burp Extender 的 Python Environment 中加载 Jython standalone jar。
2. 新建扩展脚本，定义 `BurpExtender(IBurpExtender, IHttpListener, ITab)`；在 `registerExtenderCallbacks` 中设置扩展名、保存 callbacks/helpers、`addSuiteTab`、`registerHttpListener`。
3. 构建配置选项卡：两个多行文本域（Domains to drop / Paths to drop）+ Update/Reset 按钮，Update 时 `splitlines()` 写入列表并弹框。
4. 在 `processHttpMessage` 中仅处理请求方向，`analyzeRequest` 取 URL 后调用 `should_drop`：域名列表任一 `domain in url.getHost()` 或路径列表任一 `path in url.getPath()` 即命中。
5. 命中时 `setRequest(buildHttpMessage([], b""))` 丢弃并打印命中日志；其余请求正常放行。
6. 在 Proxy History 确认目标请求被拦截（原文截图中被丢请求行标红，路径含 `tools`/`apis`）。

## PoC

```python
# -*- coding: UTF-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTextArea, JScrollPane, JButton, JLabel, JOptionPane
from java.awt import GridBagLayout, GridBagConstraints

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RequestDropper")

        self.tab = JPanel(GridBagLayout())
        self.domain_area = JTextArea("", 4, 20)
        self.path_area = JTextArea("", 4, 20)
        self.update_button = JButton("Update", actionPerformed=self.update_config)
        self.reset_button = JButton("Reset", actionPerformed=self.reset_config)
        self.tab.add(JLabel("Domains to drop (one per line):"))
        self.tab.add(JScrollPane(self.domain_area))
        self.tab.add(JLabel("Paths to drop (one per line):"))
        self.tab.add(JScrollPane(self.path_area))
        self.tab.add(self.update_button)
        self.tab.add(self.reset_button)

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self.domains_to_drop = []
        self.paths_to_drop = []

    def getTabCaption(self):
        return "Request Dropper Config"

    def getUiComponent(self):
        return self.tab

    def update_config(self, event):
        self.domains_to_drop = self.domain_area.getText().splitlines()
        self.paths_to_drop = self.path_area.getText().splitlines()
        JOptionPane.showMessageDialog(None, "Configuration Updated")

    def reset_config(self, event):
        self.domain_area.setText("")
        self.path_area.setText("")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if self.should_drop(url):
                self.drop_request(messageInfo)

    def should_drop(self, url):
        for domain in self.domains_to_drop:
            if domain in url.getHost():
                return True
        for path in self.paths_to_drop:
            if path in url.getPath():
                return True
        return False

    def drop_request(self, messageInfo):
        messageInfo.setRequest(self._helpers.buildHttpMessage([], b""))
```

说明：原文完整代码还包含 GridBag 约束与命中日志打印；此处保留最小可运行骨架（UI 布局从简）。

## 变体与关联

- 变体：改用 Montoya API 的 `HttpHandler`/`ProxyRequestHandler` 在请求阶段直接不转发，语义上更接近“拦截”而非空报文替换（关联既有 [[tools-burp-montoya-extension-skeleton-suite-tab-context-menu]] 骨架卡）。
- 变体：把“丢弃”改为“改包”——删除特定 header、替换上报 URL 或返回伪造响应，用于欺骗前端埋点/风控；与 autoDecoder、Galaxy 等加解密钩子不同，本卡处理的是流量筛选。
- 变体：把域名/路径列表改为正则或优先队列，支持导入配置文件和热更新。
- 关联：Burp 扩展开发与请求改写系列卡（[[tools-burp-montoya-pyro-python-hot-reload-bridge]]、[[tools-burp-galaxy-http-hook-dynamic-key-capture]]）；本卡是“按规则丢弃请求”的最小实现。

## 检测与防御

- 测试侧注意：空请求替换可能导致连接复用/会话状态异常或误丢关键请求，应先用小范围路径验证并保留命中日志；域名/路径采用子串匹配，注意误伤（如 `api` 会命中 `apix`）。
- 防御/分析侧启示：客户端上报（IP、设备信息等）依赖本地代理链路时可被代理层丢弃，因此服务端安全审计不应仅依赖前端上报数据，关键事件应在服务端独立采集与校验。
- 合规：只在授权测试范围内使用；丢弃上报可能影响被测系统的风控判断，需与目标方确认测试影响。
