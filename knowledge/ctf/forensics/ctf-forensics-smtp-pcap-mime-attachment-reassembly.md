---
id: ctf-forensics-smtp-pcap-mime-attachment-reassembly
title: SMTP pcap 取证：提取 MIME 附件 Base64、口令与分段 PDF 重组
type: scenario
domain: ctf
path: ctf/forensics
technique: smtp-pcap-mime-attachment-reassembly
aliases:
- SMTP 流量取证
- 邮件附件提取
- MIME multipart
- Base64 附件
- pcap 邮件
- PDF 分段合并
tags:
- ctf
- forensics
- smtp
- pcap
- mime
- base64
- email
- attachment
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V205
  verified_at: '2026-11-07T02:40:42+08:00'
  notes: 已对照原文与图片55/57/59核对：MIME boundary、base64 附件、密码 S3W8yzixNoL8、PDF 分段合并一致；PoC 未复跑。
---

## 一句话结论

SMTP 明文流量中的 `DATA` 段承载完整 MIME 邮件，附件通常是 `Content-Transfer-Encoding: base64` 的分段文本；按邮件/附件边界提取并 Base64 解码，可还原 ZIP/PDF 等文件；口令可能在同一邮件的正文或被 `strings`/`grep Password` 直接发现，多个 PDF 分段按顺序合并即可得到完整文档与 flag。

## 原理

- **SMTP 会话**：客户端 `EHLO/MAIL FROM/RCPT TO/DATA`，`DATA` 之后是 RFC 822 邮件头 + MIME 正文；`250 OK` 结束。pcap 中可直接跟随 TCP 流看到明文（未加密的 25/587 端口）。
- **MIME multipart**：`Content-Type: multipart/mixed; boundary=...` 分隔多个 part；每个 part 有 `Content-Type`、`Content-Disposition: attachment; filename=...`、`Content-Transfer-Encoding: base64`，正文是 76 字符/行的 Base64。
- **附件提取**：按 boundary 切分 part，取附件 part 的 Base64 正文，去掉换行后解码；用文件魔数（`PK\x03\x04`、`%PDF-`）校验。
- **口令线索**：邮件正文/主题/附件名可能写 `Password: ...`；`strings pcap | grep -i password` 能快速定位。ZIP 可能加密，需要该口令解压。
- **PDF 分段**：大文件可能被拆成多个邮件/附件发送（如 `part1`、`part2`）；按名称/序号排序后 `cat` 合并，或按 PDF 对象/EOF 边界拼接。
- **为什么可行**：SMTP 明文 + Base64 无加密，协议层完整保留附件；只要抓到完整 `DATA` 段，文件可无损还原。

## 触发条件

- pcap 包含未加密 SMTP 会话（端口 25/587/2525 等），且 `DATA` 段完整。
- 邮件为 MIME multipart，附件使用 Base64（或 quoted-printable）编码。
- 附件未使用 S/MIME/PGP 加密；ZIP 口令可从正文/其他邮件获得。
- 大文件被分段时，所有分段都在 pcap 中且可排序。

## 利用步骤

1. 用 Wireshark/tshark 过滤 `smtp`，或 `tcp.port == 25`；`Follow TCP Stream` 查看完整会话。
2. 找到 `DATA` 段与 `Content-Type: multipart/...; boundary=...`，按 boundary 切分 part。
3. 对每个附件 part：读取 `filename`、`Content-Transfer-Encoding`、Base64 正文；去掉换行后解码，用魔数判断类型。
4. 搜索口令：正文/主题/附件名中的 `Password`、`pass`、`unzip`；或 `strings capture.pcap | grep -i password`。
5. 若附件是加密 ZIP，用口令解压（`unzip -P <password>` / 7z）；若为 PDF 分段，按文件名/序号排序后合并。
6. 打开还原的 PDF/文档，读取 flag；对图片/二维码做进一步解码。

## PoC

```bash
# 1) 过滤 SMTP 并导出 TCP 流
tshark -r phreaky.pcap -Y smtp -T fields -e frame.number -e tcp.stream
tshark -r phreaky.pcap -q -z follow,tcp,ascii,0 > smtp_stream.txt

# 2) 快速找口令
strings -a phreaky.pcap | grep -iE 'password|passwd|unzip'

# 3) 提取 Base64 附件（示例：从流文本中取 boundary 之间的 base64）
python3 - <<'PY'
import base64, re
text = open("smtp_stream.txt", encoding="utf-8", errors="ignore").read()
# 按 MIME boundary 粗切；实际可按 Content-Type/Disposition 精确解析
parts = re.split(r"--[-=\w]+", text)
for i, p in enumerate(parts):
    if "Content-Disposition: attachment" not in p:
        continue
    body = p.split("\n\n", 1)[-1]
    b64 = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    if len(b64) < 100:
        continue
    data = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    open(f"attachment_{i}.bin", "wb").write(data)
    print(i, data[:8])
PY

# 4) 解压/合并
unzip -P 'S3W8yzixNoL8' decoded.zip
cat parts/*.pdf.* > phreaks_plan.pdf
```

## 变体与关联

- **SMTP over TLS**：若使用 SMTPS/STARTTLS，需要服务器私钥或 SSLKEYLOGFILE 才能解密；见 [[ctf-forensics-tls-keylog-pcap-decrypt]]。
- **quoted-printable**：`Content-Transfer-Encoding: quoted-printable`，用 `quopri` 解码；注意软换行 `=`。
- **HTML 正文**：flag 可能在 HTML 正文/注释/内嵌 `cid:` 图片中；同时检查 `text/html` part。
- **多封邮件**：按 `Message-ID`/`Subject` 分组，附件可能分散在多封邮件；用 `tshark -e smtp.data` 批量导出。
- **关联卡片**：[[ctf-forensics-phishing-email-xor-docx-base64-key]]（.eml 附件 XOR 解密）；[[ctf-forensics-pcap-irc-dcc-nested-archive-password]]（pcap 带外传输与口令）。

## 检测与防御

- **邮件加密**：对外邮件使用 TLS（SMTPS/STARTTLS），敏感附件使用 S/MIME/PGP 或加密压缩包。
- **DLP**：监控外发邮件附件类型/大小/关键字；对 Base64 大附件做内容检测。
- **取证**：保留 pcap 原始文件与哈希；记录提取脚本、boundary、文件名、口令来源，确保可复现。
- **检测**：SMTP 会话中出现大量 Base64、`Content-Disposition: attachment`、异常附件名/多分段；结合邮件网关日志关联发件人/收件人。
