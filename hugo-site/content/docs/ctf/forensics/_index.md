---
title: CTF Forensics
weight: 1
---

# CTF Forensics

## 这层是什么

取证与流量分析。

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

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [1.2 MS/s 原始 PCM 转 WAV：频谱图 Morse 解出 Base32，掩码爆破频谱中的 RAR 密码](ctf-forensics-raw-pcm-spectrogram-morse-base32-rar/) | verified | high | 2026-11-07 |
| [1bpp 帧缓冲二维码还原：88x88 位图逐行左移 2y 再整体左移 24 像素](ctf-forensics-1bpp-qr-row-shift-frame-recovery/) | verified | high | 2026-11-06 |
| [4×4 打乱二维码按顺序重排并解码](ctf-forensics-qr-4x4-tile-reorder/) | verified | high | 2026-11-06 |
| [ADS-B 报文 pcap 解码：pyModeS 提取 ICAO 与速度找最快飞机](ctf-forensics-adsb-pcap-pymodes-fastest-icao-md5/) | verified | high | 2026-11-12 |
| [ANSI 终端控制序列模拟：从终端录像恢复被清屏/覆盖隐藏的 flag](ctf-forensics-ansi-terminal-emulator-screen-recovery/) | verified | high | 2026-11-06 |
| [Arnold 猫脸变换逆变换：矩阵求逆 + 多轮还原 + a/b 参数爆破](ctf-forensics-arnold-cat-map-inverse-parameter-brute-force/) | verified | high | 2026-11-06 |
| [BitLocker 内存取证：Volatility 提取 FVEK + dislocker 离线挂载解密卷](ctf-forensics-bitlocker-fvek-memory-dislocker-mount/) | verified | high | 2026-11-07 |
| [bkcrack -d 解出的条目仍是 raw deflate：Raw Inflate 还原内层 ZIP 后再处理口令](ctf-forensics-bkcrack-d-raw-inflate-nested-zip/) | verified | high | 2026-11-06 |
| [CAN pcap 干扰帧过滤 + 物理量解析：按 payload 唯一率找真实车速并哈希峰值帧号](ctf-forensics-can-signal-id-filter-speed-peak-frame-hash/) | verified | high | 2026-11-06 |
| [CAN 重复帧末字节隐蔽信道：按 ID 过滤 pcap 提取隐藏数据还原 flag](ctf-forensics-can-repeated-frame-trailing-byte-covert-channel/) | verified | high | 2026-11-06 |
| [candump 日志里成对提取 UDS 0x2E（WriteDataByIdentifier）请求与 0x6E 正响应，把请求帧第 4 字节起的负载按 UTF-8 解码即还原被写入的数据](ctf-forensics-can-uds-wdbi-request-response-pair-extract/) | verified | high | 2026-11-08 |
| [Chrome DevTools 堆快照中搜索泄漏的 flag](ctf-forensics-chrome-heap-snapshot-flag-search/) | verified | high | 2026-11-06 |
| [DeepSound 音频隐写：WAV 载体中提取隐藏文档与密码链](ctf-forensics-deepsound-audio-stego-extract/) | verified | high | 2026-11-06 |
| [DNS A 查询子域携带 Base64 分片：固定偏移提取、去重拼接后还原命令会话与 flag](ctf-forensics-dns-a-base64-label-dedup-reassemble/) | verified | medium | 2026-11-08 |
| [DNS TXT 两位编号分片重组 JAR：Java 校验器异或逆推](ctf-forensics-dns-txt-chunk-reassembly-jar-validator/) | verified | high | 2026-11-06 |
| [DNS 隧道隐写：二进制子域名还原二维码口令 + 按事务 ID 分流 zip/PGP，私钥 rev+hex+rev 修复后解密](ctf-forensics-dns-binary-label-qr-password-transactionid-pgp/) | verified | medium | 2026-11-09 |
| [DOCM 宏提取与去混淆：vbaProject.bin 中 Base64+XOR 0x23 还原 PowerShell 下载 URL](ctf-forensics-docm-vba-base64-xor-powershell-download-url/) | verified | high | 2026-11-06 |
| [DOCX 解压取 customXml/item1.xml 注释中的 Base64 隐藏数据](ctf-forensics-docx-customxml-base64-comment/) | verified | high | 2026-11-06 |
| [ext4 镜像未分配块 strings 残留：恢复口令、密钥与明文 flag](ctf-forensics-ext4-image-unallocated-strings-residual/) | verified | high | 2026-11-06 |
| [FAT16 删除文件非连续簇恢复：按接口连续性拼接 4 段并 CRC32 校验，提取 Lua 状态机常量](ctf-forensics-fat16-deleted-noncontiguous-extent-recovery/) | verified | high | 2026-11-05 |
| [FHIR Observation 生命体征隐写：血压四档编码四元符号 + GF(2) 仿射映射还原 flag](ctf-forensics-fhir-observation-base4-affine-stego/) | verified | high | 2026-11-05 |
| [HTA 多层 unescape 嵌套 + 大小写空格规避 → VBS 垃圾串注入 base64 → XSLT CDATA 字符位移：四层静态还原](ctf-forensics-hta-layered-unescape-to-vbs-charshift-defiller/) | draft | medium | 2026-11-08 |
| [HTTP beacon gate.php + DNS A 记录定位 C2：从 pcap 提取目的 IP、Host 域名与端口](ctf-forensics-http-beacon-gate-php-dns-c2-extraction/) | verified | high | 2026-11-06 |
| [HTTP C2 初始化 JSON 的 AES key/IV 与 PNG tEXt 命令通道取证](ctf-forensics-http-c2-aes-init-png-text-command-channel/) | verified | high | 2026-11-06 |
| [HTTP Range 分片重组取证：Content-Range 回填 + MD5 校验 + 邮件线索恢复 SQLCipher 口令](ctf-forensics-http-range-fragment-reassembly-sqlcipher/) | verified | high | 2026-11-06 |
| [HTTP 内嵌 pyc + 自定义 Base64 TCP 协议：tshark 提取 3333 流量还原命令输出](ctf-forensics-pcap-custom-base64-tcp-protocol/) | verified | high | 2026-11-06 |
| [HTTP 流量未授权 API 审计：无认证头 + 200 + 业务数据，GET 405/POST 200 也算](ctf-forensics-http-unauth-api-audit/) | verified | high | 2026-11-06 |
| [I/Q 文件 NBFM 解调 + Morse 数字密码：从 192kHz 采样恢复压缩包口令](ctf-forensics-nbfm-iq-morse-digit-password-zip/) | verified | high | 2026-11-06 |
| [ICMP Echo Request payload 顺序拼接还原隐蔽文本](ctf-forensics-icmp-echo-payload-concatenation/) | verified | high | 2026-11-06 |
| [ICMP TTL 隐写：64/65 映射二进制位还原 ASCII](ctf-forensics-icmp-ttl-bit-stego/) | verified | high | 2026-11-06 |
| [ICMP 隐蔽外带双层加密：EX1L 元数据 + PBKDF2 派生 + ChaCha20/AES-GCM + ScrambleSeed 乱序](ctf-forensics-icmp-double-layer-pbkdf2-shuffle-exfil/) | verified | high | 2026-11-06 |
| [ISO 启动层 isolinux.bin 偏移处隐藏 Base58 字符串](ctf-forensics-iso-isolinux-base58-hidden/) | verified | high | 2026-11-06 |
| [JA3 与目的 IP 过滤日志分片：按时间戳拼接 5 字符载荷](ctf-forensics-ja3-flow-fragment-timestamp-reassembly/) | verified | medium | 2026-11-06 |
| [KeePass kdbx 密码库离线爆破：hashcat -m 13400 恢复主密码并读取横向凭据](ctf-forensics-keepass-kdbx-hashcat-master-crack/) | verified | high | 2026-11-07 |
| [Kerberos keytab + GSSAPI subkey 手动解密 DCE/RPC Packet Privacy 分片，提取计划任务 XML](ctf-forensics-kerberos-dcerpc-packet-privacy-subkey-decrypt/) | verified | high | 2026-11-06 |
| [Linux input_event 键盘记录还原：24 字节 struct + Shift 状态还原按键序列](ctf-forensics-linux-input-event-keylogger-decode/) | verified | high | 2026-11-07 |
| [Linux 内存镜像恢复 RC4 加密文件：linux_find_file 导出为空时搜源码取硬编码双密钥，两层 RC4 解密](ctf-forensics-linux-memory-rc4-encrypted-file-source-key-recovery/) | verified | medium | 2026-11-11 |
| [LSB 截图水印提取：时间戳种子 AES-CTR + 置换索引 + 3 次重复，暴力时间戳还原姓名工号](ctf-forensics-lsb-watermark-timestamp-aesctr-permutation/) | verified | high | 2026-11-07 |
| [MIDI 多轨共享时钟隐写：note 事件异或寄存器 + 时间网格偏移还原隐藏消息](ctf-forensics-midi-shared-tick-register-stego/) | verified | high | 2026-11-05 |
| [Modbus/TCP 异常写寄存器定位：0x10 多寄存器写入 + IEEE754 浮点还原](ctf-forensics-modbus-write-register-ieee754-abnormal-value/) | verified | high | 2026-11-06 |
| [Modbus/TCP 读保持寄存器载荷重建 PDF：口令爆破后提取隐藏文字](ctf-forensics-modbus-read-register-pdf-carve-password-hidden-text/) | verified | high | 2026-11-07 |
| [NTFS $LogFile 重命名时间线：从 USN/RENAME 记录恢复分段 flag](ctf-forensics-ntfs-logfile-rename-timeline-recovery/) | verified | high | 2026-11-07 |
| [NTFS 镜像元数据取证：UTF-16LE 文件名残留 + MFT slack + ADS 恢复分段 flag](ctf-forensics-ntfs-mft-slack-ads-flag-segments/) | verified | high | 2026-11-06 |
| [OPC UA 流量中分段 Base64 C2 结果重组：String 节点提取 + JSON 命令还原](ctf-forensics-opcua-string-segmented-base64-c2-results/) | verified | high | 2026-11-06 |
| [OpenIGTLink POSITION 轨迹还原：剔除失真点后按 z 分层栅格化成 5×7 像素字体](ctf-forensics-openigtlink-position-trajectory-pixel-font/) | verified | high | 2026-11-05 |
| [PCAP HTTP 外传取证：从下载脚本提取 XOR key，解密 multipart 上传的 hex 数据](ctf-forensics-pcap-http-xor-exfil-key-recover/) | verified | high | 2026-11-06 |
| [pcap shell 历史还原 base64 外传图片：nc 传输与 JPG 尾部 flag](ctf-forensics-pcap-shell-history-base64-nc-image-exfil/) | verified | high | 2026-11-06 |
| [pcap 与 PHP session 文件关联审计：非管理员用他人 search_id 查询的水平越权](ctf-forensics-pcap-php-session-search-id-idor-audit/) | verified | high | 2026-11-07 |
| [PCAP 中 IRC DCC 传输加密 7z：Base64 口令 + 嵌套 pcap 追踪 TCP 流](ctf-forensics-pcap-irc-dcc-nested-archive-password/) | verified | high | 2026-11-06 |
| [PCAP 中 RTP 语音导出与 Whisper 转写：八进制数字串还原 7z 密码](ctf-forensics-rtp-pcap-audio-whisper-octal-7z/) | verified | high | 2026-11-07 |
| [PCAP 噪声分层取口令：组播 Base64 口令 + HTTP JSON AES ZIP + RGB-LSB 位流](ctf-forensics-pcap-multicast-base64-password-aes-zip-rgb-lsb/) | verified | high | 2026-11-06 |
| [PCAP 导出 HTTP 上传的加密 webshell：用脚本内置 SM4 实现、key 与密文解密还原 flag](ctf-forensics-pcap-http-sm4-webshell-decrypt/) | verified | medium | 2026-11-07 |
| [PCAP 还原 WiFi 入侵链：EAPOL 握手、LuCI 后台爆破、DNS 劫持与反弹 shell](ctf-forensics-pcap-wifi-router-takeover-chain/) | verified | high | 2026-11-06 |
| [PCAP 里 HTTP 上传字段的 base64 密码解不开：按上传报文格式定位真实起始偏移，去掉前 N 字符再解](ctf-forensics-pcap-http-upload-field-offset-base64-password/) | verified | medium | 2026-11-08 |
| [PDF 扫描件嵌入图像批处理：contact sheet 定位竖排低对比 flag 条带](ctf-forensics-pdf-embedded-images-contact-sheet-vertical-strip/) | verified | high | 2026-11-06 |
| [PKZIP 传统加密密钥调度逆向：由 Key0/Key1/Key2 反推密码（bkcrack -r）](ctf-forensics-pkzip-key-schedule-reverse-password/) | verified | high | 2026-11-06 |
| [PLC 固件容器与 OT 流量取证：段熵筛真段、CRC-16 剔除伪造密钥帧、槽位状态三重裁决](ctf-forensics-plc-firmware-container-nwlp-crc-slot-adjudication/) | verified | high | 2026-11-06 |
| [PNG IHDR 宽高 CRC32 爆破：文件头整体减一还原 + 正确宽高恢复](ctf-forensics-png-ihdr-width-height-crc32-brute-force/) | verified | high | 2026-11-06 |
| [PNG LSB 内嵌 FAT12 软盘镜像：zsteg b8 平面提取磁盘 + testdisk/FTK 恢复 _LAG.ICO 取 flag](ctf-forensics-png-lsb-embedded-fat12-disk-testdisk/) | verified | medium | 2026-11-12 |
| [PNG LSB 进阶隐写：行优先无结果时改用列优先 yx 扫描，短载荷用编码特征而非可打印率判定](ctf-forensics-png-lsb-column-major-scan-order/) | verified | high | 2026-11-06 |
| [PNG LSB 隐写提取下载 URL 与 OpenPGP 公钥：zsteg 多通道扫描并按大小比对释放载荷](ctf-forensics-png-lsb-zsteg-download-url-openpgp-payload/) | verified | medium | 2026-11-08 |
| [PNG 尾部 IEND 之后附加一句话木马/脚本的识别：末 8 字节校验与尾部载荷提取](ctf-forensics-png-iend-appended-webshell-audit/) | verified | high | 2026-11-07 |
| [PNG 条形码多通道取数重建 21×21 QR：Comment/首行红通道 LSB 与 6 位 hex 低 21 位](ctf-forensics-barcode-png-multichannel-qr-row-rebuild/) | verified | high | 2026-11-06 |
| [PNG 蓝通道 8×8 DCT QIM 提取隐藏 pyc，再按 alpha LSB 与循环 XOR 还原明文](ctf-forensics-png-dct-qim-blue-channel-pyc-alpha-lsb/) | verified | high | 2026-11-06 |
| [S7COMM pcap 按 TCP 校验和筛出未篡改分组：拼接有效载荷 hex→base32 还原 flag](ctf-forensics-s7comm-tcp-checksum-valid-packet-filter/) | verified | medium | 2026-11-08 |
| [SMTP pcap 取证：提取 MIME 附件 Base64、口令与分段 PDF 重组](ctf-forensics-smtp-pcap-mime-attachment-reassembly/) | verified | high | 2026-11-07 |
| [SNOW 空白隐写 + binwalk 尾随 ZIP + ZipCrypto 明文攻击](ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip/) | verified | high | 2026-11-06 |
| [SOC 编排日志取证：DNS 隧道 + base32 分片外泄 PAT 与 git 配置劫持链](ctf-forensics-soc-dns-tunnel-base32-pat-exfil/) | verified | high | 2026-11-06 |
| [SQLite Freeblock 链表隐写：sys_config 入口指针 + 大端节点 + 页号 XOR 还原隐藏 SQL](ctf-forensics-sqlite-freeblock-linked-list-page-xor/) | verified | high | 2026-11-06 |
| [SQLite 外壳内嵌 GZIP/TAR/LevelDB：伪装数据库的递归解包](ctf-forensics-fake-sqlite-embedded-gzip-tar-leveldb/) | verified | high | 2026-11-06 |
| [SSTV 慢扫描电视音频解码：从 WAV 还原图片与密码](ctf-forensics-sstv-audio-image-decode/) | verified | high | 2026-11-06 |
| [Task Scheduler RPC 流量提取计划任务：Description 字段承载 Base64 外带文件](ctf-forensics-task-scheduler-rpc-description-exfil/) | verified | high | 2026-11-06 |
| [TCP payload 序号化 8-bit 记录取最低位：按嵌入序号重排 392 bit 还原隐藏文本](ctf-forensics-tcp-payload-indexed-lsb-bitstream/) | verified | high | 2026-11-07 |
| [TCP 紧急指针隐写：URG 标志与 16 位 urgent_pointer 一一对应，ASCII 拼 base64](ctf-forensics-tcp-urgent-pointer-covert-channel/) | verified | high | 2026-11-06 |
| [TCP 载荷末两字节十六进制拼接重建 ZIP：另一条流量里的明文口令解压取 flag](ctf-forensics-tcp-payload-tail-two-bytes-zip-rebuild/) | verified | high | 2026-11-07 |
| [Thumbs.db 缩略图缓存恢复已删除图片：从磁盘镜像提取 Explorer 缩略图流](ctf-forensics-thumbs-db-deleted-image-thumbnail-recovery/) | verified | high | 2026-11-07 |
| [TLS keylog 解密 pcap：从流量中提取 SSLKEYLOGFILE 并导入 Wireshark 还原 HTTP](ctf-forensics-tls-keylog-pcap-decrypt/) | verified | high | 2026-11-07 |
| [Tomcat 管理面板入侵 pcap 还原：nmap SYN 扫描 → gobuster → /admin Basic 认证 → WAR 上传 → 反弹 shell/计划任务](ctf-forensics-tomcat-manager-pcap-scan-basic-war-reverse-shell/) | verified | high | 2026-11-11 |
| [TrueCrypt 内存镜像主密钥提取：进程/命令行定位 + 密钥搜索 + 挂载加密卷](ctf-forensics-truecrypt-memory-key-mount/) | verified | high | 2026-11-06 |
| [UDP 载荷 AES-ECB：16 字节帧头异或 0xFF 作 key，解密 OLE2 宏 hex 再 XOR 爆破](ctf-forensics-udp-aes-ecb-key-header-xor-ole2-macro/) | verified | high | 2026-11-08 |
| [USB HID 键盘流量还原击键：参考 pcap 建立 Shift/非 Shift 键位映射](ctf-forensics-usb-hid-keyboard-reference-mapping/) | verified | high | 2026-11-07 |
| [VeraCrypt AES-XTS 数据区手动解密：已知 master key 按扇区还原裸盘](ctf-forensics-veracrypt-aes-xts-manual-sector-decrypt/) | verified | high | 2026-11-06 |
| [VeraCrypt 卷伪装为 flag.txt + key.jpg 作 keyfile 挂载，提取流量包取 flag](ctf-forensics-veracrypt-keyfile-mislabeled-container/) | verified | high | 2026-11-12 |
| [VeraCrypt 隐藏卷取证：vmdk 用 7z 提取 FAT 容器、主/备用双密码分别进入外层与隐藏卷、WinHex 扇区级读已解锁卷](ctf-forensics-veracrypt-hidden-volume-vmdk-7z-winhex/) | verified | medium | 2026-11-12 |
| [VMware 加密虚拟机 vmx 字典爆破：pyvmx-cracker 解加密 VM，encryptedVM.guid 残留行导致失败的修复](ctf-forensics-vmware-vmx-encrypted-vm-dictionary-crack/) | verified | medium | 2026-11-12 |
| [Volatility filescan 定位用户壁纸文件，按 cmdscan 提示做 Atbash 解码](ctf-forensics-volatility-filescan-wallpaper-atbash-cmdscan/) | verified | medium | 2026-11-08 |
| [Volatility memdump 记事本进程提取 Edit 控件明文：从 notepad.exe 内存 dump 搜链接/提取码/flag](ctf-forensics-memdump-notepad-edit-control-plaintext/) | verified | medium | 2026-11-12 |
| [Volatility windows 插件定位窗口所属进程：explorer.exe memdump 后 foremost 按签名分离已打开图片（缩略图缓存取证）](ctf-forensics-volatility-windows-plugin-explorer-memdump-foremost/) | verified | medium | 2026-11-12 |
| [Volatility2 cmdline/cmdscan/consoles 三件套：从内存恢复命令行输入与控制台输出，dump 恶意脚本定位 base64 秘密](ctf-forensics-volatility-cmdscan-consoles-command-history/) | verified | high | 2026-11-13 |
| [Volatility2 iehistory/chromehistory 提取浏览器历史：file:// 访问记录、下载链接与 pastebin/邮箱线索链](ctf-forensics-volatility-iehistory-chromehistory-browser-clues/) | verified | high | 2026-11-13 |
| [Volatility2 mftparser 从内存镜像恢复已删除文件：$MFT 记录常驻 $DATA 直接读出删除文本 flag](ctf-forensics-volatility-mftparser-deleted-file-recover/) | verified | high | 2026-11-13 |
| [Volatility2 screenshot 插件从内存镜像恢复桌面截图：多 GDI 会话 WinSta0 位图 dump 读窗口内 flag 与线索](ctf-forensics-volatility-screenshot-desktop-recover/) | verified | medium | 2026-11-12 |
| [WAV 频域 8 频点并行 FSK 隐写：每 0.1s 用 8 个频率的开关还原 1 字节](ctf-forensics-wav-multifrequency-8bit-block-fsk-stego/) | verified | high | 2026-11-06 |
| [Web 开放目录泄露 .bash_history：从命令历史还原攻击者 TTP 并取出 base64 编码的 C2 凭据](ctf-forensics-web-open-dir-bash-history-ttp-replay/) | verified | medium | 2026-11-08 |
| [WebP RIFF 自定义 chunk 隐写提取：按 chunk 遍历与奇数字节对齐取出 ECH0 载荷](ctf-forensics-webp-riff-custom-chunk-ech0-extraction/) | verified | high | 2026-11-06 |
| [WebShell 流量取证：由 ViewMore.php 写出的 d00r.php 后门 + POST 中 base64 加密 ZIP 与同流密码还原攻击者写入文件](ctf-forensics-webshell-generated-backdoor-base64-zip-in-http-stream/) | verified | high | 2026-11-13 |
| [Windows 便签取证：volatility filescan 提取 .snt 文件 + 磁盘找密钥文件 + OpenSSL Salted AES 解密](ctf-forensics-windows-sticky-notes-snt-memory-openssl-aes/) | verified | medium | 2026-11-12 |
| [Windows 镜像离线 SAM/SYSTEM 蜂巢提取 NTLM 并掩码爆破：6 位纯数字口令秒破](ctf-forensics-windows-sam-system-offline-ntlm-mask-crack/) | verified | high | 2026-11-06 |
| [Word DOCM VBA 工程密码保护绕过：篡改 DPB 标记 + olevba 提取并改写 Decode 调用取明文](ctf-forensics-docm-vba-project-password-dpb-bypass/) | verified | high | 2026-11-06 |
| [Word 宏三段载荷：VBA XOR+Base64 解出 PowerShell，-EncodedCommand 解码后再 Deflate 解压取出最终脚本](ctf-forensics-docm-vba-xor-powershell-encodedcommand-deflate/) | verified | high | 2026-11-07 |
| [WSL ext4.vhdx 离线取证：挂载虚拟磁盘读取 bash_history 与模型部署配置](ctf-forensics-wsl-ext4-vhdx-offline-inspect/) | verified | medium | 2026-11-06 |
| [XM 模块音乐渲染 WAV 后按窗口峰值还原比特流](ctf-forensics-xm-module-peak-window-bitstream-stego/) | verified | medium | 2026-11-06 |
| [zip2john $pkzip$ 哈希 + 已知密码：直接解密 ZipCrypto 流恢复压缩包内容](ctf-forensics-zip2john-pkzip-hash-zipcrypto-stream-decrypt/) | verified | high | 2026-11-06 |
| [ZipCrypto 已知明文攻击：用 PNG 文件头 16 字节 bkcrack 恢复密钥](ctf-forensics-zipcrypto-png-header-known-plaintext-bkcrack/) | verified | high | 2026-11-07 |
| [从 pcap 按业务请求顺序还原栈式 VM 后门指令并解密 payload](ctf-forensics-pcap-http-order-vm-opcode-reconstruction/) | verified | high | 2026-11-06 |
| [像素 R/B 通道拼 16 位码元：还原 UTF-16/Unicode 隐藏文本](ctf-forensics-pixel-rb-channel-utf16-codepoint/) | verified | high | 2026-11-06 |
| [光棱坦克隐写：灰度分段 + 对角线交错像素分离（支持多图与彩色）](ctf-forensics-prism-tank-grayscale-band-diagonal-interleave/) | verified | medium | 2026-11-06 |
| [内存镜像关键词搜索：按 UTF-8/UTF-16 编码定位明文 flag](ctf-forensics-memory-image-flag-keyword-search/) | verified | medium | 2026-11-07 |
| [内存镜像按「flag 前缀的 Base64」搜索：Win10 浏览器搜索历史把 base64(irisctf{...) 当查询词留在内存，grep 即得整段](ctf-forensics-memory-base64-prefix-browser-history-flag/) | verified | high | 2026-11-08 |
| [内存镜像跨证据口令链：hashdump NTLM/envars/图片文字/前序 flag 的 SHA1 作为压缩包与 KeePass 口令](ctf-forensics-memory-cross-artifact-password-chain/) | verified | high | 2026-11-13 |
| [加密 Office 文档离线破解：office2john 提取校验哈希后字典/掩码爆破](ctf-forensics-office-doc-password-office2john-hashcat/) | verified | medium | 2026-11-06 |
| [加密 VirtualBox 虚拟机与 LUKS 磁盘离线破解：pyvboxdie-cracker 爆破 VDI KeyStore + bruteforce-luks 爆破 /dev/sda](ctf-forensics-vbox-vdi-keystore-luks-dictionary-crack/) | verified | medium | 2026-11-12 |
| [十六进制 PNG 流重组：QR 码链与 base64 解码](ctf-forensics-hex-png-stream-qr-chain-base64/) | verified | high | 2026-11-06 |
| [单频正弦波逐字符音频：按 0.12s 分段 FFT 主频还原字符](ctf-forensics-audio-per-char-single-frequency-fft/) | verified | high | 2026-11-06 |
| [双灰度像素二值隐写：128/129 映射 0/1 还原 flag](ctf-forensics-two-tone-gray-128-129-binary/) | verified | high | 2026-11-06 |
| [图片 R 通道 mod 10 特征 + 给定 MLP 推理：从隐写图恢复 ASCII flag](ctf-forensics-image-r-channel-mod10-mlp-decode/) | verified | high | 2026-11-06 |
| [图片隐写多阶段链：EXIF ROT13 提示 → steghide 取加密 zip → john 爆破 → 二进制 leet 口令](ctf-forensics-cinnamon-image-steghide-zip-binary-leet-chain/) | verified | medium | 2026-11-06 |
| [图片题三段链：Aztec 条码读出压缩包口令 → 解包后图片尾部叠加 PNG/TIFF/Zlib → 分离出 PNG 并按 CRC 重算修复被改的宽高](ctf-forensics-aztec-barcode-password-appended-image-carve-png-ihdr-height-fix/) | verified | medium | 2026-11-07 |
| [多层 PNG/WAV 隐写链：XMP 掩码口令 + 尾部逆序 nibble 交换 ZIP + 频谱字符表 + 伪造 IHDR 高度与 G^A 低位迷宫](ctf-forensics-multilayer-png-wav-spectrogram-maze-stego/) | verified | high | 2026-11-06 |
| [多接口脱敏数据关联还原身份链：手机号爆破 + 姓名/生日/身份证/邮箱/IP 交叉匹配](ctf-forensics-multi-api-masked-pii-correlation/) | verified | high | 2026-11-06 |
| [多证书 TLS 流量解密：RSA 参数 n 匹配证书、tshark 导入私钥、JWT 与请求体身份不一致统计越权](ctf-forensics-tls-rsa-cert-match-tshark-jwt-body-mismatch/) | verified | high | 2026-11-06 |
| [已知密钥文件异或恢复 PNG：再按 10×10 大像素块转二进制](ctf-forensics-xor-known-key-large-pixel-block/) | verified | high | 2026-11-06 |
| [幻影坦克隐写：PNG Alpha 混合双图公式与棋盘格像素分离](ctf-forensics-mirage-tank-alpha-two-image-checkerboard/) | verified | high | 2026-11-06 |
| [幻影坦克隐写：RGBA 字节流 2-bit pair 与奇偶校验还原隐藏图/密码](ctf-forensics-phantom-tank-rgba-2bit-pair-parity/) | verified | medium | 2026-11-06 |
| [循环异或加密的 PNG：用已知明文（8 字节魔数 + IHDR 长度/类型，共 16 字节）反推重复密钥，再整文件异或解密](ctf-forensics-repeating-xor-png-header-key-recovery/) | verified | high | 2026-11-08 |
| [循环异或的 WAV/RIFF 头：第 4–8 字节是文件长度而非常量，用密文自身长度（XOR 不改变长度）补出该字段，凑齐 16 字节已知明文反推出可读的密钥串](ctf-forensics-repeating-xor-wav-riff-size-field-derived-key/) | verified | high | 2026-11-09 |
| [批量 PDF 钓鱼链接提取：Annotation URI + 正文 URL + redirect 参数域名白名单与 MD5](ctf-forensics-pdf-annotation-redirect-phishing-url-extraction/) | verified | high | 2026-11-06 |
| [数据泄露溯源：从 PCAP 还原前端 AES 加密的登录口令 + 内存镜像定位异常外联进程](ctf-forensics-pcap-frontend-aes-login-password-and-memory-anomalous-process-trace/) | verified | medium | 2026-11-08 |
| [日志异常字段中的分段 Base64 提取拼接还原 flag](ctf-forensics-log-field-base64-fragments/) | verified | high | 2026-11-06 |
| [每行一包的十六进制文本重组 pcapng：scapy wrpcap 还原后追踪 TCP 流，把载荷里的 JFIF 段导出为图片](ctf-forensics-hexlines-wrpcap-tcpstream-jpeg/) | verified | high | 2026-11-08 |
| [注册表编号值交替偏移：1-26 单字符值按奇偶 +7/-6 还原](ctf-forensics-registry-numbered-values-alternating-shift/) | verified | high | 2026-11-06 |
| [流量包尾部逆序 7z + steghide 密钥 + 时间戳平方动态 KEY 逐层解出 flag](ctf-forensics-reversed-7z-steghide-timestamp-squared-dynamic-key/) | verified | high | 2026-11-07 |
| [海量视频语料中检索隐藏 flag：发布时间排序 + 逐帧 OCR/VLM 扫描](ctf-forensics-video-corpus-frame-ocr-vlm-flag-search/) | verified | high | 2026-11-07 |
| [私有封装 pcap 剥离与 Modbus 写寄存器隐蔽载荷：双重反转 Base64 还原 flag](ctf-forensics-modbus-private-pcap-write-register-covert/) | verified | high | 2026-11-06 |
| [自定义协议 ET3RNUMX + AES-256-GCM 流量解密：从 Go 二进制字符串提取 key](ctf-forensics-custom-protocol-aes-gcm-pcap-binary-key/) | verified | high | 2026-11-06 |
| [蚁剑流量定位连接密钥与攻击者留存值：SQL 注入写 shell 的 POST 参数名即连接密码，参数 base64 解出 hacker.txt 的 UUID 标记](ctf-forensics-antsword-connection-key-request-param-attacker-marker/) | verified | high | 2026-11-13 |
| [蚁剑自定义编码器流量按编码器逐段还原：ROT13 与 Reverse（按字符倒序）两层解码](ctf-forensics-antsword-rot13-reverse-encoder-traffic-decode/) | verified | high | 2026-11-08 |
| [螺旋像素置乱还原 + 空白像素填充隐写](ctf-forensics-spiral-pixel-scramble-blank-fill/) | verified | high | 2026-11-06 |
| [视频 8x8 块黑白位图隐写：逐帧采样还原文件并 XOR 0xAA](ctf-forensics-video-8x8-block-bitmap-stego-xor-aa/) | verified | high | 2026-11-06 |
| [视频单像素通道隐写：逐帧读取指定坐标的 B/G/R 值还原字符流](ctf-forensics-video-single-pixel-channel-extraction/) | verified | high | 2026-11-06 |
| [进程内存转储改后缀 .data 用 GIMP 按原始图像打开恢复画面](ctf-forensics-process-memory-dump-gimp-raw-image/) | verified | low | 2026-11-08 |
| [透视形变二维码：正面无法识别，按近大远小从侧面角度扫描](ctf-forensics-perspective-warped-qr-angle-scan/) | verified | high | 2026-11-06 |
| [部分 EWF 镜像解析 + NTFS 删除文件/git 对象恢复 + OpenSSL aes-256-cbc 解密核心记忆](ctf-forensics-partial-ewf-ntfs-openssl-memory-decrypt/) | verified | high | 2026-11-06 |
| [钓鱼邮件附件 XOR 加密 DOCX：从正文 Base64 取真实密钥并解密](ctf-forensics-phishing-email-xor-docx-base64-key/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
