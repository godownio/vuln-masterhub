# 取证

## 这层是什么

主机、内存、网络与日志取证。

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
| [access.log 攻击链还原：DirBuster→sqlmap→后台登录→KindEditor 上传→蚁剑的 UA 与路径时间线](defense-forensics-access-log-attack-chain-tool-ua.md) | verified | high | 2026-11-08 |
| [AD CS 证书滥用取证：certocm.log 定位可疑 CA 名，再用 ESEDatabaseView 解析 CertLog 下 CA 数据库 .edb 的 Certificates/RequestAttributes 表定位恶意证书模板与序列号](defense-forensics-adcs-abuse-certocm-log-ca-edb-template-serial.md) | verified | high | 2026-11-08 |
| [AdaptixC2 BeaconHTTP 流量解密：DB 取 Listener EncryptKey、RC4 解心跳提 SessionKey 再还原命令与回显](defense-forensics-adaptixc2-beacon-http-rc4-session-key-traffic-decrypt.md) | verified | high | 2026-11-07 |
| [AdaptixC2 Gopher TCP 配置提取与流量解密：Listener Key、INIT_PACK 会话密钥与多层 msgpack 帧](defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt.md) | verified | high | 2026-11-07 |
| [AdaptixC2 HTTP Beacon 配置提取与 RC4 解密：4 字节长度 + 加密 Profile + 16 字节 Key](defense-forensics-adaptixc2-http-beacon-profile-rc4-extract.md) | verified | high | 2026-11-07 |
| [Agent Tesla 内存邮箱取证：套壳提取 .NET 母体后，dnSpy 替换资源号解密 SMTP NetworkCredential 账号与口令](defense-forensics-agenttesla-dotnet-smtp-credential-resource-decrypt.md) | verified | high | 2026-11-11 |
| [AhMyth Android RAT C2 流量识别与解析：Socket.IO 明文 order 指令、x0000ca/fm/lm 等远控码与二进制附件回传](defense-forensics-ahmyth-android-rat-socketio-c2-traffic-parse.md) | verified | high | 2026-11-09 |
| [ANSI 转义序列注入日志：清屏与隐藏文本篡改终端显示](defense-forensics-ansi-escape-log-poisoning.md) | verified | high | 2026-11-05 |
| [AsyncRAT 内存取证：按配置结构特征（长度前缀+0x00000080+0x2C Key）定位提取配置，MegaDumper+dnspy 提模块](defense-forensics-asyncrat-memory-config-extract.md) | verified | high | 2026-11-12 |
| [AsyncRAT 服务端自带无口令 p12 解 C2 流量：openssl 导出 ServerCertificate.p12 私钥，Wireshark 解 TLS 1.0 RSA_WITH_AES_128_CBC_SHA 后再解 gzip 载荷](defense-forensics-asyncrat-servercert-p12-empty-pass-tls-gzip-decrypt.md) | verified | high | 2026-11-12 |
| [AsyncRAT 通信流量批量解密：4 字节小端压缩长度/解压长度 + gzip 外层帧，MessagePack 内层与 Msgpack/Dll 嵌套 gzip 的解析脚本](defense-forensics-asyncrat-traffic-frame-gzip-msgpack-decrypt-script.md) | verified | high | 2026-11-12 |
| [BianLian 勒索软件解密：硬编码 AES-CBC KEY/IV + 每样本加密偏移，desktop.ini 已知明文匹配密钥，按文件大小分块逆向恢复](defense-forensics-bianlian-ransomware-hardcoded-aes-cbc-offset-decrypt.md) | verified | high | 2026-11-10 |
| [BRC4 Badger C2 配置与请求格式：管道分隔域名/端口/UA + JSON cds/mtdt 加密 POST](defense-forensics-brc4-badger-config-json-beacon-format.md) | verified | medium | 2026-11-08 |
| [C2 服务端目录取证：SQLite clients/listeners/tunnels 与 setting.conf 还原基础设施](defense-forensics-c2-server-sqlite-conf-artifacts.md) | verified | high | 2026-11-06 |
| [Chromium 数据离线解析：密钥静态注入、前缀分派与七类数据还原](defense-forensics-chromium-artifact-offline-decrypt.md) | verified | high | 2026-11-05 |
| [CloudTrail 原始日志 jq 溯源：User-Agent/IP 指纹定位攻击者 → 事件时间线 → IAM 提权与持久化动作还原](defense-forensics-cloudtrail-raw-jq-useragent-ip-timeline.md) | verified | high | 2026-11-09 |
| [Cobalt Strike C2 流量解密：beacon_keys 私钥解元数据得 Raw Key，再用 cs-parse-http-traffic 还原命令](defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt.md) | verified | high | 2026-11-07 |
| [Core dump 敏感信息提取：strings、字节搜索、ELF LOAD 映射与高熵扫描](defense-forensics-core-dump-secret-extraction.md) | verified | high | 2026-11-05 |
| [CryptoAPI AES-256 文件加密样本：SHA-256 派生密钥与 CryptSetKeyParam 取 IV 后离线解密](defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery.md) | verified | high | 2026-11-06 |
| [CVE-2026-34621 PDF 在野样本分层去混淆：PDF 十六进制转义、JSFuck、Base64、字符串数组与 AES-CTR/zlib 载荷](defense-forensics-cve-2026-34621-pdf-js-layered-deobfuscation.md) | verified | high | 2026-11-05 |
| [CyberGate RAT 通信解密：7c0a 长度帧 + RC4 固定 key + zlib 魔标，与自定义字符集 Base64 的 0d0a 帧](defense-forensics-cybergate-rat-traffic-rc4-zlib-custom-base64.md) | verified | high | 2026-11-10 |
| [DanderSpritz 模块化后门通信协议：内置 RSA 公钥校验 + RSA 封装 AES 会话密钥 + 模块下发解密](defense-forensics-danderspritz-modular-backdoor-rsa-aes-protocol.md) | verified | high | 2026-11-06 |
| [DinodasRAT Linux UDP 变体流量解密：独立内置 key + UDP 二次封装，QQ-TEA/qq_crypt 还原心跳设备信息](defense-forensics-dinodasrat-udp-variant-traffic-decrypt.md) | verified | medium | 2026-11-09 |
| [EagleMonitorRAT 通信协议逆向与批量解密：4+1 字节帧头 + BinaryFormatter/QuickLZ/PBKDF2/AES-CBC + 16 字节 GUID 前缀](defense-forensics-eaglemonitorrat-traffic-protocol-decrypt.md) | verified | high | 2026-11-09 |
| [ELF 构造器顺序取证：DT_NEEDED 顺序不等于实际初始化顺序](defense-forensics-elf-constructor-order-dt-needed.md) | verified | high | 2026-11-05 |
| [ELF 符号顶替的四路取证：dladdr、readelf、LD_DEBUG 与 objdump](defense-forensics-elf-symbol-interposition-triage.md) | verified | high | 2026-11-05 |
| [Flask SSTI 注入的 RC4 加密后门：从错误处理器 payload 提取密钥并解密 C2 流量](defense-forensics-flask-ssti-rc4-backdoor-traffic-decrypt.md) | verified | high | 2026-11-06 |
| [Go 挖矿样本内存取证：gdb dump 可读段并用 strings 提取 msgpack 上报字段](defense-forensics-go-miner-heap-msgpack-field-extraction.md) | verified | high | 2026-11-06 |
| [HomuWitch 勒索加密格式与免赎金解密：硬编码口令 + 文件头 16B salt 经 PBKDF2(10000) 派生 AES-256-CBC 密钥，DEFLATE 压缩](defense-forensics-homuwitch-pbkdf2-aes-cbc-deflate-decrypt.md) | verified | high | 2026-11-10 |
| [IFUNC resolver 行为取证：readelf、strace 与 LD_DEBUG 判定加载期执行](defense-forensics-ifunc-resolver-triage.md) | verified | high | 2026-11-05 |
| [IIS 默认日志盲区与 FREB 捕获请求头攻击载荷](defense-forensics-iis-freb-header-payload-capture.md) | verified | medium | 2026-11-04 |
| [IM 客户端 SQLCipher 数据库解密：定位 sqlite3_key 并从进程内存提取密钥](defense-forensics-sqlcipher-im-db-memory-key-extraction.md) | verified | high | 2026-11-05 |
| [iOS Wi-Fi 取证：com.apple.wifi-private-mac-networks.plist 的 NSDate 首连时间与 SSID/热点名还原](defense-forensics-ios-wifi-plist-nsdate-first-join.md) | verified | medium | 2026-11-06 |
| [iOS 加密备份口令离线爆破与 plist/sysdiagnose 元数据提取：4 位 PIN、序列号与蓝牙 MAC](defense-forensics-ios-encrypted-backup-pin-bruteforce-plist.md) | verified | medium | 2026-11-06 |
| [iOS 照片库 Photos.sqlite 溯源：ZASSET 关联导入来源判定 AirDrop、原始文件名与拍摄 App](defense-forensics-ios-photos-sqlite-airdrop-origin.md) | verified | medium | 2026-11-06 |
| [iOS 第三方文件传输 App 取证：Paprika（com.estmob.paprika）偏好 plist 设备标识与状态枚举判定传输方向](defense-forensics-ios-thirdparty-transfer-app-plist-state.md) | verified | medium | 2026-11-06 |
| [Java 内存马 heap dump 取证：cafebabe/yv66 字节码特征与 strings 请求记录](defense-forensics-java-memshell-heapdump-bytecode.md) | verified | high | 2026-11-05 |
| [Java 远控插件加载与内网穿透：PluginUtil 下载 JAR + neutrino proxy 隧道 + PscpService 远程文件/DB/PowerShell](defense-forensics-java-rat-plugin-loader-neutrino-tunnel.md) | verified | high | 2026-11-06 |
| [Java 远控配置解密：AES-ECB version.txt + SHA1 派生 key 与 H2 agent.mv.db 历史配置](defense-forensics-java-rat-encrypted-config-h2-db.md) | verified | high | 2026-11-06 |
| [Linux 进程名伪装取证：comm/cmdline/exe 三源不一致与 15 字节上限](defense-forensics-linux-process-name-masquerade-comm-cmdline.md) | verified | high | 2026-11-05 |
| [LocalSend 传输时间取证：GUI 只显示到分钟时从 settings.json/FlutterSharedPreferences 取秒级时间戳](defense-forensics-localsend-config-precise-timestamp.md) | verified | high | 2026-11-06 |
| [MemProcFS 挂载内存镜像为虚拟文件系统：pid/sys 浏览、forensic 时间线与 findevil 异常定位](defense-forensics-memprocfs-mount-findevil-timeline.md) | verified | medium | 2026-11-09 |
| [Merlin Agent 内存取 OPAQUE 会话密钥：64 位 hex 字符串扫描 + transformers 解密全协议流量](defense-forensics-merlin-agent-opaque-memory-secret-traffic-decrypt.md) | verified | high | 2026-11-07 |
| [MSSQL 1433 TDS 流量复盘：从 SQL batch 还原 xp_cmdshell 建号、加管理员与开 RDP 命令](defense-forensics-mssql-tds-xpcmdshell-traffic-replay.md) | verified | high | 2026-11-07 |
| [MySQL binlog 行镜像恢复被删除订单：定位 Delete_rows 事件并解码 before-image](defense-forensics-mysql-binlog-delete-row-recovery.md) | verified | medium | 2026-11-06 |
| [MySQL 通用查询日志溯源：按 Access denied 聚合爆破源 IP 并定位首次成功登录时间](defense-forensics-mysql-general-log-bruteforce-source-success-time.md) | verified | high | 2026-11-07 |
| [NjRAT/Bladabindi C2 流量识别与解码：明文上线包、Base64 受害者信息、act/kl/pas 命令与 CAP JPEG 桌面帧](defense-forensics-njrat-c2-traffic-base64-decode.md) | verified | high | 2026-11-06 |
| [Obsidian 本地库取证：Mega 恢复密钥与 self-hosted LiveSync CouchDB 凭据恢复](defense-forensics-obsidian-livesync-config-credential-recovery.md) | verified | high | 2026-11-06 |
| [Office 外链 RTF 样本分析：oleid/oleobj 取外部关系、rtfobj 提 Equation.3 对象、xorsearch 定位 GetEIP、scDbg FindSc/CreateDump 还原下载执行 shellcode](defense-forensics-office-rtf-equation-editor-sample-shellcode-triage.md) | verified | medium | 2026-11-12 |
| [OSC 52 剪贴板读取：在受害者终端内窃取宿主机剪贴板内容](defense-forensics-terminal-osc52-clipboard-read.md) | verified | high | 2026-11-05 |
| [OverlayFS/挂载覆盖隐藏 /var/log 的识别与恢复](defense-forensics-overlayfs-mount-shadowing-log-hide.md) | verified | high | 2026-11-05 |
| [pslist 与 psscan 双视角对比：从内存镜像发现隐藏与已退出进程](defense-forensics-pslist-psscan-hidden-terminated-process-diff.md) | verified | medium | 2026-11-09 |
| [PyInstaller 勒索样本取证：解包提取内嵌 RSA 私钥，OAEP 解 AES key，ECB 解密 PDF](defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery.md) | verified | high | 2026-11-06 |
| [PyInstaller 木马 C2 流量解密：4 字节长度 + 12 字节 nonce + 密文 + 16 字节 GCM tag](defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt.md) | verified | high | 2026-11-06 |
| [PyInstaller 木马双载荷分析：诱饵 PDF + Dropbox 标题死信箱密钥 + DWService 静默安装](defense-forensics-pyinstaller-dropbox-dead-drop-dwservice.md) | verified | medium | 2026-11-06 |
| [Python 信息窃取脚本：win32crypt/AES 解 Chrome/Edge Cookie 与密码，ipinfo 国家围栏后经 ngrok 中转外联](defense-forensics-python-stealer-browser-credentials-geofence-ngrok.md) | verified | medium | 2026-11-09 |
| [Python 木马配置字符串：反转 + Base64 + URL 编码还原 C2、暂存目录与监视关键字](defense-forensics-python-malware-reversed-base64-url-config.md) | verified | high | 2026-11-06 |
| [QEMU socket 隧道流量取证：4 字节长度前缀 + 以太网帧，editcap 去 58 字节还原内层 PCAP](defense-forensics-qemu-socket-tunnel-pcap-extract.md) | verified | high | 2026-11-11 |
| [Quasar RAT 解密载荷的无 schema protobuf 解码：From Hex + Protobuf Decode 还原进程与连接消息](defense-forensics-quasar-protobuf-tls-payload-decode.md) | verified | medium | 2026-11-11 |
| [RDP 流量解密与输入还原：导出 .pfx 私钥解 TLS，提取 fastpath scancode 还原键盘输入](defense-forensics-rdp-pfx-tls-decrypt-scancode-replay.md) | verified | high | 2026-11-06 |
| [RDP 登录来源显示为路由器网关：DNAT 叠加 SNAT 掩盖真实来源](defense-forensics-rdp-source-gateway-snat.md) | verified | medium | 2026-11-04 |
| [RedLine Stealer 信息窃取面：浏览器 Login Data/Autofill、Telegram tdata、Discord leveldb、Steam/钱包、FileZilla、VPN DPAPI 与 ip.sb 地理围栏](defense-forensics-redline-stealer-collection-geofence.md) | verified | medium | 2026-11-08 |
| [RSA 私钥销毁后的内存残留：符号化污点跟踪 CryptDestroyKey/CryptReleaseContext 定位用户态/内核态密钥副本](defense-forensics-rsa-key-lifecycle-residue-taint-analysis.md) | verified | low | 2026-11-10 |
| [SChannel 套件顺序降级强制 RSA 密钥交换：用 p12 私钥解密原本 ECDHE 的 TLS 1.2 流量](defense-forensics-schannel-cipher-order-downgrade-rsa-tls-decrypt.md) | verified | high | 2026-11-11 |
| [Security.evtx 账户持久化取证：4720/4726/4727/4728 事件还原攻击者建组建用户加域管的操作序列，再以 ntds.dit+SYSTEM 离线提 hash 用 john 爆破出新用户明文密码](defense-forensics-security-evtx-account-persistence-4720-4727-4728-audit.md) | verified | high | 2026-11-08 |
| [SM4 C2 流量解密：4 字节种子经 PRNG 派生密钥字后还原加密命令](defense-forensics-sm4-c2-traffic-seed-prng-key-decrypt.md) | verified | high | 2026-11-06 |
| [SMB3 加密流量解密：NTLM Hash + NTProofStr + Encrypted Session Key 推导 Random Session Key](defense-forensics-smb3-session-key-wireshark-decrypt.md) | verified | high | 2026-11-06 |
| [Snake Keylogger 窃密面与三条外传通道：浏览器 Login Data、Outlook/Foxmail、Discord token，FTP/SMTP/Telegram 回传](defense-forensics-snake-keylogger-stealer-collection-exfil-channels.md) | verified | high | 2026-11-08 |
| [SSH 日志取证：sshd.log + bash_history 关联还原攻击者登录与命令会话](defense-forensics-sshd-log-bash-history-session-reconstruction.md) | verified | high | 2026-11-07 |
| [Suo5 HTTP 隧道流量识别：/connect 分块 POST、UA 口令与内存马注入特征](defense-forensics-suo5-http-tunnel-traffic-identify.md) | verified | medium | 2026-11-07 |
| [Synaptics/Synares 类文件感染病毒的主机取证：落盘、Run 键、缓存副本与版本伪装](defense-forensics-synaptics-file-infector-artifacts.md) | verified | medium | 2026-11-05 |
| [TinyShell 后门流量解密：40 字节 IV 握手 + SHA1(secret||IV) 派生 AES-128-CBC 会话密钥与 HMAC-SHA1 尾](defense-forensics-tinyshell-backdoor-traffic-decrypt.md) | verified | high | 2026-11-09 |
| [ValleyRAT C2 流量解密：6666/0x36 线索与载荷前缀多字节 XOR 密钥还原主机信息与登录模块插件](defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt.md) | verified | medium | 2026-11-06 |
| [VBA Stomping 识别：olevba 发现 VBA 源码与 p-code 不一致，静态审计不能只看源码](defense-forensics-vba-stomping-source-pcode-mismatch.md) | verified | medium | 2026-11-06 |
| [Ventoy 日志取证：从 log.txt 恢复删除分区大小与启动介质制作完成时间](defense-forensics-ventoy-log-partition-history.md) | verified | high | 2026-11-06 |
| [VeraCrypt 加密分区取证：从手机笔记数据库关联恢复挂载密钥](defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence.md) | verified | high | 2026-11-06 |
| [Vidar Stealer 窃密面：14 款 Chromium Local State、17+ 钱包目录、Thunderbird、WinSCP/FileZilla、跳转列表、$Recycle.Bin、NTFS $Secure 与 SOFTWARE hive，ProgramData 暂存自锁后删除](defense-forensics-vidar-stealer-collection-surface-programdata-selfclean.md) | verified | medium | 2026-11-08 |
| [Volatility2 Linux Profile 制作：按目标内核编译 module.dwarf、配对 System.map 打包 zip 放入 overlays，并规避 dwarfdump 弃用与版本兼容坑](defense-forensics-volatility2-linux-profile-build-module-dwarf-systemmap.md) | verified | medium | 2026-11-09 |
| [Volatility2 mimikatz 插件从内存镜像提取 wdigest 账户凭据](defense-forensics-volatility2-mimikatz-wdigest-credential.md) | verified | high | 2026-11-08 |
| [Volatility2 usbstor 插件从内存镜像恢复 USB 存储设备接入历史：序列号、厂商型号与最后连接时间](defense-forensics-volatility2-usbstor-usb-device-history.md) | verified | high | 2026-11-13 |
| [Volatility2 userassist 插件从内存镜像恢复程序执行记录：运行次数、聚焦时长与最后更新时间](defense-forensics-volatility2-userassist-execution-history.md) | verified | high | 2026-11-13 |
| [Volatility2 Windows 内存四查：cmdline 识破 Temp 伪装 svchost、printkey 取主机名、hashdump 取 NTLM、netscan 定位外联](defense-forensics-volatility2-cmdline-hashdump-netscan-triage.md) | verified | high | 2026-11-07 |
| [Volatility2 解析 Linux 内存镜像：raw 转储报 No suitable address space mapping，LiME 分段头格式可正常建立地址空间](defense-forensics-volatility2-linux-raw-vs-lime-address-space.md) | verified | medium | 2026-11-09 |
| [Volatility3 Linux 符号表制作：发行版 dbg 包解出 System.map+vmlinux，dwarf2json 生成 ISF JSON 放入 symbols/linux](defense-forensics-volatility3-linux-isf-symbol-build-dwarf2json-dbg.md) | verified | medium | 2026-11-11 |
| [Volatility3 二次转储：导出进程内存、地址映射、DLL、缓存文件与注入段](defense-forensics-volatility3-secondary-dump-process-memmap-dll-dumpfiles.md) | verified | medium | 2026-11-09 |
| [VShell C2 配置提取与流量解密：0x5000 AES-CBC 配置块、md5(salt) 派生的 AES-GCM 帧](defense-forensics-vshell-config-aes-cbc-traffic-aes-gcm-decrypt.md) | verified | high | 2026-11-06 |
| [Web 访问日志溯源：按 IP 频次、敏感路径与 2xx 状态定位入侵者](defense-forensics-web-access-log-attacker-ip-triage.md) | verified | medium | 2026-11-07 |
| [Windows SID 取证关联：用计算机 SID 前缀与 RID 把 4624/4726/4688 串成横向移动与账户清理时间线](defense-forensics-windows-sid-correlation-timeline.md) | verified | medium | 2026-11-06 |
| [Windows 主机入侵取证：Security.evtx 4624/4688 + PSReadLine + TeamViewer/known_hosts 还原 wmiexec 横向与持久化链](defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction.md) | verified | high | 2026-11-07 |
| [Winos4 C2 通信解密：4 字节长度 + 10 字节密钥 + 1 字节指令 + (key+0x36) 滚动 XOR](defense-forensics-winos4-c2-frame-xor-decrypt.md) | verified | high | 2026-11-06 |
| [Winos4 插件注册表驻留与提取：HKCU\Console\0|1\<MD5> 三段式二进制载荷](defense-forensics-winos4-plugin-registry-residency-extraction.md) | verified | high | 2026-11-06 |
| [WinRM 流量解密与命令还原：明文口令解 NTLM 会话，提取 SOAP stdout Base64](defense-forensics-winrm-ntlm-traffic-decrypt-soap-command.md) | verified | medium | 2026-11-06 |
| [Wireshark 从 HTTP 分段响应重组导出 JPEG：FF D8/FF D9 截取 + binascii 还原图片](defense-forensics-http-segmented-response-jpeg-carve.md) | verified | high | 2026-11-12 |
| [Xeno-RAT 通信协议与批量解密：4+1 字节帧、AES-CBC（零 IV、key=SHA256 密码）、LZNT1 压缩与插件 DLL 还原](defense-forensics-xeno-rat-aes-cbc-lznt1-traffic-batch-decrypt.md) | verified | high | 2026-11-09 |
| [Xeno-RAT 配置提取与通信密钥推导：dnSpy 定位 C# 静态字段，EncryptionKey=SHA256(密码)，服务端 Config.json 明文对照](defense-forensics-xeno-rat-client-config-encryption-key-sha256.md) | verified | high | 2026-11-09 |
| [XMRig 配置提取与 Monero 支付 ID 追踪：矿池 worker/支付记录到区块链交易与收益归因](defense-forensics-xmrig-monero-payment-id-pool-tracking.md) | verified | high | 2026-11-08 |
| [xRAT 通信数据解密：长度前缀帧 + MD5(Password) 派生 AES key + 前 16 字节 IV + QuickLZ 解压](defense-forensics-xrat-traffic-aes-cbc-quicklz-decrypt.md) | verified | medium | 2026-11-11 |
| [中文勒索软件加密方案取证：RSA 封装随机口令 + 按 50MB 分流 AES-CFB/CBC（固定盐 11223344），密钥日志 libadvpack.dll 与 ._locked 结构](defense-forensics-chinese-ransomware-rsa-wrapped-aes-cfb-cbc-dual-branch.md) | verified | medium | 2026-11-11 |
| [事件日志被批量清除后的多源时间线重建](defense-forensics-multisource-timeline-log-clear.md) | verified | medium | 2026-11-04 |
| [从 Microsoft-Windows-Windows Defender%4Operational.evtx 的 1116/1117 事件还原被查杀木马的文件名与绝对路径](defense-forensics-defender-operational-evtx-1116-1117-malware-path.md) | verified | high | 2026-11-08 |
| [从 ssh/sshd 进程内存提取 sshenc 会话密钥并解密 SSH pcap 会话](defense-forensics-openssh-session-key-memory-sshenc-pcap-decrypt.md) | verified | high | 2026-11-07 |
| [从应用异常堆栈识别 Java 原生反序列化 JNDI 链](defense-forensics-java-native-deser-jndi-log-triage.md) | verified | high | 2026-11-04 |
| [伪装 v2ray 的恶意程序：RC4 解密同目录载荷提取 DLL 并还原文件加密链](defense-forensics-fake-v2ray-embedded-rc4-dll-extract.md) | verified | high | 2026-11-06 |
| [伪造邮件 .eml 的头部溯源与硬信号判定](defense-forensics-email-header-spoof-detection.md) | verified | high | 2026-11-04 |
| [内存镜像按外联 IP 定位注入进程：Volatility3 netscan → malfind dump → IDA 还原](defense-forensics-memory-netscan-malfind-dump-injected-process.md) | verified | high | 2026-11-06 |
| [冰蝎 JSP WebShell 静态取证：按约 2.6KB 体积定位并从 xc/pass 提取 AES key 与连接密码](defense-forensics-behinder-jsp-static-key-password-extraction.md) | verified | high | 2026-11-06 |
| [冰蝎 JSP 内存马流量解密：密码 MD5 前 16 位派生 AES key，还原命令与分块上传文件](defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt.md) | verified | high | 2026-11-06 |
| [冰蝎 PHP WebShell 流量解密：从马文件取 AES key，Base64+AES-CBC 还原命令与响应](defense-forensics-behinder-php-webshell-traffic-decrypt.md) | verified | high | 2026-11-06 |
| [冰蝎 PHP 默认密钥 e45e329feb5d925b：AES-128-ECB 魔数截断解密与 gzip/Base64 多层响应还原](defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode.md) | verified | high | 2026-11-07 |
| [冰蝎4.0 PHP 会话与命令执行流量：连接/信息包结构、cmd/path 的 Base64 与六函数回退链](defense-forensics-behinder40-php-session-command-payload.md) | verified | high | 2026-11-10 |
| [冰蝎4.0 PHP 文件操作流量：目录列表字段级 Base64、读文件双层 Base64 与下载双包反序 JSON](defense-forensics-behinder40-php-file-operation-response-parse.md) | verified | high | 2026-11-10 |
| [加密 WebShell 流量解密：从流量取马源码，本地搭建后把 eval 改为 printf，回放密文请求体直接得明文](defense-forensics-webshell-local-replay-eval-to-printf-traffic-decrypt.md) | verified | high | 2026-11-13 |
| [勒索事件中入口跳板机常最后加密：用加密时间反推入口](defense-forensics-ransomware-entry-host-encrypted-last.md) | verified | medium | 2026-11-04 |
| [哥斯拉 EKP 版 JSP 流量解密：双 Base64 请求与 JS 变量 Re<md5>_config 回显](defense-forensics-godzilla-ekp-jsp-traffic-decode.md) | verified | high | 2026-11-07 |
| [哥斯拉 Java WebShell 流量识别与解密（JAVA_AES_BASE64 / JAVA_AES_RAW）](defense-forensics-godzilla-java-webshell-traffic-decode.md) | verified | high | 2026-11-05 |
| [哥斯拉 PHP payload 内部参数分帧与模块调度：0x02 分隔 + 4 字节长度 + methodName/codeName/includeCode 插件入 SESSION](defense-forensics-godzilla-php-payload-param-framing-module-dispatch.md) | verified | medium | 2026-11-09 |
| [哥斯拉 PHP WebShell 流量识别与解密（PHP_EVAL_XOR_BASE64 / PHP_XOR_BASE64 / PHP_XOR_RAW）](defense-forensics-godzilla-php-webshell-traffic-decode.md) | verified | high | 2026-11-05 |
| [图片/公文截图真实性鉴别：MagicEXIF 多维 EXIF 一致性与 Class 1–5 评级、JPEGsnoop 换算，再用公文格式与检索核对](defense-forensics-image-authenticity-exif-class-public-document-check.md) | verified | medium | 2026-11-12 |
| [应用配置泄露 AES key/IV：离线解密数据库敏感字段（PbootCMS AES-128-CBC 实例）](defense-forensics-config-aes-key-iv-database-field-decrypt.md) | verified | high | 2026-11-07 |
| [微信 4.x WCDB 数据库离线解密：AES-256-CBC + PBKDF2-HMAC-SHA512 256000 次，4096 页/80 reserve 并修复 SQLite 头](defense-forensics-wcdb4-sqlcipher-offline-decrypt.md) | verified | high | 2026-11-06 |
| [微信 4.x 内存镜像密钥提取：Volatility3 转储 Weixin.exe，按 x'<64hex enc_key><32hex salt>' 扫描并用 salt 匹配数据库头](defense-forensics-wechat4-memory-image-key-extraction.md) | verified | high | 2026-11-06 |
| [恶意 Chrome 扩展遥测取证：Simple Allow Copy 0.8.8 用持久 UUID 关联 tabs 监听并上报全量 URL/浏览器指纹](defense-forensics-chrome-extension-url-telemetry-exfiltration.md) | verified | high | 2026-11-08 |
| [按 60+ 加密钱包扩展 ID 定位 Chromium 扩展存储：读 Local Extension Settings/IndexedDB 并配合 ETH、TRON 钱包文件完成盗币](defense-forensics-wallet-extension-id-local-extension-settings-collection.md) | verified | medium | 2026-11-09 |
| [无 beacon_keys 时从进程内存提取 CobaltStrike 4.x Beacon 会话密钥：sha256 结构定位与 16 字节候选碰撞](defense-forensics-cobaltstrike-memory-beacon-session-key-collision.md) | verified | high | 2026-11-07 |
| [无中间件访问日志时用应用服务调用日志还原 Java 入侵](defense-forensics-app-service-call-log-timeline.md) | verified | medium | 2026-11-04 |
| [无密钥场景下哥斯拉 PHP_XOR_BASE64 密钥反推：用响应 16 个十六进制字符 md5 框架作 oracle 爆破原始口令再取 md5 前 16 位](defense-forensics-godzilla-php-xor-key-md5-bruteforce.md) | verified | high | 2026-11-08 |
| [无访问日志时用 Java 异常堆栈重建 Web 入侵时间线](defense-forensics-java-exception-timeline-reconstruction.md) | verified | medium | 2026-11-04 |
| [照片 EXIF 伪造与校验器绕过：改 GPS/拍摄时间后用“图片重构”套用他机型号数据把可信度从 Class 1 刷到 Class 5](defense-forensics-exif-photo-forgery-reconstruct-verifier-bypass.md) | verified | high | 2026-11-12 |
| [用 S3 数据事件与 CloudTrail 追踪外泄角色、AssumeRole 与横向主机](defense-forensics-cloudtrail-s3-exfil-identity-trace.md) | verified | high | 2026-11-05 |
| [用回车符 \r 覆写终端同一行，伪造下载地址、校验结果与进程名](defense-forensics-carriage-return-output-overwrite.md) | verified | high | 2026-11-05 |
| [电子证据文件审查：百纳秒级时间戳与关联痕迹交叉验证文档来源与篡改](defense-forensics-electronic-evidence-file-timestamp-associated-artifacts-review.md) | verified | medium | 2026-11-08 |
| [窗口标题查询序列 ESC[21t 把注入内容回灌 stdin 导致终端命令执行](defense-forensics-terminal-title-query-stdin-rce.md) | verified | medium | 2026-11-05 |
| [红星OS 文件尾数字水印：24 字节加密磁盘序列号 + 长度字段 + EOF，可叠加并可解密归因](defense-forensics-redstar-os-file-tail-watermark-disk-serial.md) | verified | medium | 2026-11-12 |
| [自定义 XOR+Base64+gzip PHP Webshell 流量解密：请求/响应标记与 Cookie 回显](defense-forensics-custom-xor-gzip-php-webshell-traffic.md) | verified | high | 2026-11-07 |
| [蓝队溯源：用 commit .patch 的 From 邮箱与公开账号关联定位提交者](defense-forensics-git-commit-patch-email-attribution.md) | verified | high | 2026-11-05 |
| [蚁剑/菜刀 ASPX 一句话木马流量：chopper 参数、substr(2) 前缀 Base64 与明文回显还原](defense-forensics-chopper-aspx-webshell-base64-traffic-decode.md) | verified | high | 2026-11-07 |
| [蚁剑（AntSword）默认/Base64/chr/RSA 编码器流量还原与检测特征：ini_set 模板、双字符前缀 base64 与响应分段标记](defense-forensics-antsword-encoder-traffic-decode-features.md) | verified | high | 2026-11-10 |
| [运行中浏览器 SQLite 被独占锁：句柄枚举 + DuplicateHandle + 文件映射复制](defense-forensics-locked-browser-sqlite-handle-duplication.md) | verified | high | 2026-11-05 |
| [进程环境取证：/proc/pid/environ 只是启动视图，getenv 才是当前状态](defense-forensics-proc-environ-startup-view-split.md) | verified | high | 2026-11-05 |
| [远控软件本地日志取证：按创建时间选日志、用角色特征标签从向日葵/ToDesk/TeamViewer 日志提取对端真实 IP 并判断主控/被控角色](defense-forensics-remote-control-log-peer-ip-role.md) | verified | high | 2026-11-12 |
| [通讯软件诱饵传播的 Python 信息窃取器：BAT/CMD 两阶段下载链、7 浏览器凭据与 Facebook Cookie、Telegram sendDocument 双通道外传](defense-forensics-python-infostealer-messaging-bat-telegram-browser.md) | verified | high | 2026-11-10 |
| [钓鱼邮件基础设施取证：开放目录下的 PHPMailer 发件页、品牌落地页与按 IP 保存的凭据日志](defense-forensics-phishing-infra-open-directory-phpmailer-credential-logs.md) | verified | medium | 2026-11-09 |
| [银狐/Winos4 主机痕迹采集：Network 分组备注、DirectInput 键盘记录、kernelquick Rootkit 与 Dwm 注入 shellcode](defense-forensics-silverfox-winos4-file-registry-artifact-dump.md) | verified | high | 2026-11-06 |
| [魔改冰蝎 PHP 马流量：Base64+RC4+key[i+1] 异或双层解密](defense-forensics-behinder-php-rc4-xor-modified-traffic.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
