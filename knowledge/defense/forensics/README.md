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
| [AdaptixC2 BeaconHTTP 流量解密：DB 取 Listener EncryptKey、RC4 解心跳提 SessionKey 再还原命令与回显](defense-forensics-adaptixc2-beacon-http-rc4-session-key-traffic-decrypt.md) | verified | high | 2026-11-07 |
| [AdaptixC2 Gopher TCP 配置提取与流量解密：Listener Key、INIT_PACK 会话密钥与多层 msgpack 帧](defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt.md) | verified | high | 2026-11-07 |
| [AdaptixC2 HTTP Beacon 配置提取与 RC4 解密：4 字节长度 + 加密 Profile + 16 字节 Key](defense-forensics-adaptixc2-http-beacon-profile-rc4-extract.md) | verified | high | 2026-11-07 |
| [ANSI 转义序列注入日志：清屏与隐藏文本篡改终端显示](defense-forensics-ansi-escape-log-poisoning.md) | verified | high | 2026-11-05 |
| [C2 服务端目录取证：SQLite clients/listeners/tunnels 与 setting.conf 还原基础设施](defense-forensics-c2-server-sqlite-conf-artifacts.md) | verified | high | 2026-11-06 |
| [Chromium 数据离线解析：密钥静态注入、前缀分派与七类数据还原](defense-forensics-chromium-artifact-offline-decrypt.md) | verified | high | 2026-11-05 |
| [Cobalt Strike C2 流量解密：beacon_keys 私钥解元数据得 Raw Key，再用 cs-parse-http-traffic 还原命令](defense-forensics-cobaltstrike-beacon-keys-metadata-rawkey-traffic-decrypt.md) | verified | high | 2026-11-07 |
| [Core dump 敏感信息提取：strings、字节搜索、ELF LOAD 映射与高熵扫描](defense-forensics-core-dump-secret-extraction.md) | verified | high | 2026-11-05 |
| [CryptoAPI AES-256 文件加密样本：SHA-256 派生密钥与 CryptSetKeyParam 取 IV 后离线解密](defense-forensics-cryptoapi-aes256-file-encrypt-key-iv-recovery.md) | verified | high | 2026-11-06 |
| [CVE-2026-34621 PDF 在野样本分层去混淆：PDF 十六进制转义、JSFuck、Base64、字符串数组与 AES-CTR/zlib 载荷](defense-forensics-cve-2026-34621-pdf-js-layered-deobfuscation.md) | verified | high | 2026-11-05 |
| [DanderSpritz 模块化后门通信协议：内置 RSA 公钥校验 + RSA 封装 AES 会话密钥 + 模块下发解密](defense-forensics-danderspritz-modular-backdoor-rsa-aes-protocol.md) | verified | high | 2026-11-06 |
| [ELF 构造器顺序取证：DT_NEEDED 顺序不等于实际初始化顺序](defense-forensics-elf-constructor-order-dt-needed.md) | verified | high | 2026-11-05 |
| [ELF 符号顶替的四路取证：dladdr、readelf、LD_DEBUG 与 objdump](defense-forensics-elf-symbol-interposition-triage.md) | verified | high | 2026-11-05 |
| [Flask SSTI 注入的 RC4 加密后门：从错误处理器 payload 提取密钥并解密 C2 流量](defense-forensics-flask-ssti-rc4-backdoor-traffic-decrypt.md) | verified | high | 2026-11-06 |
| [Go 挖矿样本内存取证：gdb dump 可读段并用 strings 提取 msgpack 上报字段](defense-forensics-go-miner-heap-msgpack-field-extraction.md) | verified | high | 2026-11-06 |
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
| [Merlin Agent 内存取 OPAQUE 会话密钥：64 位 hex 字符串扫描 + transformers 解密全协议流量](defense-forensics-merlin-agent-opaque-memory-secret-traffic-decrypt.md) | verified | high | 2026-11-07 |
| [MySQL binlog 行镜像恢复被删除订单：定位 Delete_rows 事件并解码 before-image](defense-forensics-mysql-binlog-delete-row-recovery.md) | verified | medium | 2026-11-06 |
| [MySQL 通用查询日志溯源：按 Access denied 聚合爆破源 IP 并定位首次成功登录时间](defense-forensics-mysql-general-log-bruteforce-source-success-time.md) | verified | high | 2026-11-07 |
| [NjRAT/Bladabindi C2 流量识别与解码：明文上线包、Base64 受害者信息、act/kl/pas 命令与 CAP JPEG 桌面帧](defense-forensics-njrat-c2-traffic-base64-decode.md) | verified | high | 2026-11-06 |
| [Obsidian 本地库取证：Mega 恢复密钥与 self-hosted LiveSync CouchDB 凭据恢复](defense-forensics-obsidian-livesync-config-credential-recovery.md) | verified | high | 2026-11-06 |
| [OSC 52 剪贴板读取：在受害者终端内窃取宿主机剪贴板内容](defense-forensics-terminal-osc52-clipboard-read.md) | verified | high | 2026-11-05 |
| [OverlayFS/挂载覆盖隐藏 /var/log 的识别与恢复](defense-forensics-overlayfs-mount-shadowing-log-hide.md) | verified | high | 2026-11-05 |
| [PyInstaller 勒索样本取证：解包提取内嵌 RSA 私钥，OAEP 解 AES key，ECB 解密 PDF](defense-forensics-pyinstaller-ransomware-embedded-rsa-aes-ecb-recovery.md) | verified | high | 2026-11-06 |
| [PyInstaller 木马 C2 流量解密：4 字节长度 + 12 字节 nonce + 密文 + 16 字节 GCM tag](defense-forensics-pyinstaller-aes-gcm-c2-frame-decrypt.md) | verified | high | 2026-11-06 |
| [PyInstaller 木马双载荷分析：诱饵 PDF + Dropbox 标题死信箱密钥 + DWService 静默安装](defense-forensics-pyinstaller-dropbox-dead-drop-dwservice.md) | verified | medium | 2026-11-06 |
| [Python 木马配置字符串：反转 + Base64 + URL 编码还原 C2、暂存目录与监视关键字](defense-forensics-python-malware-reversed-base64-url-config.md) | verified | high | 2026-11-06 |
| [RDP 流量解密与输入还原：导出 .pfx 私钥解 TLS，提取 fastpath scancode 还原键盘输入](defense-forensics-rdp-pfx-tls-decrypt-scancode-replay.md) | verified | high | 2026-11-06 |
| [RDP 登录来源显示为路由器网关：DNAT 叠加 SNAT 掩盖真实来源](defense-forensics-rdp-source-gateway-snat.md) | verified | medium | 2026-11-04 |
| [SM4 C2 流量解密：4 字节种子经 PRNG 派生密钥字后还原加密命令](defense-forensics-sm4-c2-traffic-seed-prng-key-decrypt.md) | verified | high | 2026-11-06 |
| [SMB3 加密流量解密：NTLM Hash + NTProofStr + Encrypted Session Key 推导 Random Session Key](defense-forensics-smb3-session-key-wireshark-decrypt.md) | verified | high | 2026-11-06 |
| [SSH 日志取证：sshd.log + bash_history 关联还原攻击者登录与命令会话](defense-forensics-sshd-log-bash-history-session-reconstruction.md) | verified | high | 2026-11-07 |
| [Suo5 HTTP 隧道流量识别：/connect 分块 POST、UA 口令与内存马注入特征](defense-forensics-suo5-http-tunnel-traffic-identify.md) | draft | medium | 2026-11-07 |
| [Synaptics/Synares 类文件感染病毒的主机取证：落盘、Run 键、缓存副本与版本伪装](defense-forensics-synaptics-file-infector-artifacts.md) | verified | medium | 2026-11-05 |
| [ValleyRAT C2 流量解密：6666/0x36 线索与载荷前缀多字节 XOR 密钥还原主机信息与登录模块插件](defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt.md) | verified | medium | 2026-11-06 |
| [VBA Stomping 识别：olevba 发现 VBA 源码与 p-code 不一致，静态审计不能只看源码](defense-forensics-vba-stomping-source-pcode-mismatch.md) | verified | medium | 2026-11-06 |
| [Ventoy 日志取证：从 log.txt 恢复删除分区大小与启动介质制作完成时间](defense-forensics-ventoy-log-partition-history.md) | verified | high | 2026-11-06 |
| [VeraCrypt 加密分区取证：从手机笔记数据库关联恢复挂载密钥](defense-forensics-veracrypt-key-from-mobile-notes-cross-evidence.md) | verified | high | 2026-11-06 |
| [Volatility2 Windows 内存四查：cmdline 识破 Temp 伪装 svchost、printkey 取主机名、hashdump 取 NTLM、netscan 定位外联](defense-forensics-volatility2-cmdline-hashdump-netscan-triage.md) | verified | high | 2026-11-07 |
| [VShell C2 配置提取与流量解密：0x5000 AES-CBC 配置块、md5(salt) 派生的 AES-GCM 帧](defense-forensics-vshell-config-aes-cbc-traffic-aes-gcm-decrypt.md) | verified | high | 2026-11-06 |
| [Web 访问日志溯源：按 IP 频次、敏感路径与 2xx 状态定位入侵者](defense-forensics-web-access-log-attacker-ip-triage.md) | verified | medium | 2026-11-07 |
| [Windows SID 取证关联：用计算机 SID 前缀与 RID 把 4624/4726/4688 串成横向移动与账户清理时间线](defense-forensics-windows-sid-correlation-timeline.md) | verified | medium | 2026-11-06 |
| [Windows 主机入侵取证：Security.evtx 4624/4688 + PSReadLine + TeamViewer/known_hosts 还原 wmiexec 横向与持久化链](defense-forensics-windows-evtx-psreadline-rmm-chain-reconstruction.md) | verified | high | 2026-11-07 |
| [Winos4 C2 通信解密：4 字节长度 + 10 字节密钥 + 1 字节指令 + (key+0x36) 滚动 XOR](defense-forensics-winos4-c2-frame-xor-decrypt.md) | verified | high | 2026-11-06 |
| [Winos4 插件注册表驻留与提取：HKCU\Console\0|1\<MD5> 三段式二进制载荷](defense-forensics-winos4-plugin-registry-residency-extraction.md) | verified | high | 2026-11-06 |
| [WinRM 流量解密与命令还原：明文口令解 NTLM 会话，提取 SOAP stdout Base64](defense-forensics-winrm-ntlm-traffic-decrypt-soap-command.md) | verified | medium | 2026-11-06 |
| [事件日志被批量清除后的多源时间线重建](defense-forensics-multisource-timeline-log-clear.md) | verified | medium | 2026-11-04 |
| [从 ssh/sshd 进程内存提取 sshenc 会话密钥并解密 SSH pcap 会话](defense-forensics-openssh-session-key-memory-sshenc-pcap-decrypt.md) | verified | high | 2026-11-07 |
| [从应用异常堆栈识别 Java 原生反序列化 JNDI 链](defense-forensics-java-native-deser-jndi-log-triage.md) | verified | high | 2026-11-04 |
| [伪装 v2ray 的恶意程序：RC4 解密同目录载荷提取 DLL 并还原文件加密链](defense-forensics-fake-v2ray-embedded-rc4-dll-extract.md) | verified | high | 2026-11-06 |
| [伪造邮件 .eml 的头部溯源与硬信号判定](defense-forensics-email-header-spoof-detection.md) | verified | high | 2026-11-04 |
| [内存镜像按外联 IP 定位注入进程：Volatility3 netscan → malfind dump → IDA 还原](defense-forensics-memory-netscan-malfind-dump-injected-process.md) | verified | high | 2026-11-06 |
| [冰蝎 JSP WebShell 静态取证：按约 2.6KB 体积定位并从 xc/pass 提取 AES key 与连接密码](defense-forensics-behinder-jsp-static-key-password-extraction.md) | verified | high | 2026-11-06 |
| [冰蝎 JSP 内存马流量解密：密码 MD5 前 16 位派生 AES key，还原命令与分块上传文件](defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt.md) | verified | high | 2026-11-06 |
| [冰蝎 PHP WebShell 流量解密：从马文件取 AES key，Base64+AES-CBC 还原命令与响应](defense-forensics-behinder-php-webshell-traffic-decrypt.md) | verified | high | 2026-11-06 |
| [冰蝎 PHP 默认密钥 e45e329feb5d925b：AES-128-ECB 魔数截断解密与 gzip/Base64 多层响应还原](defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode.md) | verified | high | 2026-11-07 |
| [勒索事件中入口跳板机常最后加密：用加密时间反推入口](defense-forensics-ransomware-entry-host-encrypted-last.md) | verified | medium | 2026-11-04 |
| [哥斯拉 EKP 版 JSP 流量解密：双 Base64 请求与 JS 变量 Re<md5>_config 回显](defense-forensics-godzilla-ekp-jsp-traffic-decode.md) | draft | high | 2026-11-07 |
| [哥斯拉 Java WebShell 流量识别与解密（JAVA_AES_BASE64 / JAVA_AES_RAW）](defense-forensics-godzilla-java-webshell-traffic-decode.md) | verified | high | 2026-11-05 |
| [哥斯拉 PHP WebShell 流量识别与解密（PHP_EVAL_XOR_BASE64 / PHP_XOR_BASE64 / PHP_XOR_RAW）](defense-forensics-godzilla-php-webshell-traffic-decode.md) | verified | high | 2026-11-05 |
| [应用配置泄露 AES key/IV：离线解密数据库敏感字段（PbootCMS AES-128-CBC 实例）](defense-forensics-config-aes-key-iv-database-field-decrypt.md) | verified | high | 2026-11-07 |
| [微信 4.x WCDB 数据库离线解密：AES-256-CBC + PBKDF2-HMAC-SHA512 256000 次，4096 页/80 reserve 并修复 SQLite 头](defense-forensics-wcdb4-sqlcipher-offline-decrypt.md) | verified | high | 2026-11-06 |
| [微信 4.x 内存镜像密钥提取：Volatility3 转储 Weixin.exe，按 x'<64hex enc_key><32hex salt>' 扫描并用 salt 匹配数据库头](defense-forensics-wechat4-memory-image-key-extraction.md) | verified | high | 2026-11-06 |
| [无 beacon_keys 时从进程内存提取 CobaltStrike 4.x Beacon 会话密钥：sha256 结构定位与 16 字节候选碰撞](defense-forensics-cobaltstrike-memory-beacon-session-key-collision.md) | draft | high | 2026-11-07 |
| [无中间件访问日志时用应用服务调用日志还原 Java 入侵](defense-forensics-app-service-call-log-timeline.md) | verified | medium | 2026-11-04 |
| [无访问日志时用 Java 异常堆栈重建 Web 入侵时间线](defense-forensics-java-exception-timeline-reconstruction.md) | verified | medium | 2026-11-04 |
| [用 S3 数据事件与 CloudTrail 追踪外泄角色、AssumeRole 与横向主机](defense-forensics-cloudtrail-s3-exfil-identity-trace.md) | verified | high | 2026-11-05 |
| [用回车符 \r 覆写终端同一行，伪造下载地址、校验结果与进程名](defense-forensics-carriage-return-output-overwrite.md) | verified | high | 2026-11-05 |
| [窗口标题查询序列 ESC[21t 把注入内容回灌 stdin 导致终端命令执行](defense-forensics-terminal-title-query-stdin-rce.md) | verified | medium | 2026-11-05 |
| [自定义 XOR+Base64+gzip PHP Webshell 流量解密：请求/响应标记与 Cookie 回显](defense-forensics-custom-xor-gzip-php-webshell-traffic.md) | verified | high | 2026-11-07 |
| [蓝队溯源：用 commit .patch 的 From 邮箱与公开账号关联定位提交者](defense-forensics-git-commit-patch-email-attribution.md) | verified | high | 2026-11-05 |
| [运行中浏览器 SQLite 被独占锁：句柄枚举 + DuplicateHandle + 文件映射复制](defense-forensics-locked-browser-sqlite-handle-duplication.md) | verified | high | 2026-11-05 |
| [进程环境取证：/proc/pid/environ 只是启动视图，getenv 才是当前状态](defense-forensics-proc-environ-startup-view-split.md) | verified | high | 2026-11-05 |
| [银狐/Winos4 主机痕迹采集：Network 分组备注、DirectInput 键盘记录、kernelquick Rootkit 与 Dwm 注入 shellcode](defense-forensics-silverfox-winos4-file-registry-artifact-dump.md) | verified | high | 2026-11-06 |
| [魔改冰蝎 PHP 马流量：Base64+RC4+key[i+1] 异或双层解密](defense-forensics-behinder-php-rc4-xor-modified-traffic.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
