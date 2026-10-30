# dsh-ssh-helper

**DSH 插件**：给个人服务器运维用的 SSH 连接池与 AI 工具集。

> 标签：`dsh-plugin` · `dsh` · `ssh` · `server-ops`

## 解决什么问题

使用 AI 维护服务器时，常见痛点是：

- 每条命令重新握手，慢且打断排查节奏；
- AI 一次读整段日志，主会话上下文很快被淹没；
- 让 AI 装软件、改配置时，怕它执行 `rm -rf /etc`、`mkfs`、写块设备这类让机器报废的操作；
- 不同会话之间 shell 状态互相污染。

这个插件把连接、文件和日志操作收进一个常驻 SSH 池，同时保留**最大日常权限**：只拦会让整台机器报废的命令，不拦业务目录和普通维护。

## 主要能力

- **连接复用**：每台主机一个 SSH 连接，后续命令不再重复握手；断线自动重连，退避间隔 1s → 2s → 4s → …（上限 5 分钟）。
- **掉线不空转**：连续 6 次握手超时后暂停后台重连，面板显示“已暂停”；点“重试”或发起一次主动 SSH 调用即可恢复。
- **文件操作不悬挂**：SFTP 建链最多等 15 秒，超时会明确报错并记录，不再卡住会话。
- **9 个工具**：列主机、执行命令、健康检查、读写/编辑文件、按名查找、内容搜索、文件传输。
- **单档安全护栏**：只拒绝系统树递归删除、`mkfs`/分区、写块设备、覆写系统文件、递归改系统目录权限；业务目录和日常运维不拦。
- **日志旁路分析**：可选开关；大日志交给一个**没有工具**的旁路模型总结，主会话只收摘要，不塞全文。
- **会话隔离**：shell 会话按 agent + session 名隔离；连接共享，但 `cd`/环境变量不会串。
- **面板与诊断**：连接状态、隐藏主机、输出上限、旁路开关；`/ssh-pool/state` 保留最近 50 条脱敏诊断事件。
- **key-only**：使用本机 SSH key / agent，不支持密码登录，不存私钥。

## 安装

前置：已安装 DSH、Node.js、Git，并能在 `~/.ssh/config` 中看到目标主机。

```bash
git clone https://github.com/bcdws/dsh-ssh-helper.git
cd dsh-ssh-helper
npm install
dsh plugin --profile <profile> add "link:$PWD"
```

PowerShell 最后一行改为：

```powershell
dsh plugin --profile <profile> add "link:$((Get-Location).Path)"
```

如果 `dsh` 不在 PATH，请使用 DSH 自带的 CLI 路径，不要猜。装好后确认：

```bash
dsh plugin --profile <profile> list
```

`ssh_hosts` 的返回值里会出现 `[policy]` 提示，说明插件已加载。

## 让 AI 自己安装

把下面整段发给 DSH 里的 AI：

```text
请把 DSH 插件 dsh-ssh-helper 安装到当前 profile。
仓库：https://github.com/bcdws/dsh-ssh-helper

步骤：
1. git clone 到一个临时目录；
2. 在仓库目录执行 npm install；
3. 执行 dsh plugin --profile <profile> add "link:<仓库绝对路径>"；
4. 用 dsh plugin --profile <profile> list 验证；
5. 只报告安装结果和 profile 路径。

约束：
- 不修改我的 ~/.ssh/config，不添加主机；
- 不连接任何服务器，不执行远程命令；
- 如果 dsh 不在 PATH 或 profile 不明确，先问我，不要猜。
```

## 使用

先在 `~/.ssh/config` 配好主机和 IdentityFile，然后直接用自然语言对 AI 说，不需要点名工具：

```text
帮我看看有哪些服务器
查一下 server-a 最近 10 分钟的日志
检查一下 server-a 的健康状态
帮我在 server-b 上安装这个本地 deb 包
```

AI 会根据场景自动选择工具；下面的清单只是便于你了解它能做什么。

常用工具：

| 工具 | 用途 |
|---|---|
| `ssh_hosts` | 列主机、连接状态、最后错误 |
| `ssh_run` | 执行命令；支持持久 session |
| `ssh_check` | 固定只读健康检查 |
| `ssh_read` / `ssh_grep` | 读文件、搜内容 |
| `ssh_write` / `ssh_edit` | 写新文件 / 精确改现有文件 |
| `ssh_glob` | 按文件名/路径找文件 |
| `ssh_transfer` | 上传/下载单个文件 |

主机可以在面板里设为「隐藏」：隐藏后 AI 看不到也连不上，面板仍可管理。

## 安全边界

这不是沙箱，而是**防手滑的安全带**：

- 只拦 6 类会让整台机器报废的操作；
- 业务目录（`/srv`、`/home`、`/opt`、`/var/www`、`/data`）的删除和普通维护不拦；
- 命令护栏匹配 shell 文本，脚本内部、文件工具写 `/etc` 等路径不在同一层判断；
- 真正的隔离仍应使用受限账号、备份和最小权限。

日志旁路分析默认关闭；开启后日志会先脱敏，再发送到你配置的默认模型提供商。敏感日志请保持关闭。

## 开发与测试

```bash
npm install
node test/run.mjs --offline   # 离线套件，不需要服务器
node test/run.mjs             # 离线 + 可选 live smoke
```

## License

MIT
