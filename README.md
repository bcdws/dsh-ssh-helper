# dsh-ssh-helper

给 AI 运维个人服务器用的 SSH 连接池、8 个工具和一道防止误删系统的护栏。同一套核心有两种接入方式：**DSH 插件**，或标准的 **MCP server**（stdio，任何 MCP 客户端或网关都能接入）。

- **连接复用**：每台主机一个常驻 SSH 连接，断线自动重连，命令不再重复握手。
- **会话隔离**：`cd` 和环境变量按调用方隔离，连接共享。
- **安全护栏**：只拦会让整台机器报废的 6 类操作，其余放行。
- **key-only**：使用 `~/.ssh/config` 里的密钥或 ssh-agent，不支持密码，也不存私钥。

```
lib/              共享核心：连接池、策略、工具
index.js  dsh/    DSH 适配层（插件注册、面板、计划模式拦截）
mcp/      bin/    MCP 适配层（stdio server + 管理面板）
```

## 安装

前置：Node.js ≥ 18，`~/.ssh/config` 里已配好主机。

### 方式一：DSH 插件

```bash
git clone https://github.com/bcdws/dsh-ssh-helper.git
cd dsh-ssh-helper
npm install
dsh plugin --profile <profile> add "link:$PWD"
```

用 `dsh plugin --profile <profile> list` 确认已加载；`ssh_hosts` 的结果里出现 `[policy]` 也说明已加载。

### 方式二：MCP server

不需要 clone。把下面这段配置加到你的 MCP 客户端或网关里（Claude Code、Codex、Cursor 等都用同一段）：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "github:bcdws/dsh-ssh-helper#stable"]
    }
  }
}
```

需要时可以在 `args` 末尾追加参数：`--config <file.json>`（与插件 config 同名的键，如 `hosts`、`exclude`）、`--ssh-config <path>`、`--state <path>`、`--no-control`、`--quiet`。

#### 管理面板

```bash
npx -y github:bcdws/dsh-ssh-helper#stable panel --open
```

在 `http://127.0.0.1:7318/` 打开一个和 DSH 插件面板类似的页面（`--port` 可以换端口）：

- 主机的隐藏、备注、单独的空闲超时，以及输出上限、空闲超时、传输超时、日志旁路分析这几项全局设置；
- 重命名 Host 和密钥文件（会修改 `~/.ssh/config`，并先备份）；
- 本机所有正在运行的 MCP 进程（每个客户端会话一个）及其实时连接，可以手动连接或断开。

工作方式：

- 设置保存在 `~/.dsh-ssh-mcp/state.json`，**只有面板写这个文件**，每个 MCP 进程只读跟随，大约 1 秒内生效。隐藏一台主机后，各进程会断开到它的现有连接。
- 每个 MCP 进程启动后会在 `127.0.0.1` 的随机端口上开一个控制口，并把端口和令牌写进 `~/.dsh-ssh-mcp/run/<pid>.json`（权限 0600），面板通过这个文件找到它。不需要面板时可以加 `--no-control`。
- 面板和控制口都只接受本机请求，并且会校验 `Host` 头（防 DNS rebinding）；写操作还需要令牌。面板自己不会建立 SSH 连接。
- `DSH_SSH_MCP_HOME` 可以把上面这个目录换到别处。

**更新**：`stable` 分支只在 CI 全部通过后才前进；npx 每次启动都会重新解析它，所以新版本在下次启动 server 时自动生效，不用重装。想固定版本就把 `#stable` 换成 tag（如 `#v0.6.0`），想跟最新提交就去掉 `#stable`。

这个包运行时零依赖（ssh2 已预打包进 `vendor/`），npx 只解一个 tarball、不跑安装脚本，启动足够快，不会超出客户端等待 `initialize` 的时间。

两种方式互不影响：

- 各有各的连接池和状态文件：MCP 默认跟随自己的 `~/.dsh-ssh-mcp/state.json`，不读 DSH 面板的状态。如果想让它跟随 DSH，加 `--state ~/.dsh/ssh-pool/state.json`（只读）；这时 MCP 面板里的隐藏和设置对这个进程不生效，面板会标出来。
- 在 DSH 面板里隐藏主机，只影响 DSH 的连接池；在 MCP 面板里隐藏主机，只影响跟随 MCP 状态文件的进程。
- 已经装了插件的 DSH agent 不要再接这个 MCP，否则工具会重复。

## 工具

| 工具 | 用途 |
|---|---|
| `ssh_hosts` | 列主机、连接状态、最后错误 |
| `ssh_run` | 执行命令；`session` 保持目录和变量，`background` 后台运行 |
| `ssh_read` / `ssh_grep` / `ssh_glob` | 读文件、搜内容、找文件 |
| `ssh_write` / `ssh_edit` | 写新文件 / 精确修改现有文件 |
| `ssh_transfer` | 上传或下载单个文件 |

## 安全边界

**这不是沙箱。** 护栏只拦 6 类致命操作：递归删除系统目录、`mkfs` / 分区、`dd` 写块设备、覆盖设备或系统关键文件、递归改系统目录权限、`cd` 到系统目录后批量删除。业务目录（`/srv`、`/home`、`/opt`、`/var/www`、`/data`）不拦。两种方式都在工具内部执行这道检查。

- 被拒时应说明意图（哪台机器、做什么、预期影响），不要换一种等价写法重试。误报按 bug 处理。
- 计划模式拦截和本地 bash 拦截只在 DSH 里有。在 MCP 下，审批由客户端负责：工具带有只读 / 可能破坏的注解。
- 真正可靠的保障在插件之外：远程用非 root 账号加 sudo 白名单，重要数据做快照或异机备份。
- 日志旁路分析默认关闭。开启后日志先脱敏再发给模型（DSH 用默认模型，MCP 用客户端的 sampling）。

## 开发

```bash
node test/run.mjs --offline   # 离线测试，不需要服务器
node test/run.mjs             # 加上可选的 live 测试
```

推送到 `main` 后 CI 跑测试和打包冒烟，全绿则自动把 `stable` 快进到该提交；推 `v*` tag 会生成带 tarball 的 release。

## License

MIT
