# dsh-ssh-helper

给 AI 运维个人服务器用的 SSH 连接池、8 个工具和一道防止误删系统的护栏。同一套核心有两种接入方式：**DSH 插件**，或 **MCP server**（通过 Magpie 等网关给任意 agent 使用）。

- **连接复用**：每台主机一个常驻 SSH 连接，断线自动重连，命令不再重复握手。
- **会话隔离**：`cd` 和环境变量按调用方隔离，连接共享。
- **安全护栏**：只拦会让整台机器报废的 6 类操作，其余放行。
- **key-only**：使用 `~/.ssh/config` 里的密钥或 ssh-agent，不支持密码，也不存私钥。

```
lib/              共享核心：连接池、策略、工具
index.js  dsh/    DSH 适配层（插件注册、面板、计划模式拦截）
mcp/      bin/    MCP 适配层（stdio server）
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

### 方式二：MCP（Magpie 等任意 MCP 客户端）

不需要 clone。在 Magpie 的 MCP 库里添加服务时粘贴下面这段 JSON，然后勾选需要的 agent；Windows 还是 WSL 由 Magpie 自己处理。Claude Code、Codex、Cursor 等客户端也用同一段配置。

```json
{
  "mcpServers": {
    "ssh": {
      "command": "npx",
      "args": ["-y", "github:bcdws/dsh-ssh-helper"]
    }
  }
}
```

需要时可以在 `args` 末尾追加参数：`--config <file.json>`（与插件 config 同名的键，如 `hosts`、`exclude`）、`--ssh-config <path>`、`--state <path>`、`--quiet`。

两种方式互不影响：

- 各有各的连接池；MCP 默认不读 DSH 面板状态，需要跟随时加 `--state ~/.dsh/ssh-pool/state.json`（只读）。
- 已经装了插件的 DSH agent 不要再勾选这个 MCP，否则工具会重复。

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

## License

MIT
