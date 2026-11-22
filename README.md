# dsh-ssh-helper

给 AI 运维个人服务器用的 SSH 工具：常驻连接池、8 个工具、一道防止把机器搞报废的护栏。可以作为 **DSH 插件**，也可以作为标准 **stdio MCP server** 接入任何客户端。

- 每台主机一条常驻连接，断线自动重连；`cd` 和环境变量按调用方隔离。
- 只用 `~/.ssh/config` 里的密钥或 ssh-agent，不支持密码，不保存私钥。

## 安装

前置：Node.js ≥ 22，`~/.ssh/config` 里已配好主机。

**DSH 插件**

```bash
git clone https://github.com/bcdws/dsh-ssh-helper.git && cd dsh-ssh-helper
npm install
dsh plugin --profile <profile> add "link:$PWD"
```

`ssh_hosts` 的结果里出现 `[policy]` 即为已加载。

**MCP server**

```json
{
  "mcpServers": {
    "ssh": { "command": "npx", "args": ["-y", "github:bcdws/dsh-ssh-helper#stable"] }
  }
}
```

可选参数：`--config <file.json>`（`hosts`、`exclude`、`autoConnect` 等）、`--ssh-config <path>`、`--state <path>`、`--max-call-ms <n>`（见下）、`--no-control`、`--quiet`。

**客户端超时（`--max-call-ms`）**：有的客户端等一个工具调用最多几十秒（magpie 是 50 秒），超时就放弃并取消调用，agent 拿不到任何输出。把 `--max-call-ms` 设得比客户端超时少几秒即可。不传时按 `initialize` 里的客户端名决定：已知约 60 秒就放弃的客户端（Codex、Claude Desktop、Cursor）默认 50000，其他客户端默认 0（不启用）。显式传值（包括 0）总是优先：

```json
"args": ["-y", "github:bcdws/dsh-ssh-helper#stable", "--max-call-ms", "45000"]
```

用 `bash -lc` 启动时，参数写进那一整段命令里（`"cd ~ && exec npx -y github:bcdws/dsh-ssh-helper#stable --max-call-ms 45000"`），不要拆成 `args` 里单独的元素。

- 只管 `ssh_run`，从发起算起（含建连）。在上限内跑完的命令不受任何影响。
- 到点时先带着已有输出返回，结果标 `detached: true`。命令**不会被杀**，继续跑到它自己的截止时间（预计时长 × 3，最长 30 分钟）。
- 命令结束后，`ssh_hosts` 的 `lastCommand` 会带上 `[finished after cap: exit 0, 60s]` 这样的结尾；失败、超时或断线另记 `lastFailure`。agent 应该去查结果，而不是重跑。
- 带 `session` 的命令被提前返回后，同一会话的下一条命令会立刻执行，但读到的仍是它之前的目录和变量，要等它跑完才会更新。
- 这只是兜底：已知会跑很久的任务（构建、升级、备份）直接用 `background: true`，立刻返回并写日志。
- DSH 插件没有客户端超时的问题，不需要设。

另外两条与超时有关的行为：到了截止时间或被客户端取消的命令，插件会连同它起的子进程一起杀掉，约 2 秒内返回；请求带了 `progressToken` 的长调用，每 10 秒会收到一次进度通知，附带命令最新的一行输出（已脱敏，最长 160 字符），支持的客户端会据此重新计时（magpie 不会）。

主机和密钥在 WSL 里、客户端在 Windows 上时，让 server 在 WSL 里跑：

```json
{ "command": "wsl.exe", "args": ["-d", "<distro>", "--", "bash", "-lc", "cd ~ && exec npx -y github:bcdws/dsh-ssh-helper#stable"] }
```

`-l` 加载 PATH（nvm/mise 等），`cd ~` 让 `localPath` 的相对路径落在 WSL 里，`exec` 让客户端能直接结束 node 进程。

**更新**：推到 `main` 且 CI 全绿后 `stable` 自动前进，下次启动 server 即生效。要固定版本，把 `#stable` 换成 tag（如 `#v0.6.0`）。

**启动速度**：server 本身启动不到 0.1 秒，慢在 npx。`github:` 写法每次启动都要先查询 GitHub，实测约 3.5 秒，`stable` 刚更新后约 9 秒，网络或代理慢时更久；换成 tag 或加 `--offline` 也省不掉这一步。想秒开就装一次，用装好的命令启动，代价是不再自动更新：

```bash
npm install -g github:bcdws/dsh-ssh-helper#stable   # 以后更新也是这条
```

配置里的 `command` 改成 `dsh-ssh-mcp`（客户端找不到时写 `$(npm prefix -g)/bin/dsh-ssh-mcp` 的完整路径），`args` 只留可选参数。

## 管理面板

```bash
npx -y github:bcdws/dsh-ssh-helper#stable panel --open
```

打开 `http://127.0.0.1:7318/`（端口被占用时顺延）。界面和 DSH 侧边栏的面板是同一个。可以：

- 隐藏主机、打生产标记、写备注、设置单台主机的空闲超时；
- 调整全局设置（输出上限、超时、日志旁路分析、地址打码）；
- 重命名 Host 和密钥文件（修改前会备份 `~/.ssh/config`）；
- 查看每个运行中的 MCP 进程及其连接，并手动连接或断开。

注意：

- 设置存在 `~/.dsh-ssh-mcp/state.json`，只有面板写它，MCP 进程只读跟随，约 1 秒生效。隐藏主机后 agent 立即无法访问，现有连接 20 秒后断开。
- Windows 和 WSL 各有一套 `~/.ssh/config`、状态文件和面板，互不相通。
- DSH 和 MCP 的状态也是分开的。想让 MCP 跟随 DSH，加 `--state ~/.dsh/ssh-pool/state.json`。
- 已装插件的 DSH agent 不要再接 MCP，否则工具会重复。

## 工具

| 工具 | 用途 |
|---|---|
| `ssh_hosts` | 列主机、连接状态、最近失败、server 所在机器（`local`） |
| `ssh_run` | 执行命令；`session` 保持目录和变量，`background` 后台运行 |
| `ssh_read` / `ssh_grep` / `ssh_glob` | 读文件、搜内容、找文件 |
| `ssh_write` / `ssh_edit` | 写新文件 / 精确修改 |
| `ssh_transfer` | 上传或下载单个文件（`localPath` 按 server 所在机器解析） |

- **后台模式留下的文件**：`background: true` 会在服务器上留两个文件，结果里都会返回路径：日志（`logPath`）和隐藏脚本 `.dsh-ssh-run-<hash>.sh`（`scriptPath`，存放命令正文，权限 700）。脚本总在插件的日志目录 `~/.local/state/dsh-ssh/logs/`（可用 `DSH_SSH_LOG_DIR` 改），即使用 `logPath` 把日志放到了别处。插件不会删除这两个文件。
- **生产标记和备注**：只提醒、不拦截。对生产主机做修改类调用时，结果会带 `[PROD]` 提醒；有备注的主机，每次调用结果都会带 `[note]`。MCP 下两者也会放进结构化结果的 `notices` 字段。
- **MCP 结构化结果**：`structuredContent` 不放没有信息量的字段：值为 null 或 false 的字段、为 0 的主机计数，以及 `ssh_run` 的握手耗时、连接复用标记和截止时间推算（命令超时时保留推算）。`outputSchema` 的 `required` 相应放宽，文本内容不变。
- **MCP 下的 `[policy]`**：`initialize` 的说明里一直有完整规则；`ssh_hosts` 只在第一次调用和命令被拒之后给出全文，其他时候只留一行 `[policy] unchanged…`。DSH 插件每次都给全文。
- **错误码**：失败时末尾附 `[error: <code>] 下一步建议`，MCP 下也放在 `_meta["dsh-ssh-helper/error"]`。错误码有：`connect_timeout`、`connection_refused`、`closed_before_handshake`、`host_unreachable`、`auth_failed`、`key_unusable`、`host_key_mismatch`、`transport_lost`、`exec_timeout`、`cancelled`、`policy_denied`、`unknown_host`、`local_path`、`invalid_argument`。失败会记到主机的 `lastFailure`。

## 安全边界

**这不是沙箱。** 护栏只拦 6 类致命操作：递归删除系统目录、`mkfs` / 分区、`dd` 写块设备、覆盖设备或系统关键文件、递归改系统目录权限、`cd` 进系统目录后批量删除。业务目录（`/srv`、`/home`、`/opt`、`/var/www`、`/data`）不拦。

- 被拒时说明意图交给人决定，不要换等价写法重试。误报按 bug 处理。
- MCP 下的审批由客户端负责；计划模式拦截只在 DSH 里有。
- 真正的保障在插件之外：用非 root 账号加 sudo 白名单，重要数据做备份。
- 日志旁路分析默认关闭。开启后日志先脱敏再交给模型；客户端不支持 `sampling` 时，改为返回本地规则摘要，不调用模型。

## 开发

```bash
node test/run.mjs --offline   # 离线测试
node test/run.mjs             # 含 live 测试，会连接真实主机
```

代码结构和改动规则见 [AGENTS.md](AGENTS.md)。推 `v*` tag 会生成带 tarball 的 release。

## License

MIT
