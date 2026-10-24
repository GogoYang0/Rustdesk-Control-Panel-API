#!/usr/bin/env bash
# =============================================================================
# Step 5 — M3 会话治理真机回归（Linux + Docker 云端一键执行）
#
# 目标：真实 panel + 真实 rustdesk-server 容器 + 真实 docker logs 采集，
#       验证 v0.4.0 的 M3 会话治理链路（票据/策略/审批/告警/native 会话）。
#
# 用法：
#   chmod +x step5-m3-run.sh
#   PUBLIC_HOST=<云主机公网IP或域名> ./step5-m3-run.sh /root/step5m3-work
#   ./step5-m3-run.sh /root/step5m3-work --probe     # 额外跑 #36 碰撞率专项
#
# 前置：docker（docker ps 可用）、go 1.27+、curl、python3、bash
# 说明：脚本可重跑（复用同名组织与既有容器；panel 已在跑则跳过启动）。
# 产出：$WORKDIR/evidence/*（逐项证据）+ $WORKDIR/step5-m3-result.md（报告骨架）
# =============================================================================
set -euo pipefail
WORKDIR="${1:-$PWD/step5m3-work}"
RUN_PROBE="${2:-}"
REPO_URL="${REPO_URL:-https://github.com/GogoYang0/Rustdesk-Control-Panel-API.git}"
BRANCH="${BRANCH:-develop}"
RS_VERSION="${RS_VERSION:-1.1.16}"
API="${API:-http://127.0.0.1:8080}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
PASS=0; FAIL=0
ok(){ echo "✅ $1"; PASS=$((PASS+1)); }
bad(){ echo "❌ $1"; FAIL=$((FAIL+1)); }
section(){ echo; echo "===== $1 ====="; }

mkdir -p "$WORKDIR"
WORKDIR=$(cd "$WORKDIR" && pwd)   # absolute: paths below are used from other cwds
cd "$WORKDIR"
EV="$WORKDIR/evidence"; mkdir -p "$EV"
DB="$WORKDIR/panel-data/data/panel.db"

if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST=$(curl -s --noproxy '*' --max-time 5 https://api.ipify.org || true)
  [ -n "$PUBLIC_HOST" ] || { echo "需要 PUBLIC_HOST=<云主机公网IP/域名>（客户端要连的地址）"; exit 1; }
  echo "（未显式指定 PUBLIC_HOST，探测到 $PUBLIC_HOST）"
fi

section "0. 环境检查"
docker ps >/dev/null 2>&1 && ok "docker daemon" || { bad "docker daemon 不可用"; exit 1; }
go version >/dev/null 2>&1 && ok "go ($(go version))" || { bad "go 未安装（需要 1.27+，go.mod 指定）"; exit 1; }
curl --version >/dev/null 2>&1 && ok "curl" || { bad "curl 未安装"; exit 1; }
python3 --version >/dev/null 2>&1 && ok "python3" || { bad "python3 未安装（断言需要）"; exit 1; }

section "1. 构建 panel"
if [ ! -d repo ]; then
  git clone --depth 1 -b "$BRANCH" "$REPO_URL" repo
else
  git -C repo fetch --depth 1 origin "$BRANCH" && git -C repo checkout -q FETCH_HEAD
fi
if [ ! -d repo/tools/regression/m3harness ]; then
  bad "分支 $BRANCH 不含 tools/regression/*：请把 M3 回归工具合并到该分支后再跑（BRANCH=<含工具的分支>）"
  exit 1
fi
( cd repo && go build -o "$WORKDIR/panel" ./cmd/server )
ok "panel 构建完成（commit $(git -C repo rev-parse --short HEAD)）"

section "2. 启动 panel（真实配置，logcollect 已启用）"
mkdir -p panel-data/configs panel-data/data
if [ -f panel-data/panel.pid ] && kill -0 "$(cat panel-data/panel.pid)" 2>/dev/null; then
  ok "panel 已在运行（pid $(cat panel-data/panel.pid)），跳过启动"
else
  SECRET=$(head -c 48 /dev/urandom | base64 | tr -d '\n/+=' | cut -c1-64)
  cat > panel-data/configs/config.yaml <<EOF
server:
  addr: "127.0.0.1:8080"
auth:
  secret: "$SECRET"
  accessTTL: 15m
  refreshTTL: 168h
provision:
  portStart: 21116
  portEnd: 22115
  orgLabel: "com.rustdesk-panel.org"
  roleLabel: "com.rustdesk-panel.role"
  # Must be reachable by clients: the hbbs container hands this to peers.
  relayHost: "$PUBLIC_HOST"
  image: "rustdesk/rustdesk-server:$RS_VERSION"
  dataDir: "$WORKDIR/server-data"
  maxOrgsPerUser: 5
  workers: 1
database:
  driver: sqlite
  dsn: "file:data/panel.db"
log:
  level: info
  format: json
mail:
  devMode: true
  smtp: { host: "", port: 587, username: "", from: "" }
web:
  baseURL: "http://localhost:5173"
logcollect:
  enabled: true
  containerPrefix: "panel-org"
  rules:
    - name: file-transfer
      pattern: '^\[[^\]]+\]\s+INFO\s+\[[^\]]+\]\s+.*(?:file|transfer).*?(?P<device>\d{6,12})'
      level: info
      kind: file
    - name: connection
      pattern: '^\[[^\]]+\]\s+INFO\s+\[[^\]]+\]\s+.*?(?P<device>\d{6,12})'
      level: info
      kind: conn
    - name: warnings
      pattern: '^\[[^\]]+\]\s+WARN\s+\[[^\]]+\]\s+(?P<msg>.*)$'
      level: warn
      kind: other
    - name: errors
      pattern: '^\[[^\]]+\]\s+ERROR\s+\[[^\]]+\]\s+(?P<msg>.*)$'
      level: error
      kind: error
  retentionSweepInterval: 6h
session:
  idleTimeout: 10m
EOF
  ( cd panel-data && exec nohup "$WORKDIR/panel" > panel.log 2>&1 ) &
  echo $! > panel-data/panel.pid
  sleep 5
fi
curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$API/healthz" | grep -q 200 \
  && ok "panel 健康检查 200" || { bad "panel 未启动（看 $WORKDIR/panel-data/panel.log）"; exit 1; }

section "3. 播种前置数据（首个账号/组织/设备；直写库）"
( cd repo && go run ./tools/regression/m3harness -base "$API" -db "file:$DB" -out "$EV" -phase seed -confirm-seed )
ok "seed 完成（owner=step5m3@example.com / device rustdesk_id=123456789）"

section "4. M3 面板侧全链路（12 项断言 + 证据落盘）"
set +e
( cd repo && go run ./tools/regression/m3harness -base "$API" -db "file:$DB" -out "$EV" -phase flows )
FLOW_RC=$?
set -e
[ "$FLOW_RC" -eq 0 ] && ok "harness flows 全绿（明细见 $EV/*.json）" || bad "harness flows 有失败项（明细见 $EV/*.json）"

section "5. Docker provision 端到端（真实容器）"
TOKEN=$(curl -s --noproxy '*' -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"step5m3@example.com","password":"step5m3-pass-123456"}' | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] && ok "登录拿到 access token" || { bad "登录失败"; exit 1; }

# Reuse the organization across reruns: a new one would burn another 5-port
# block and, after five attempts, hit provision.maxOrgsPerUser.
ORG2=$(curl -s --noproxy '*' "$API/api/v1/orgs" -H "Authorization: Bearer $TOKEN" |
  python3 -c 'import json,sys
d=json.load(sys.stdin)
rows=d.get("data") or []
o=next((r for r in rows if r.get("name")=="step5m3-provision-org"), None)
print(o.get("id","") if o else "")')
if [ -z "$ORG2" ]; then
  curl -s --noproxy '*' -X POST "$API/api/v1/orgs" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d '{"name":"step5m3-provision-org"}' > "$EV/provision-org.json"
  ORG2=$(python3 - "$EV/provision-org.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print((d.get("data") or {}).get("id") or "")
PY
)
fi
[ -n "$ORG2" ] && ok "provision 组织 id=$ORG2" || { bad "创建/查找组织失败"; exit 1; }

echo "等待 provision（最多 180s）…"
READY=0
for _ in $(seq 1 60); do
  N=$(docker ps --filter "name=panel-org-$ORG2-" --format '{{.Names}}' | wc -l)
  if [ "$N" -ge 2 ]; then READY=1; break; fi
  sleep 3
done
[ "$READY" -eq 1 ] && ok "两个容器已就绪" || bad "180s 内未出现两个容器（看 docker ps -a 与 panel.log）"
docker ps --filter "name=panel-org-$ORG2-" --format '{{.Names}} {{.Ports}}' > "$EV/provision-containers.txt"
cat "$EV/provision-containers.txt"
grep -q "panel-org-$ORG2-hbbs" "$EV/provision-containers.txt" && ok "hbbs 容器就绪" || bad "hbbs 容器未出现"
grep -q "panel-org-$ORG2-hbbr" "$EV/provision-containers.txt" && ok "hbbr 容器就绪" || bad "hbbr 容器未出现"

# Real allocated ports: the panel assigns a 5-port block and the container
# maps hbbs to <hbbs_port>+1 and hbbr to <hbbr_port>+1 on the host.
PORTS=$(python3 - "$DB" "$ORG2" <<'PY'
import sqlite3,sys
con=sqlite3.connect(sys.argv[1]); org=sys.argv[2]
row=con.execute("select hbbs_port,hbbr_port from server_groups where organization_id=?",(org,)).fetchone()
if row: print(f"{row[0]},{row[1]},{row[0]+1},{row[1]+1}")
PY
)
IFS=, read -r HBBS_PORT HBBR_PORT ID_PORT RELAY_PORT <<< "${PORTS:-,,,}"
[ -n "${ID_PORT:-}" ] && ok "端口块：hbbs=$HBBS_PORT hbbr=$HBBR_PORT → 客户端 ID=$PUBLIC_HOST:$ID_PORT relay=$PUBLIC_HOST:$RELAY_PORT" \
  || bad "读不到 server_groups 端口（库 $DB / org $ORG2）"

: > "$EV/docker-logs.txt"
docker ps --filter "name=panel-org-$ORG2-" --format '{{.Names}}' | while read -r c; do
  echo "--- docker logs -t $c ---" >> "$EV/docker-logs.txt"
  docker logs -t "$c" >> "$EV/docker-logs.txt" 2>&1 || true
done
grep -q "Listening on tcp/udp :21116" "$EV/docker-logs.txt" && ok "hbbs 启动日志符合 1.1.x 格式" || bad "hbbs 日志未见监听行（见 docker-logs.txt）"
KEY=$(docker logs "panel-org-$ORG2-hbbs" 2>&1 | sed -n 's/.*Key: *//p' | tail -1)
[ -n "$KEY" ] && ok "hbbs 公钥已取得" || bad "取不到 hbbs 公钥（见 docker-logs.txt）"

section "6. 真实日志采集 → LogEvent → native 会话（需真实客户端注册）"
cat <<TIP
请在客户端里填：
  ID 服务器   $PUBLIC_HOST:${ID_PORT:-?}
  中继服务器  $PUBLIC_HOST:${RELAY_PORT:-?}
  Key         ${KEY:-?}
TIP
# Two-step ordering matters: the collector attaches a session only when the
# rustdesk_id is already registered in the organization at the time it handles
# the line. So (1) let the client register once, (2) read its id from the hbbs
# log and register the device, (3) have the operator reconnect so a *new*
# registration line arrives after the device exists.
if [ -t 0 ]; then
  read -r -p "第 1 步：客户端已启动并完成一次注册后按回车…" _ || true
else
  echo "（非交互环境：跳过等待，直接读日志；请确保客户端已连接）"
fi
docker logs "panel-org-$ORG2-hbbs" > "$EV/docker-logs.txt" 2>&1 || true
CLIENT_ID=$(grep -oE 'update_pk [0-9]{6,12}' "$EV/docker-logs.txt" | tail -1 | awk '{print $2}' || true)
if [ -z "${CLIENT_ID:-}" ] && [ -t 0 ]; then
  read -r -p "日志里没读到设备 ID；请手动输入客户端显示的 ID（留空跳过）：" CLIENT_ID || true
fi
[ -n "${CLIENT_ID:-}" ] && ok "客户端设备 ID=$CLIENT_ID" || bad "拿不到客户端设备 ID（日志无 update_pk 且未手输）"
if [ -n "${CLIENT_ID:-}" ]; then
  python3 - "$DB" "$ORG2" "$CLIENT_ID" <<'PY'
import sqlite3,sys,datetime
db,org,rid=sys.argv[1],int(sys.argv[2]),sys.argv[3]
con=sqlite3.connect(db)
now=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S+00:00')
con.execute("""INSERT INTO devices (organization_id, rustdesk_id, name, bound_uuid, binding_generation,
                created_at, updated_at) SELECT ?,?,?, '', 0, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM devices WHERE organization_id=? AND rustdesk_id=?)""",
            (org,rid,"step5m3-real-client",now,now,org,rid))
con.commit()
print("device registered:", rid)
PY
  ok "设备已登记到组织 $ORG2（rustdesk_id=$CLIENT_ID）"
  if [ -t 0 ]; then
    read -r -p "第 2 步：请更换客户端密钥对（重装/重置密钥确认）或重启 hbbs 容器使其丢失 peer 记录，确认出现登记后的新 update_pk 日志行，然后按回车…" _ || true
  fi
fi

# Poll until the collector has seen a conn event and produced a native session
# (or the bound expires). Events handled before the device row existed are
# intentionally not retro-linked, so this waits for lines after registration.
CONNS=0; NATIVE=0
for _ in $(seq 1 30); do
  curl -s --noproxy '*' "$API/api/v1/orgs/$ORG2/log-events?limit=50" -H "Authorization: Bearer $TOKEN" > "$EV/log-events.json"
  curl -s --noproxy '*' "$API/api/v1/orgs/$ORG2/sessions?origin=native&pageSize=50" -H "Authorization: Bearer $TOKEN" > "$EV/native-sessions.json"
  read -r CONNS NATIVE <<<"$(python3 - "$EV/log-events.json" "$EV/native-sessions.json" <<'PY'
import json,sys
le=json.load(open(sys.argv[1])); rows=le.get("data") or []
ss=json.load(open(sys.argv[2])); items=(ss.get("data") or {}).get("items") or []
print(sum(1 for r in rows if r.get("kind")=="conn"), len(items))
PY
)"
  [ "${CONNS:-0}" -ge 1 ] && [ "${NATIVE:-0}" -ge 1 ] && break
  sleep 3
done
python3 - "$EV/log-events.json" "$EV/native-sessions.json" <<'PY'
import json,sys
le=json.load(open(sys.argv[1])); rows=le.get("data") or []
print(f"log-events 条数={len(rows)}")
for r in rows[:5]: print(" ", r.get("source"), r.get("kind"), r.get("device_id"), r.get("occurred_at"))
ss=json.load(open(sys.argv[2])); items=(ss.get("data") or {}).get("items") or []
print(f"native 会话条数={len(items)}")
for s in items[:5]: print(" ", s.get("id"), s.get("status"), s.get("started_at"), s.get("end_reason"))
PY
[ "${CONNS:-0}" -ge 1 ] && ok "采集到 conn 事件（真实 docker logs → LogEvent）" || bad "没有 conn 事件（客户端未注册到 hbbs，或采集器未覆盖该组织）"
[ "${NATIVE:-0}" -ge 1 ] && ok "native 会话已由日志推断入库" || bad "没有 native 会话（设备是否在注册后重新连接？设备需登记在组织 $ORG2）"

section "7. #36 纳秒碰撞率专项（可选）"
if [ "$RUN_PROBE" = "--probe" ]; then
  bash repo/docs/reference/step5-collision-probe.sh "100 1000 5000 20000" | tee "$EV/collision-probe.txt"
  ok "碰撞率专项已执行（结果见 collision-probe.txt）"
else
  echo "（跳过；用 --probe 参数可执行）"
fi

section "8. 结果汇总"
if [ ! -e "$WORKDIR/step5-m3-result.md" ]; then
  # The template is a convenience, never a reason to abort before the summary.
  cp repo/docs/reference/step5-m3-report-template.md "$WORKDIR/step5-m3-result.md" \
    || echo "WARN: 报告模板缺失，未生成 step5-m3-result.md（证据目录仍完整）"
fi
echo "PASS=$PASS FAIL=$FAIL"
echo "证据目录：$EV"
echo "panel 日志：$WORKDIR/panel-data/panel.log"
echo "数据库：$DB"
[ "$FAIL" -eq 0 ] || exit 1
