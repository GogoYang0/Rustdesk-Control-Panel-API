#!/usr/bin/env bash
# =============================================================================
# Step 5 — M3 会话治理真机回归（Linux + Docker 云端一键执行）
#
# 目标：在带 Docker 的 Linux 主机上，用「真实 panel + 真实 rustdesk-server 容器
#       + 真实日志采集（docker logs -t）」验证 v0.4.0 的 M3 会话治理链路。
#
# 用法：
#   chmod +x step5-m3-run.sh
#   ./step5-m3-run.sh /root/step5m3-work        # 全流程（默认）
#   ./step5-m3-run.sh /root/step5m3-work --probe # 额外跑 #36 纳秒碰撞率专项
#
# 前置：docker（可 docker ps）、go >= 1.24、curl、bash
# 产出：$WORKDIR/evidence/*.json（逐项证据）、$WORKDIR/step5-m3-result.md（待填报告骨架）
# =============================================================================
set -euo pipefail
WORKDIR="${1:-$PWD/step5m3-work}"
RUN_PROBE="${2:-}"
REPO_URL="${REPO_URL:-https://github.com/GogoYang0/Rustdesk-Control-Panel-API.git}"
BRANCH="${BRANCH:-develop}"
RS_VERSION="${RS_VERSION:-1.1.16}"
API="${API:-http://127.0.0.1:8080}"
DB="$WORKDIR/panel-data/data/panel.db"
EV="$WORKDIR/evidence"
PASS=0; FAIL=0
ok(){ echo "✅ $1"; PASS=$((PASS+1)); }
bad(){ echo "❌ $1"; FAIL=$((FAIL+1)); }
section(){ echo; echo "===== $1 ====="; }

mkdir -p "$WORKDIR" && cd "$WORKDIR"
mkdir -p "$EV"

section "0. 环境检查"
docker ps >/dev/null 2>&1 && ok "docker daemon" || { bad "docker daemon 不可用"; exit 1; }
go version >/dev/null 2>&1 && ok "go ($(go version))" || { bad "go 未安装"; exit 1; }
curl --version >/dev/null 2>&1 && ok "curl" || { bad "curl 未安装"; exit 1; }
python3 --version >/dev/null 2>&1 && ok "python3" || { bad "python3 未安装（断言脚本需要）"; exit 1; }

section "1. 构建 panel"
if [ ! -d repo ]; then
  git clone --depth 1 -b "$BRANCH" "$REPO_URL" repo
fi
( cd repo && go build -o "$WORKDIR/panel" ./cmd/server )
ok "panel 构建完成（commit $(git -C repo rev-parse --short HEAD)）"

section "2. 启动 panel（真实配置，logcollect 已启用）"
mkdir -p panel-data/configs panel-data/data
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
  relayHost: "127.0.0.1"
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
( cd panel-data && nohup "$WORKDIR/panel" > panel.log 2>&1 & echo $! > panel.pid )
sleep 5
curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$API/healthz" | grep -q 200 \
  && ok "panel 健康检查 200" || { bad "panel 未启动（看 $WORKDIR/panel-data/panel.log）"; exit 1; }

section "3. 播种前置数据（首个账号/组织/设备，直接写库）"
( cd repo && go run ./tools/regression/m3harness -base "$API" -db "file:$DB" -out "$EV" -phase seed )
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
curl -s --noproxy '*' -X POST "$API/api/v1/orgs" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"step5m3-provision-org"}' > "$EV/provision-org.json"
ORG2=$(python3 - "$EV/provision-org.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print((d.get("data") or {}).get("id") or "")
PY
)
[ -n "$ORG2" ] && ok "创建第二组织 id=$ORG2（触发 provision）" || { bad "创建组织失败"; exit 1; }
echo "等待 provision（最多 180s）…"
for i in $(seq 1 60); do
  N=$(docker ps --filter "name=panel-org-$ORG2-" --format '{{.Names}}' | wc -l)
  [ "$N" -ge 2 ] && break
  sleep 3
done
docker ps --filter "name=panel-org-$ORG2-" --format '{{.Names}} {{.Ports}}' | tee "$EV/provision-containers.txt"
grep -q "panel-org-$ORG2-hbbs" "$EV/provision-containers.txt" && ok "hbbs 容器已就绪" || bad "hbbs 容器未出现"
grep -q "panel-org-$ORG2-hbbr" "$EV/provision-containers.txt" && ok "hbbr 容器已就绪" || bad "hbbr 容器未出现"
docker ps --filter "name=panel-org-$ORG2-" --format '{{.Names}}' | while read -r c; do
  echo "--- docker logs -t $c ---" >> "$EV/docker-logs.txt"
  docker logs -t "$c" >> "$EV/docker-logs.txt" 2>&1 || true
done
grep -q "Listening on tcp/udp :21116" "$EV/docker-logs.txt" && ok "hbbs 启动日志符合 1.1.x 格式" || bad "hbbs 日志未见监听行"

section "6. 真实日志采集 → LogEvent → native 会话（需要真实客户端连接）"
cat <<'TIP'
下一步需要一台真实 RustDesk 客户端连到本机 hbbs（无法在无 GUI 的容器里自动完成）：
  1) 取该组织 hbbs 的公钥：docker logs panel-org-<orgId>-hbbs | grep "Key:" 或读 server-data/org-<id>/id_ed25519.pub
  2) 客户端「ID/中继服务器」填 <云主机IP>:21116，Key 填上面的公钥
  3) 启动客户端 → hbbs 会打印 `update_pk <id> ...` → panel 采集器（已启用）自动入库
  4) 回到本脚本按回车继续（或稍后手工执行本节断言）
TIP
read -r -p "客户端已连接后按回车继续…" _ || true
ORG1=$(curl -s --noproxy '*' "$API/api/v1/orgs" -H "Authorization: Bearer $TOKEN" |
  python3 -c 'import json,sys
d=json.load(sys.stdin)
rows=d.get("data") or []
o=next((r for r in rows if r.get("name")=="step5m3-org"), rows[0] if rows else {})
print(o.get("id",""))')
[ -n "$ORG1" ] || { bad "取不到组织 id"; exit 1; }
curl -s --noproxy '*' "$API/api/v1/orgs/$ORG1/log-events?limit=50" -H "Authorization: Bearer $TOKEN" > "$EV/log-events.json"
python3 - "$EV/log-events.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
rows=d.get("data") or []
print(f"log-events 条数={len(rows)}")
for r in rows[:5]: print(" ", r.get("source"), r.get("kind"), r.get("device_id"), r.get("occurred_at"))
PY
curl -s --noproxy '*' "$API/api/v1/orgs/$ORG1/sessions?origin=native&limit=50" -H "Authorization: Bearer $TOKEN" > "$EV/native-sessions.json"
python3 - "$EV/native-sessions.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
items=(d.get("data") or {}).get("items") or []
print(f"native 会话条数={len(items)}")
for s in items[:5]: print(" ", s.get("id"), s.get("status"), s.get("started_at"), s.get("end_reason"))
PY
grep -q '"kind":"conn"' "$EV/log-events.json" && ok "采集到 conn 事件（真实 docker logs → LogEvent）" || bad "未采集到 conn 事件（检查客户端是否真的注册到 hbbs）"
python3 - "$EV/native-sessions.json" <<'PY' && ok "native 会话已由日志推断入库" || bad "未出现 native 会话"
import json,sys
d=json.load(open(sys.argv[1]))
items=(d.get("data") or {}).get("items") or []
sys.exit(0 if items else 1)
PY

section "7. #36 纳秒碰撞率专项（可选）"
if [ "$RUN_PROBE" = "--probe" ]; then
  if [ -f repo/docs/reference/step5-collision-probe.sh ]; then
    bash repo/docs/reference/step5-collision-probe.sh "100 1000 5000 20000" | tee "$EV/collision-probe.txt"
    ok "碰撞率专项已执行（结果见 collision-probe.txt）"
  else
    bad "未找到 step5-collision-probe.sh"
  fi
else
  echo "（跳过；用 --probe 参数可执行）"
fi

section "8. 结果汇总"
cp -f repo/docs/reference/step5-m3-report-template.md "$WORKDIR/step5-m3-result.md" 2>/dev/null || true
echo "PASS=$PASS FAIL=$FAIL"
echo "证据目录：$EV"
echo "panel 日志：$WORKDIR/panel-data/panel.log"
echo "数据库：$DB"
[ "$FAIL" -eq 0 ] || exit 1
