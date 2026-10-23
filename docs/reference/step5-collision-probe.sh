#!/usr/bin/env bash
# =============================================================================
# #36 碰撞率专项 — 测量 dockerd 给相邻日志行分配的纳秒时间戳碰撞率
# 口径：与 logcollect 游标消费的值一致（docker logs -t 输出的捕获时间戳）
# 方法：busybox 容器按可调速率输出行 → docker logs -t --since <本档起点> 采样
#       → 统计相邻行同纳秒 / 同毫秒 / 同秒的比率，并报告**实测**吞吐
# 用法：./step5-collision-probe.sh [RATES]  例：./step5-collision-probe.sh "100 1000 5000 20000"
# 说明：高吞吐档下 `sleep` 精度与每行一次 fork 的开销会让**实测**速率低于名义值；
#       本脚本以时间戳跨度计算实测速率并写进结果，判定只看碰撞率，不看名义值。
# =============================================================================
set -euo pipefail
RATES="${1:-100 1000 5000 20000}"
SAMPLES="${SAMPLES:-5000}"
IMG="${IMG:-busybox:latest}"
CONT=step5-collision-probe
OUT="${OUT:-/tmp/probe-stream.txt}"

docker rm -f "$CONT" >/dev/null 2>&1 || true
docker pull -q "$IMG" >/dev/null 2>&1 || true
docker run -d --name "$CONT" "$IMG" sh -c 'sleep 3600' >/dev/null

for RATE in $RATES; do
  # Each tier reads only its own lines: without --since the second tier onward
  # would replay every earlier tier's lines and the ratio would be meaningless.
  SINCE=$(python3 -c "import datetime;print(datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'))")
  DELAY=$(python3 -c "print(f'{1.0/$RATE:.6f}')")   # seconds between lines

  docker exec "$CONT" sh -c "i=0; while [ \$i -lt $SAMPLES ]; do echo \"line-\$i\"; i=\$((i+1)); sleep $DELAY; done" >/dev/null 2>&1 &
  EMIT_PID=$!
  sleep 1
  docker logs -t --since "$SINCE" -f "$CONT" > "$OUT" 2>&1 &
  READ_PID=$!
  wait "$EMIT_PID" 2>/dev/null || true
  sleep 2
  kill "$READ_PID" 2>/dev/null || true
  wait "$READ_PID" 2>/dev/null || true

  python3 - "$RATE" "$OUT" <<'PY'
import sys, re, datetime
nominal = float(sys.argv[1]); path = sys.argv[2]
ts = []
for line in open(path, errors='ignore'):
    # docker logs -t format: 2026-10-21T08:00:00.123456789Z line-0
    m = re.match(r'^(\S+T\S+Z)\s', line)
    if m:
        ts.append(m.group(1))

def parse(s):
    return datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))

pairs = len(ts) - 1
same_ns = sum(1 for a, b in zip(ts, ts[1:]) if a == b)
same_ms = sum(1 for a, b in zip(ts, ts[1:]) if a[:23] == b[:23])
same_s = sum(1 for a, b in zip(ts, ts[1:]) if a[:20] == b[:20])
ns_rate = same_ns / pairs if pairs else 0.0
actual = 0.0
if len(ts) >= 2:
    span = (parse(ts[-1]) - parse(ts[0])).total_seconds()
    actual = pairs / span if span > 0 else 0.0
print(f"nominal={nominal:.0f}/s actual={actual:.0f}/s lines={len(ts)} pairs={pairs} | "
      f"同纳秒={same_ns} ({ns_rate:.4%}) 同毫秒={same_ms} 同秒={same_s}")
PY
done

echo
echo "判定：#36 的决策点是『同纳秒碰撞是否达到需要唯一去重键的水平』。"
echo "- 若各吞吐档同纳秒率≈0：游标方案（+1ns 重连）可行，#36 保持低优先级"
echo "- 若高吞吐档出现显著同纳秒碰撞：需要唯一去重键（内容 hash + 序号），#36 升级"
echo "- 报告里必须同时记录 nominal 与 actual，两者差距大时以 actual 解读结果"
docker rm -f "$CONT" >/dev/null 2>&1 || true
