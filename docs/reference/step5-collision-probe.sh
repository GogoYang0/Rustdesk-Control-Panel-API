#!/usr/bin/env bash
# =============================================================================
# #36 碰撞率专项 — 测量 dockerd 给相邻日志行分配的纳秒时间戳碰撞率
#
# 口径：与 logcollect 游标消费的值一致（`docker logs -t` 的捕获时间戳）。
#
# 方法要点（两个坑，都已在云端实测踩过）：
#   1) docker 只把 **PID 1** 的 stdout/stderr 写进 json-file 日志。用
#      `docker exec ... echo` 生成的行直连 CLI，`docker logs` 永远读不到
#      （实测 Docker 27.5.1：四档全部 lines=0）。所以每档的容器把「发日志的
#      循环」作为 entrypoint，让 PID 1 自己输出。
#   2) 每档用**独立容器**，退出后一次性 `docker logs -t` 取全量。这样既不需要
#      `--since`，也不会有上一档的行混进来。
#   3) 实测吞吐会显著低于名义值（每行一次 fork + sleep 精度），脚本按时间戳
#      跨度算出 actual 并打印；判定只看碰撞率，同时必须报告 actual。
#
# 用法：./step5-collision-probe.sh [RATES]     例："./... \"100 1000 5000 20000\""
# 可选：SAMPLES=5000 IMG=busybox:latest OUT=/tmp/probe-stream.txt
# =============================================================================
set -euo pipefail
RATES="${1:-100 1000 5000 20000}"
SAMPLES="${SAMPLES:-5000}"
IMG="${IMG:-busybox:latest}"
CONT="${CONT:-step5-probe}"
OUT="${OUT:-/tmp/probe-stream.txt}"

docker pull -q "$IMG" >/dev/null 2>&1 || true

for RATE in $RATES; do
  NAME="$CONT-$RATE"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  # Seconds between lines. Python keeps the precision the shell would round away.
  DELAY=$(python3 -c "print(f'{1.0/$RATE:.6f}')")

  # PID 1 emits and exits; `docker run` (foreground) returns when it is done.
  docker run --name "$NAME" "$IMG" sh -c \
    "i=0; while [ \$i -lt $SAMPLES ]; do echo \"line-\$i\"; i=\$((i+1)); sleep $DELAY; done" \
    >/dev/null 2>&1

  # Container has exited but its json-file log is still readable.
  # Do NOT swallow a read failure here: an empty $OUT would otherwise be
  # reported as "0 collisions", i.e. a false green (exactly the first-cloud-run
  # failure mode). `set -e` propagates the non-zero status.
  docker logs -t "$NAME" > "$OUT" 2>&1

  python3 - "$RATE" "$OUT" "$SAMPLES" <<'PY'
import sys, re, datetime
nominal = float(sys.argv[1]); path = sys.argv[2]
expected = int(sys.argv[3])
ts = []
for line in open(path, errors='ignore'):
    # docker logs -t format: 2026-10-21T08:00:00.123456789Z line-0
    m = re.match(r'^(\S+T\S+Z)\s', line)
    if m:
        ts.append(m.group(1))

# A successful read with fewer parsed lines is still invalid data: refuse to
# turn "we could not see the stream" into "zero collisions".
if len(ts) != expected:
    raise SystemExit(
        f"FAIL: parsed lines {len(ts)} != SAMPLES {expected} (log read incomplete)")

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

  docker rm -f "$NAME" >/dev/null 2>&1 || true
done

echo
echo "判定：#36 的决策点是『同纳秒碰撞是否达到需要唯一去重键的水平』。"
echo "- 各吞吐档同纳秒率≈0 → 游标方案（重连 +1ns）可行，#36 维持低优先级"
echo "- 高吞吐档出现显著同纳秒碰撞 → 需要唯一去重键（内容 hash + 序号），#36 升级"
echo "- 同毫秒碰撞率即使不为 0 也不影响现方案，但**禁止**把游标降级到毫秒精度（会漏行）"
echo "- 报告必须同时写 nominal 与 actual；差距大时以 actual 解读"
