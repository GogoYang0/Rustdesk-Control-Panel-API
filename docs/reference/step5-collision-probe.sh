#!/usr/bin/env bash
# =============================================================================
# #36 碰撞率专项 — 测量 dockerd 给相邻日志行分配的纳秒时间戳碰撞率
# 口径：与 logcollect 游标消费的值一致（docker logs -t 输出的捕获时间戳）
# 方法：busybox 容器按可调速率输出行 → docker logs -t 采样 → 统计相邻行
#       同纳秒 / 同毫秒 / 同秒 的比率，按吞吐水平分组
# 用法：./step5-collision-probe.sh [RATES]  例：./step5-collision-probe.sh "100 1000 5000 20000"
# =============================================================================
set -euo pipefail
RATES="${1:-100 1000 5000 20000}"
SAMPLES="${SAMPLES:-5000}"
IMG="${IMG:-busybox:latest}"
CONT=step5-collision-probe

docker rm -f $CONT >/dev/null 2>&1 || true
docker pull -q $IMG >/dev/null 2>&1 || true
docker run -d --name $CONT $IMG sh -c 'sleep 3600' >/dev/null

for RATE in $RATES; do
  DELAY=$(python3 -c "print(round(1000000/$RATE))")   # microseconds between lines
  # 阶段1：按速率输出 SAMPLES 行（us 睡眠近似节流）
  docker exec $CONT sh -c "i=0; while [ \$i -lt $SAMPLES ]; do echo \"line-\$i\"; i=\$((i+1)); sleep $DELAY\"000\"; done" >/dev/null 2>&1 &
  EMIT_PID=$!
  sleep 2
  # 阶段2：同时从 docker logs -t 持续读取（模拟 tailer 消费）
  docker logs -t -f $CONT > /tmp/probe-stream.txt 2>&1 &
  READ_PID=$!
  wait $EMIT_PID 2>/dev/null || true
  sleep 3
  kill $READ_PID 2>/dev/null || true
  wait $READ_PID 2>/dev/null || true

  python3 - "$RATE" <<'PY'
import sys, re
rate=sys.argv[1]
ts=[]
for line in open('/tmp/probe-stream.txt', errors='ignore'):
    # docker logs -t 格式：2026-10-21T08:00:00.123456789Z line-0
    m=re.match(r'^(\S+T\S+Z)\s', line)
    if m: ts.append(m.group(1))
pairs=len(ts)-1
same_ns=sum(1 for a,b in zip(ts,ts[1:]) if a==b)
same_ms=sum(1 for a,b in zip(ts,ts[1:]) if a[:23]==b[:23])
same_s =sum(1 for a,b in zip(ts,ts[1:]) if a[:20]==b[:20])
rate_ns = same_ns/pairs if pairs else 0
print(f"rate={rate}/s lines={len(ts)} pairs={pairs} | 同纳秒={same_ns} ({rate_ns:.4%}) 同毫秒={same_ms} 同秒={same_s}")
PY
done

section_note(){ echo; echo "判定：#36 的决策点是『同纳秒碰撞是否达到需要唯一去重键的水平』。"; echo "- 若各吞吐档同纳秒率≈0：游标方案（+1ns 重连）可行，#36 保持低优先级"; echo "- 若高吞吐档出现显著同纳秒碰撞：需要唯一去重键（内容 hash + 序号），#36 升级"; }
section_note
docker rm -f $CONT >/dev/null 2>&1 || true
