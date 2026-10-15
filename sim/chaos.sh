#!/bin/bash
nohup /workspace/kavach/engine/kavach -seats 2000 -workers 8 -log /workspace/kavach/engine/bookings_c.jsonl > /workspace/kavach/engine/engine_c.log 2>&1 &
sleep 1
cd /workspace/kavach/sim && python3 simulate.py --total 30000 --concurrency 1000 --users 50 --bots 0.5 --out run_c.json > run_c.log 2>&1
echo "RUN_C_DONE $(date +%H:%M:%S)"
pkill -f 'engine/kavach'; sleep 1
nohup /workspace/kavach/engine/kavach -seats 2000 -workers 8 -log /workspace/kavach/engine/bookings_d.jsonl > /workspace/kavach/engine/engine_d.log 2>&1 &
sleep 1
( sleep 20; EPID=$(pgrep -f 'engine/kavach'); kill -STOP $EPID && echo "ENGINE_FROZEN $(date +%H:%M:%S)"; sleep 15; kill -CONT $EPID && echo "ENGINE_RESUMED $(date +%H:%M:%S)" ) &
cd /workspace/kavach/sim && python3 simulate.py --total 100000 --concurrency 2000 --users 100000 --bots 0.2 --out run_d.json > run_d.log 2>&1
echo "RUN_D_DONE $(date +%H:%M:%S)"
