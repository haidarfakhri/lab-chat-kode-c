
#!/bin/sh

# Usage: sh jalankan_uji_ab.sh <server_bin> <port> <srv_log> <probe_log>

SERVER_BIN="$1"

PORT="$2"

SRV_LOG="$3"

PROBE_LOG="$4"



"$SERVER_BIN" "$PORT" > "$SRV_LOG" 2>&1 &

SRV_PID=$!

sleep 0.4



./s4_lambat "$PORT" lambat 60 &

LAMBAT_PID=$!

sleep 0.3



./s4_probe "$PORT" probe 8 > "$PROBE_LOG" 2>&1 &

PROBE_PID=$!

sleep 0.3



cat banjir.txt | ./s2_klien "$PORT" banjir 12 > /dev/null 2>&1 &

BANJIR_PID=$!



wait $PROBE_PID 2>/dev/null

sleep 2

date -u +"=== SERVER KILLED AT %Y-%m-%dT%H:%M:%SZ ===" >> "${SRV_LOG}.killtime"

kill $SRV_PID $LAMBAT_PID $BANJIR_PID 2>/dev/null

wait 2>/dev/null

