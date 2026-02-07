#!/bin/bash
# Dorker monitoring script - Comprehensive status check

LOG_DIR="/root/Projects/Medin/tools/dorker/logs"
DORKER_DIR="/root/Projects/Medin/tools/dorker"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║               MEDIN DORKER STATUS MONITOR                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if dorker is running
if ps aux | grep "python dorker.py" | grep -v grep > /dev/null; then
    echo "✅ STATUS: RUNNING"
    echo ""
    ps aux | grep "python dorker.py" | grep -v grep | awk '{print "   PID: " $2 " | CPU: " $3 "% | Memory: " $4 "%"}'
else
    echo "❌ STATUS: NOT RUNNING"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "📊 STATISTICS"
echo "════════════════════════════════════════════════════════════"
echo ""

# Sites found
if [ -f "$DORKER_DIR/found_sites.json" ]; then
    SITE_COUNT=$(cat "$DORKER_DIR/found_sites.json" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len(data))" 2>/dev/null)
    HIGH_SCORE=$(cat "$DORKER_DIR/found_sites.json" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len([s for s in data if s.get('score', 0) >= 50]))" 2>/dev/null)
    SCORE_100=$(cat "$DORKER_DIR/found_sites.json" | python3 -c "import sys, json; data = json.load(sys.stdin); print(len([s for s in data if s.get('score', 0) >= 100]))" 2>/dev/null)
    echo "   Total sites found:    $SITE_COUNT"
    echo "   High score (>=50):    $HIGH_SCORE"
    echo "   Perfect score (100):  $SCORE_100"
fi

# Domains checked
if [ -f "$DORKER_DIR/seen_domains.txt" ]; then
    DOMAIN_COUNT=$(wc -l < "$DORKER_DIR/seen_domains.txt")
    echo "   Domains checked:      $DOMAIN_COUNT"
fi

# Proxies
if [ -f "$DORKER_DIR/proxies.txt" ]; then
    PROXY_COUNT=$(grep -v "^#" "$DORKER_DIR/proxies.txt" | grep -v "^$" | wc -l)
    echo "   Active proxies:       $PROXY_COUNT"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "📁 LOG FILES"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -d "$LOG_DIR" ]; then
    ls -lh "$LOG_DIR" 2>/dev/null | tail -n +2 | awk '{print "   " $9 ": " $5}'
else
    echo "   Log directory not found"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "🔴 RECENT ERRORS (last 10)"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -f "$LOG_DIR/dorker_errors.log" ] && [ -s "$LOG_DIR/dorker_errors.log" ]; then
    tail -10 "$LOG_DIR/dorker_errors.log"
else
    echo "   No errors logged"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "🌐 RECENT SEARCH ACTIVITY (last 10)"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -f "$LOG_DIR/search_results.log" ]; then
    tail -10 "$LOG_DIR/search_results.log"
else
    echo "   No search logs found"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ RECENT SITES FOUND (last 5)"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -f "$LOG_DIR/sites_found.log" ] && [ -s "$LOG_DIR/sites_found.log" ]; then
    tail -5 "$LOG_DIR/sites_found.log"
else
    echo "   No sites found yet in this session"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "📈 STATS LOG (latest)"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -f "$LOG_DIR/stats.log" ]; then
    tail -3 "$LOG_DIR/stats.log"
else
    echo "   No stats logged yet"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "📜 CONSOLE OUTPUT (last 15 lines)"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -f "$DORKER_DIR/dorker_output.log" ]; then
    tail -15 "$DORKER_DIR/dorker_output.log"
else
    echo "   No console output found"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "🏆 TOP 10 SITES BY SCORE"
echo "════════════════════════════════════════════════════════════"
echo ""
if [ -f "$DORKER_DIR/found_sites.json" ]; then
    cat "$DORKER_DIR/found_sites.json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
data.sort(key=lambda x: x.get('score', 0), reverse=True)
for site in data[:10]:
    score = site.get('score', 0)
    domain = site.get('domain', 'unknown')
    platform = site.get('platform') or 'Unknown'
    pk = site.get('pk_key', '')[:25] + '...' if site.get('pk_key') else 'None'
    print(f'   {score:3d} | {domain[:35]:<35} | {platform:<12} | {pk}')
"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "📌 COMMANDS"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "   Watch live logs:   tail -f $DORKER_DIR/dorker_output.log"
echo "   Watch errors:      tail -f $LOG_DIR/dorker_errors.log"
echo "   Watch sites:       tail -f $LOG_DIR/sites_found.log"
echo "   Full main log:     less $LOG_DIR/dorker_main.log"
echo ""
echo "   Restart dorker:"
echo "   pkill -f 'python dorker.py'"
echo "   cd $DORKER_DIR && nohup python dorker.py --token TOKEN --chat CHAT --debug > dorker_output.log 2>&1 &"
echo ""
