grep -E "^error" /tmp/agent2api-build.log | head -20
echo "---first error context---"
awk '/^error/{found=1} found{print; count++} count>25{exit}' /tmp/agent2api-build.log
