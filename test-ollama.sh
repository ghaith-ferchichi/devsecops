curl -s http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5-coder:14b",
    "system": "You are a senior devsecops engineer. always respond in structred markdown format",
    "prompt": "Give me the security mesurment that should be present in the code review. respond in bullet and dont develop",
    "stream": true
  }' | while read line; do
    echo "$line" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('response',''), end='', flush=True)
except: pass"
  done