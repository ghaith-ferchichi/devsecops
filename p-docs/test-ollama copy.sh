curl -s http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5-coder:7b",
    "prompt": " give python code to print 'Hello, World!'",
    "stream": true
  }' | while read line; do
    echo "$line" | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('response',''), end='', flush=True)
except: pass"
  done