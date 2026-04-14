import requests
import json

#OLLAMA_HOST = "http://192.168.1.38:11434/api/generate"
OLLAMA_HOST = "http://192.168.1.200:11434/api/generate"
#OLLAMA_HOST = "http://192.168.1.39:11434/api/generate"
#OLLAMA_HOST = "http://192.168.1.41:11434/api/generate"
#OLLAMA_HOST = "http://192.168.1.241:11434/api/generate"
#OLLAMA_HOST = "http://10.0.0.100:11434/api/generate"

data = {
    "model": "qwen3:8b",
    #"model": "llama3.3:latest",

    "prompt": "Hello, how are you? explain in 100 words how to fix a bent cpu pin",
}

response = requests.post(OLLAMA_HOST, headers={"Content-Type": "application/json"}, data=json.dumps(data))

print("Raw Response:", response.text)
