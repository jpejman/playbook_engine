import requests
import json
import time
from datetime import datetime

# Configuration
OLLAMA_HOST = "http://10.0.0.100:11434"
#OLLAMA_HOST = "http://192.168.1.38:11434"
#OLLAMA_HOST = "http://192.168.1.39:11434"
#OLLAMA_HOST = "http://192.168.1.41:11434"
#OLLAMA_HOST = "http://192.168.1.241:11434"
#OLLAMA_HOST = "http://10.0.0.100:11434"

OLLAMA_ENDPOINT = f"{OLLAMA_HOST}/api/generate"

MODEL = "llama3.1:latest"
PROMPT = """
1.  Write a 5000 word essay on the history of AI. Do not imagine you are outputting 5,000 words. 
    Do an actual count of words with no white space or special markdown to get an accurate total. 
2.  Put word count after each paragraph.
    Please generate an essay on the history of artificial intelligence with clearly separated sections.
    Do not include any pre-computed or annotated word counts for each section in the final output.
    After the essay text is complete, please compute the total word count by splitting the entire essay text 
    (excluding any headings or metadata you added for clarity) using whitespace as the delimiter 
    (as in Python’s text.split() method). 
    Then, on a new line at the very end of your response, output only one final line in the exact format:
    Exact Word Count: X where X is the number you computed. Do not include any commentary or extra text 
    beyond that final line.
3.  Predict what the future of AI looks like.
4.  Closing remarks.
"""

# Generate a timestamp for unique file naming
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"test_prompt_FineTuned_output_{timestamp}.txt"

# Start the timer
start_time = time.time()

print("[INFO] Sending request to the API...")

# Send request to the Ollama API with streaming enabled
response = requests.post(
    OLLAMA_ENDPOINT,
    headers={"Content-Type": "application/json"},
    data=json.dumps({"model": MODEL, "prompt": PROMPT}),
    stream=True  # Enable streaming response
)

# Measure the API request completion time
api_end_time = time.time()
api_time_taken = round(api_end_time - start_time, 2)
print(f"[INFO] API request initiated in {api_time_taken} seconds. Processing response...")

# Initialize response content storage
response_text = ""

# Process response as a stream
try:
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(f"Generation completed in {api_time_taken} seconds.\n\n")
        file.write("[INFO] Streaming response:\n\n")

        for line in response.iter_lines():
            if line:
                try:
                    json_line = json.loads(line.decode('utf-8'))  # Parse each JSON line
                    text = json_line.get("response", "")  # Extract the response field
                    response_text += text + "\n"
                    file.write(text + "\n")  # Write incremental results
                    print(text, end="", flush=True)  # Print response live in CLI

                except json.JSONDecodeError as e:
                    print(f"\n[ERROR] JSON Decode Error: {e}")
                    print(f"[DEBUG] Raw line causing issue: {line.decode('utf-8')}\n")
        
        # Append full JSON response at the end
        file.write("\n\n--- Full API Response ---\n")
        json.dump({"response": response_text}, file, indent=2)

    # Measure total processing time
    end_time = time.time()
    total_time_taken = round(end_time - start_time, 2)

    print(f"\n[INFO] Response processing completed successfully in {total_time_taken} seconds!")
    print(f"[INFO] Output saved to {output_file}")

except Exception as e:
    print(f"\n[ERROR] An error occurred: {e}")

