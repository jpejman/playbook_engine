import requests
import json
from datetime import datetime
import time
import os

# Version and Timestamp
VERSION = "v00.010.04"
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# API Configuration
API_ENDPOINT = "http://192.168.1.236:11434/api/generate"
MODELS = ["llama3.2-vision", "llama3.1:70b", "codellama"]

# Define multiple prompts
PROMPTS = [
    "Write a 100-word essay on the history and future of artificial intelligence. Include milestones, ethical implications, and the impact on industries such as healthcare, education, and transportation.",
    "Explain the ethical challenges posed by artificial intelligence in 2000 words.",
    "Create a detailed guide for deploying AI models in cloud environments, including challenges and solutions (3000 words)."
]

# Function to calculate word count
def word_count(text):
    return len(text.split())

# Function to sanitize filenames
def sanitize_filename(name):
    return name.replace(":", "_").replace("/", "_")

# Function to send a prompt and handle streaming responses
def generate_response(prompt, api_url, model):
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": model,
        "prompt": prompt
    }

    raw_response = []
    formatted_response = ""
    start_time = time.time()

    try:
        with requests.post(api_url, headers=headers, json=payload, stream=True) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if line:
                    line = line.decode('utf-8')
                    raw_response.append(line)
                    try:
                        json_line = json.loads(line)
                        if "response" in json_line:
                            formatted_response += json_line["response"]
                    except json.JSONDecodeError:
                        print(f"Warning: Unable to parse line: {line}")
        total_time = time.time() - start_time
        return formatted_response, raw_response, total_time
    except requests.exceptions.RequestException as e:
        print(f"Error during API request for model {model}: {e}")
        return None, None, 0

# Batch process prompts and models
for model in MODELS:
    sanitized_model = sanitize_filename(model)  # Sanitize model name for file paths
    for idx, prompt in enumerate(PROMPTS):
        # File paths for output
        output_dir = f"./outputs/{VERSION}/{sanitized_model}"
        os.makedirs(output_dir, exist_ok=True)
        formatted_file = os.path.join(output_dir, f"formatted_output_prompt{idx+1}_{TIMESTAMP}.txt")
        raw_file = os.path.join(output_dir, f"raw_output_prompt{idx+1}_{TIMESTAMP}.txt")

        # Generate response
        formatted, raw, total_time = generate_response(prompt, API_ENDPOINT, model)

        # Save outputs
        if formatted and raw:
            try:
                actual_word_count = word_count(formatted)
                with open(formatted_file, "w") as f_formatted:
                    f_formatted.write(f"Version: {VERSION}\n")
                    f_formatted.write(f"Timestamp: {TIMESTAMP}\n")
                    f_formatted.write(f"Model: {model}\n")
                    f_formatted.write(f"Prompt {idx+1}:\n{prompt}\n")
                    f_formatted.write(f"Actual Word Count: {actual_word_count}\n")
                    f_formatted.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
                    f_formatted.write(formatted)

                with open(raw_file, "w") as f_raw:
                    f_raw.write(f"Version: {VERSION}\n")
                    f_raw.write(f"Timestamp: {TIMESTAMP}\n")
                    f_raw.write(f"Model: {model}\n")
                    f_raw.write(f"Prompt {idx+1}:\n{prompt}\n")
                    f_raw.write(f"Actual Word Count: {actual_word_count}\n")
                    f_raw.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
                    f_raw.write("\n".join(raw))

                # Print CLI summary
                print(f"Model: {model}, Prompt {idx+1}")
                print(f"Actual Word Count: {actual_word_count}")
                print(f"Total Time Taken: {total_time:.2f} seconds")
                print(f"Formatted output saved to: {formatted_file}")
                print(f"Raw response saved to: {raw_file}")
            except Exception as e:
                print(f"Error writing files for Model: {model}, Prompt {idx+1}: {e}")
        else:
            print(f"Error for Model: {model}, Prompt {idx+1}: Response was empty or invalid.")
