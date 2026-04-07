import os
import pandas as pd
import requests
import json
import glob
from datetime import datetime
import time

# Version and Timestamp
VERSION = "v00.010.10"
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# API Configuration
API_ENDPOINT = "http://192.168.1.236:11434/api/generate"

# Model names and prompts
MODELS = ["llama3.2-vision", "llama3.1:70b", "codellama"]
PROMPTS = [
    "Write a detailed guide for deploying AI models in cloud environments, including challenges and solutions (100 words).",
    "Explain the ethical challenges posed by artificial intelligence in 100 words.",
    "Provide a security vulnerability remediation guide for Linux server configurations in 100 words."
]

# File Paths
output_dir = f"./outputs/{VERSION}/"
os.makedirs(output_dir, exist_ok=True)
ranking_results_file = os.path.join(output_dir, f"model_ranking_results_{TIMESTAMP}.txt")

# Data storage
word_counts = {model: [] for model in MODELS}
time_taken = {model: [] for model in MODELS}

# Function to call the LLM API
def call_llm_api(model, prompt):
    headers = {"Content-Type": "application/json"}
    payload = {"model": model, "prompt": prompt}

    start_time = time.time()
    
    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=payload, stream=True)
        response.raise_for_status()

        raw_response = []
        formatted_response = ""

        for line in response.iter_lines():
            if line:
                line = line.decode("utf-8")
                raw_response.append(line)
                try:
                    json_line = json.loads(line)
                    if "response" in json_line:
                        formatted_response += json_line["response"]
                except json.JSONDecodeError:
                    print(f"⚠️ Warning: Could not parse response line: {line}")

        total_time = round(time.time() - start_time, 2)
        return formatted_response, raw_response, total_time

    except requests.exceptions.RequestException as e:
        print(f"❌ Error: API call failed for {model} → {e}")
        return None, None, 0

# Run API calls and save outputs
for model in MODELS:
    model_dir = os.path.join(output_dir, model)
    os.makedirs(model_dir, exist_ok=True)

    for i, prompt in enumerate(PROMPTS):
        formatted_response, raw_response, total_time = call_llm_api(model, prompt)

        if formatted_response and raw_response:
            word_count = len(formatted_response.split())

            formatted_file = os.path.join(model_dir, f"formatted_output_prompt{i+1}_{TIMESTAMP}.txt")
            raw_file = os.path.join(model_dir, f"raw_output_prompt{i+1}_{TIMESTAMP}.txt")

            with open(formatted_file, "w") as f_formatted:
                f_formatted.write(f"Version: {VERSION}\n")
                f_formatted.write(f"Timestamp: {TIMESTAMP}\n")
                f_formatted.write(f"Prompt:\n{prompt}\n")
                f_formatted.write(f"Actual Word Count: {word_count}\n")
                f_formatted.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
                f_formatted.write(formatted_response)

            with open(raw_file, "w") as f_raw:
                f_raw.write("\n".join(raw_response))

            word_counts[model].append(word_count)
            time_taken[model].append(total_time)
        else:
            word_counts[model].append(0)
            time_taken[model].append(float("inf"))

# Calculate model rankings
ranking_results = []
for i, prompt in enumerate(PROMPTS):
    valid_word_counts = [word_counts[model][i] for model in MODELS if word_counts[model][i] > 0]
    valid_times = [time_taken[model][i] for model in MODELS if time_taken[model][i] < float("inf")]

    if not valid_word_counts or not valid_times:
        print(f"⚠️ Skipping ranking for {prompt}: No valid model responses found.")
        continue

    max_word_count = max(valid_word_counts)
    min_time_taken = min(valid_times)

    scores = []
    for model in MODELS:
        wc = word_counts[model][i]
        tt = time_taken[model][i]

        if wc == 0 or tt == float("inf"):
            score = 0  # If no response, score is 0
        else:
            completeness_score = (wc / max_word_count) * 100
            speed_score = (min_time_taken / tt) * 100
            efficiency_score = ((wc / tt) / (max_word_count / min_time_taken)) * 100

            final_score = (0.4 * completeness_score) + (0.3 * speed_score) + (0.3 * efficiency_score)
            scores.append((model, final_score))

    scores.sort(key=lambda x: x[1], reverse=True)

    for rank, (model, score) in enumerate(scores, start=1):
        ranking_results.append([prompt, model, rank, round(score, 2)])

# Convert to DataFrame and save results
df = pd.DataFrame(ranking_results, columns=["Prompt", "Model", "Rank", "Final Score"])
df.to_csv(ranking_results_file, index=False, sep="\t")

# CLI Summary
print("\n📊 **Model Ranking Report Generated:**")
print(f"   📂 Saved at: {ranking_results_file}")
print("=" * 80)

# Display results in CLI
if not df.empty:
    print(df.to_string(index=False))
else:
    print("⚠️ No valid responses to rank. Check your model outputs.")
