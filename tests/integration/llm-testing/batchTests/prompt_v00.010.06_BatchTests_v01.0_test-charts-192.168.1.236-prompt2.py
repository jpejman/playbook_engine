import requests
import json
from datetime import datetime
import time
import os
import matplotlib.pyplot as plt
import numpy as np

# Version and Timestamp
VERSION = "v00.010.07"
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# API Configuration
API_ENDPOINT = "http://192.168.1.236:11434/api/generate"
#MODELS = ["llama3.2-vision", "llama3.1:latest", "codellama"]
#MODELS = ["llama3.3:latest", "llama3.2:3b", "llama3.1:latest", "codellama"]
MODELS = ["llama3.3:latest", "llama3.2:3b", "llama3.1:70b", "llama3.2-vision", "llama3.1:70b", "codellama"]


# Define multiple prompts
PROMPTS = [
#    "Write a 100-word essay on the history and future of artificial intelligence. Include milestones, ethical implications, and the impact on industries such as healthcare, education, and transportation.",
#    "Explain the ethical challenges posed by artificial intelligence in 100 words.",
#    "Create a detailed guide for deploying AI models in cloud environments, including challenges and solutions (100 words).",



"""
You are a security analyst tasked with remediating vulnerabilities reported by a vuln scanner on your network.
You need to write a detailed remediation playbook for [CVE-2024-9313], which affects type of device [DEVICE_TYPE_HERE] running operating system [OPERATING_SYSTEM_HERE] OS version [OS_VERSION_HERE].
The CVE description highlights the root cause as [VULNERABILITY_DESCRIPTION].

Use the following workflows to generate instructions:

Workflow 1: Repository-Based Package Update
- Determine if the vulnerability can be addressed using the system’s current package manager and repositories.
- If repositories require updates or reconfiguration, provide instructions for identifying missing updates, adding new repositories, and updating repository configurations.
- Consider package managers such as apt, yum, or dnf and tailor examples to the specific OS and version.
- Ensure steps include commands, file editing instructions, and verification procedures.

Workflow 2: Manual Package Installation or Source Compilation
- If no package update is available in the repositories, outline steps to manually download and install the package or source code from a trusted source.
- Include prerequisites (e.g., build tools, dependency checks) for the operating system.
- Provide examples for compiling source code (make, gcc, etc.), running installation scripts, or using package managers (dpkg, rpm).
- Include validation steps post-installation.

Output Structure:
- Systematic steps with labeled sections for each workflow.
- Include sample commands, repository changes, and advice specific to the operating system, device type, and application type.
- Emphasize pre-remediation checks, backups, and validation steps post-remediation.
"""





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

# Data storage for visualization
word_counts = {model: [] for model in MODELS}
time_taken = {model: [] for model in MODELS}

# Batch process prompts and models
for model in MODELS:
    sanitized_model = sanitize_filename(model)  # Sanitize model name for file paths
    print("\n" + "=" * 80)  # CLI Separator for readability
    print(f"🏆  **Processing Model:** {model.upper()}")  # Bold-like Model Name
    print("=" * 80)

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
                word_counts[model].append(actual_word_count)
                time_taken[model].append(total_time)

                # Save formatted output
                with open(formatted_file, "w") as f_formatted:
                    f_formatted.write(f"Version: {VERSION}\n")
                    f_formatted.write(f"Timestamp: {TIMESTAMP}\n")
                    f_formatted.write(f"Model: {model}\n")
                    f_formatted.write(f"Prompt {idx+1}:\n{prompt}\n")
                    f_formatted.write(f"Actual Word Count: {actual_word_count}\n")
                    f_formatted.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
                    f_formatted.write(formatted)

                # Save raw output
                with open(raw_file, "w") as f_raw:
                    f_raw.write(f"Version: {VERSION}\n")
                    f_raw.write(f"Timestamp: {TIMESTAMP}\n")
                    f_raw.write(f"Model: {model}\n")
                    f_raw.write(f"Prompt {idx+1}:\n{prompt}\n")
                    f_raw.write(f"Actual Word Count: {actual_word_count}\n")
                    f_raw.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
                    f_raw.write("\n".join(raw))

                # Print CLI Summary
                print(f"\n📌 **Prompt {idx+1} Results:**")
                print(f"   ✅ Actual Word Count: {actual_word_count}")
                print(f"   ⏳ Total Time Taken: {total_time:.2f} seconds")
                print(f"   📂 Formatted Output: {formatted_file}")
                print(f"   📂 Raw Response: {raw_file}")
                print("-" * 80)  # Separator between prompts
            except Exception as e:
                print(f"Error writing files for Model: {model}, Prompt {idx+1}: {e}")
        else:
            print(f"❌ Error for Model: {model}, Prompt {idx+1}: Response was empty or invalid.")

# Create Charts Directory
charts_dir = f"./outputs/{VERSION}/charts"
os.makedirs(charts_dir, exist_ok=True)

# Generate visualization
x = np.arange(len(PROMPTS))  # Label locations
width = 0.2  # Bar width

# Plot word count comparison
fig, ax = plt.subplots(figsize=(10, 6))
for i, model in enumerate(MODELS):
    ax.bar(x + (i - 1) * width, word_counts[model], width, label=f"{model} (Words)")

ax.set_xlabel("Prompts")
ax.set_ylabel("Word Count")
ax.set_title("Word Count Comparison Across Models")
ax.set_xticks(x)
ax.set_xticklabels(PROMPTS)
ax.legend()
plt.xticks(rotation=0)
plt.grid(axis="y", linestyle="--", alpha=0.7)

# Save chart
word_count_chart_path = os.path.join(charts_dir, f"word_count_chart_{TIMESTAMP}.png")
plt.savefig(word_count_chart_path)
plt.close()

# Plot time taken comparison
fig, ax = plt.subplots(figsize=(10, 6))
for i, model in enumerate(MODELS):
    ax.bar(x + (i - 1) * width, time_taken[model], width, label=f"{model} (Time in s)")

ax.set_xlabel("Prompts")
ax.set_ylabel("Time Taken (seconds)")
ax.set_title("Time Taken Comparison Across Models")
ax.set_xticks(x)
ax.set_xticklabels(PROMPTS)
ax.legend()
plt.xticks(rotation=0)
plt.grid(axis="y", linestyle="--", alpha=0.7)

# Save chart
time_taken_chart_path = os.path.join(charts_dir, f"time_taken_chart_{TIMESTAMP}.png")
plt.savefig(time_taken_chart_path)
plt.close()

# CLI Confirmation
print("\n📊 **Charts Generated:**")
print(f"   📈 Word Count Chart: {word_count_chart_path}")
print(f"   ⏳ Time Taken Chart: {time_taken_chart_path}")
print("=" * 80)
