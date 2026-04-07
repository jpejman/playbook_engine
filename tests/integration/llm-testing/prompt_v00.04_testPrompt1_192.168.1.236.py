import requests
import json
from datetime import datetime
import time

# Version number and timestamp
VERSION = "v00.04"
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")  # Format: YYYY-MM-DD_HH-MM-SS

# API Configuration
API_ENDPOINT = "http://192.168.1.38:11434/api/generate"
API_ENDPOINT = "http://192.168.1.221:11434/api/generate"
#MODEL_NAME = "llama3.1:70b"
#MODEL_NAME = "llama3.3:latest"
#MODEL_NAME = "llama3.2:3b"
MODEL_NAME = "llama3.1:latest"
#MODEL_NAME = "codellama"

# Define the prompt
PROMPT = """
"You are a security analyst tasked with remediating vulnerabilities reported by a vulnerability scanner on your network.
Write a detailed remediation playbook for **[CVE-2024-9313]**, which affects **[LINUX]** running **[UBUNTU]** version **[OS_VERSION]**.
The CVE description highlights the root cause as: *Authd PAM module before version 0.3.5 can allow broker-managed users to impersonate
any other user managed by the same broker and perform any PAM operation with it, including authenticating as them.

Make the response as close to 500 words a possible"
"""

# Function to calculate word count
def word_count(text):
    return len(text.split())

# Function to send a prompt and handle streaming responses
def generate_remediation_guide(prompt, api_url, model):
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": model,
        "prompt": prompt
    }

    raw_response = []  # To store raw JSON lines
    formatted_response = ""  # To store concatenated 'response' fields

    start_time = time.time()  # Record the start time

    try:
        # Open a streaming connection to the API
        with requests.post(api_url, headers=headers, json=payload, stream=True) as response:
            response.raise_for_status()

            # Process the streaming chunks
            for line in response.iter_lines():
                if line:  # Skip empty lines
                    line = line.decode('utf-8')  # Decode bytes to string
                    raw_response.append(line)  # Store the raw line
                    try:
                        # Parse each line as JSON and extract the 'response' field
                        json_line = json.loads(line)
                        if "response" in json_line:
                            formatted_response += json_line["response"]
                    except json.JSONDecodeError:
                        print(f"Warning: Unable to parse line: {line}")

        end_time = time.time()  # Record the end time
        total_time = end_time - start_time  # Calculate the total time taken

        # Return both raw and formatted responses, along with the total time taken
        return formatted_response, raw_response, total_time
    except requests.exceptions.RequestException as e:
        return f"Error: {e}", None, 0

# Generate the response
formatted, raw, total_time = generate_remediation_guide(PROMPT, API_ENDPOINT, MODEL_NAME)

# File names with version and timestamp
formatted_file = f"formatted_output_{VERSION}_{TIMESTAMP}.txt"
raw_file = f"raw_output_{VERSION}_{TIMESTAMP}.txt"

# Save the formatted and raw responses to separate files
if formatted and raw:
    total_words = word_count(formatted)  # Calculate word count
    
    # Write to formatted output file
    with open(formatted_file, "w") as f_formatted:
        f_formatted.write(f"Total Words: {total_words}\n")
        f_formatted.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
        f_formatted.write(formatted)  # Write the formatted response

    # Write to raw output file
    with open(raw_file, "w") as f_raw:
        f_raw.write(f"Total Words: {total_words}\n")
        f_raw.write(f"Total Time Taken: {total_time:.2f} seconds\n\n")
        f_raw.write("\n".join(raw) + "\n")  # Write raw JSON lines

# Print outputs and file locations
if "Error:" in formatted:
    print(formatted)  # Print the error if any
else:
    print("\n--- Formatted Output ---")
    print(formatted)  # Print the formatted response
    print(f"\nFormatted output saved to: {formatted_file}")

    print("\n--- Raw Response ---")
    print("\n".join(raw))  # Print the raw JSON response
    print(f"\nRaw response saved to: {raw_file}")
