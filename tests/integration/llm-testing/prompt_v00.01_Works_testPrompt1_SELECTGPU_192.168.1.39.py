import requests
import json

# API Configuration
#API_ENDPOINT = "http://192.168.1.38:11434/api/generate"
#API_ENDPOINT = "http://192.168.1.100:11434/api/generate"
#MODEL_NAME = "llama3.1:70b"
#MODEL_NAME = "llama3.3:latest"
#MODEL_NAME = "llama3.2:1b"
MODEL_NAME = "llama3.1:latest"
#MODEL_NAME = "codellama"

# Define the prompt
PROMPT = """
"You are a security analyst tasked with remediating vulnerabilities reported by a vulnerability scanner on your network.
Write a detailed remediation playbook for **[CVE-2024-9313]**, which affects **[LINUX]** running **[UBUNTU]** version **[OS_VERSION]**.
The CVE description highlights the root cause as: *Authd PAM module before version 0.3.5 can allow broker-managed users to impersonate 
any other user managed by the same broker and perform any PAM operation with it, including authenticating as them."
"""

# Function to send a prompt and handle streaming responses
def generate_remediation_guide(prompt, api_url, model):
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": model,
        "prompt": prompt
    }

    raw_response = []  # To store raw JSON lines
    formatted_response = ""  # To store concatenated 'response' fields

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

            # Return both raw and formatted responses
            return formatted_response, "\n".join(raw_response)
    except requests.exceptions.RequestException as e:
        return f"Error: {e}", None

# Generate the response
formatted, raw = generate_remediation_guide(PROMPT, API_ENDPOINT, MODEL_NAME)

# Output the formatted and raw responses
if "Error:" in formatted:
    print(formatted)  # Print the error if any
else:
    print("\n--- Formatted Output ---")
    print(formatted)  # Print the formatted response
    print("\n--- Raw Response ---")
    print(raw)  # Print the raw JSON response
