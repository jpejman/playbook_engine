import requests
import json

# API Configuration
#API_ENDPOINT = "http://192.168.1.38:11434/api/generate"
API_ENDPOINT = "http://10.0.0.100:11434/api/generate"
#API_ENDPOINT = "http://192.168.1.39:11434/api/generate"
#API_ENDPOINT = "http://192.168.1.41:11434/api/generate"
#API_ENDPOINT = "http://192.168.1.241:11434/api/generate"
#API_ENDPOINT = "http://192.168.1.241:11434/api/generate"
#API_ENDPOINT = "http://10.0.0.106:11434/api/generate"
MODEL_NAME = "llama3.1:latest"
#MODEL_NAME = "llama3.1:70b"
#MODEL_NAME = "llama3.3:latest"
#MODEL_NAME = "llama3.2:3b"
#MODEL_NAME = "codellama"

# Define the prompt
PROMPT = """
"You are a security analyst that needs to remediate vulnerabilities that have been reported by a vuln scanner on your network.
You are tasked with writing a detailed remediation playbook for CVE CVE-2020-11716. 

The CVE description highlights the root cause as Panasonic P110, Eluga Z1 Pro, Eluga X1, and Eluga X1 Pro devices through 2020-04-10 have Insecure Permissions. NOTE: the vendor states that all affected products are at "End-of-software-support.".
Use the following workflows to generate instructions:

Workflow 1: Repository-Based Package Update
Determine if the vulnerability can be addressed using the system’s current package manager and repositories.
If repositories require updates or reconfiguration, provide instructions for identifying missing updates, adding new repositories, and updating repository configurations.
Consider package managers such as apt, yum, or dnf and tailor examples to the specific OS and version.
Ensure steps include commands, file editing instructions, and verification procedures.

Workflow 2: Manual Package Installation or Source Compilation
If no package update is available in the repositories, outline steps to manually download and install the package or source code from a trusted source.
Include prerequisites (e.g., build tools, dependency checks) for the operating system.
Provide examples for compiling source code (make, gcc, etc.), running installation scripts, or using package managers (dpkg, rpm).
Include validation steps post-installation.

Output Structure:
Systematic steps with labeled sections for each workflow.
Include sample commands, repository changes, and advice specific to the operating system, device type, and application type.
Emphasize pre-remediation checks, backups, and validation steps post-remediation."
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