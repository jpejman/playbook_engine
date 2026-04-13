#keeps going to mixed cpu mode
import requests

# API Configuration
API_ENDPOINT = "http://10.0.0.100:11434/api/generate"
#API_ENDPOINT = "http://192.168.1.221:11434/api/generate"
#MODEL_NAME = "llama3.1:70b"
#MODEL_NAME = "llama3.3:latest"
#MODEL_NAME = "llama3.2:latest"
MODEL_NAME = "llama3.1:latest"
#MODEL_NAME = "codellama"

# Define the prompt
PROMPT = """
You are a security analyst tasked with remediating vulnerabilities reported by a vulnerability scanner on your network. 

Write a detailed remediation playbook for **[CVE-2024-9313]**, which affects **[LINUX]** running **[UBUNTU]** version **[OS_VERSION]**. The CVE description highlights the root cause as:

*Authd PAM module before version 0.3.5 can allow broker-managed users to impersonate any other user managed by the same broker and perform any PAM operation with it, including authenticating as them.*

### Workflows to Generate Instructions:

#### Workflow 1: Repository-Based Package Update
1. Determine if the vulnerability can be addressed using the system's current package manager and repositories.
2. If repositories require updates or reconfiguration:
   - Provide steps for identifying missing updates.
   - Add or reconfigure repositories.
   - Update the repository configurations.
3. Include package manager examples for tools like `apt`, `yum`, or `dnf` and tailor commands to the specific OS and version.
4. Provide instructions for:
   - Commands to execute.
   - Editing necessary files.
   - Verification procedures to confirm the update.

#### Workflow 2: Manual Package Installation or Source Compilation
1. If no package update is available in the repositories:
   - Outline steps to manually download and install the package or compile the source code from a trusted source.
   - Include prerequisites like build tools and dependency checks for the OS.
   - Provide detailed examples for:
     - Compiling source code (e.g., `make`, `gcc`).
     - Running installation scripts.
     - Using package managers (`dpkg`, `rpm`).
2. Include post-installation validation steps.

### Output Structure:
1. Systematic, step-by-step instructions with labeled sections for each workflow.
2. Include:
   - Sample commands.
   - Repository configuration changes.
   - Device and application-specific advice.
3. Emphasize:
   - Pre-remediation checks.
   - Backups.
   - Post-remediation validation steps.
"""

# Send the request to the API
def generate_remediation_guide(prompt, api_url, model):
    headers = {"Content-Type": "application/json"}
    payload = {
        "model": model,
        "prompt": prompt,
        "options": {
            "main_gpu": 0,  # Force usage of GPU 2
            "num_gpu": 1    # Use only one GPU
        }
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json().get("response", "No response received.")
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Generate the response
response = generate_remediation_guide(PROMPT, API_ENDPOINT, MODEL_NAME)

# Save the response to a file
output_file = "remediation_guide_output.txt"
with open(output_file, "w") as file:
    file.write(response)

# Print confirmation
print(f"Remediation guide saved to {output_file}")
