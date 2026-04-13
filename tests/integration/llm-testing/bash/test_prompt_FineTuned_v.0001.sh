#!/bin/bash

# Get the script name without the .sh extension
SCRIPT_NAME=$(basename "$0" .sh)

# Generate a timestamp for unique file naming
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Set the output file names
OUTPUT_FILE="${SCRIPT_NAME}_output_${TIMESTAMP}.txt"
PLAIN_OUTPUT_FILE="plain_${SCRIPT_NAME}_output_${TIMESTAMP}.txt"

# Measure the start time
START_TIME=$(date +%s)

# Create a temporary file for the full API response
TEMP_FILE=$(mktemp)

# Ollama API configuration
OLLAMA_HOST="http://192.168.1.237:11434"
OLLAMA_ENDPOINT="${OLLAMA_HOST}/api/generate"
MODEL="llama3.1:70b"
PROMPT="1. Write a 5000 word essay on the history of AI.\n2. Put word count after each paragraph.\n3. Predict what the future of AI looks like.\n4. Closing remarks."

# Print a status message
echo "[INFO] Starting the Ollama inferencing script..."
echo "[INFO] Model: $MODEL"
echo "[INFO] Endpoint: $OLLAMA_ENDPOINT"
echo "[INFO] Timestamp: $TIMESTAMP"

# Use CURL to send a POST request to the Ollama API
echo "[INFO] Sending the request to the API..."
curl -s "$OLLAMA_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"model\": \"$MODEL\", \"prompt\": \"$PROMPT\"}" \
  -o "$TEMP_FILE"

# Measure the end time for generation
END_TIME=$(date +%s)
TIME_TAKEN=$((END_TIME - START_TIME))

# Print a status message
echo "[INFO] API request completed in ${TIME_TAKEN} seconds. Processing the response..."

# Check if the API response is valid
if jq -e '.' "$TEMP_FILE" >/dev/null 2>&1; then
  # Print a status message
  echo "[INFO] Extracting plain text response from the API output..."
  
  # Extract the plain response, clean up unwanted characters, and format it
  jq -r '.response' "$TEMP_FILE" | tr -d '$' | sed ':a;N;$!ba;s/\n\([^\n]\)/ \1/g' > "$PLAIN_OUTPUT_FILE"

  # Prepend the "Generation completed" and time taken message at the top
  {
    echo "Generation completed in ${TIME_TAKEN} seconds."
    echo
    cat "$PLAIN_OUTPUT_FILE"
  } > "$OUTPUT_FILE"

  # Append the full raw API response below the plain text response
  {
    echo -e "\n\n--- Full API Response ---\n"
    cat "$TEMP_FILE"
  } >> "$OUTPUT_FILE"

  # Print a success message
  echo "[INFO] Response processing completed successfully!"
  echo "[INFO] Output saved to ${OUTPUT_FILE}"
else
  # Print an error message if the response is invalid
  echo "[ERROR] Invalid API response. Check the temporary file at $TEMP_FILE."
fi

# Clean up the temporary file
rm -f "$TEMP_FILE"

# Print a final message
echo "[INFO] Script execution completed."
