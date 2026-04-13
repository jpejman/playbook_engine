#!/bin/bash
# Script: gpu_test_long_text.sh
# Version: v.0.0.1

# Coqui GPU test with longer inference time
TEXT="This is a longer sentence designed to engage the GPU and memory during synthesis. It should be long enough to allow the model to load completely into memory and activate CUDA operations during execution. We are testing to ensure the system uses the NVIDIA M40 GPU and does not fall back to CPU rendering, which is significantly slower and not what we want for large-scale batch inference. This test will help determine if the Docker image is properly configured for GPU-accelerated Torch inference using the Coqui TTS model."
MODEL_NAME="tts_models/en/vctk/vits"
OUTPUT_FILE="/root/tts-output/long_gpu_test.wav"

sudo docker run --rm --gpus device=0 \
  -e COQUI_TOS_AGREED=1 \
  -e CUDA_VISIBLE_DEVICES=0 \
  -v ~/tts-output:/root/tts-output \
  coqui-tts:cuda12x \
  --text "$TEXT" \
  --out_path "$OUTPUT_FILE" \
  --model_name "$MODEL_NAME" \
  --speaker_idx p225 \
  --use_cuda true
