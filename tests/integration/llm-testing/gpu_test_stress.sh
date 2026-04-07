#!/bin/bash
# File: gpu_test_stress.sh
# Version: v.0.0.1

TEXT="This is an extended GPU synthesis test using the Coqui TTS system running on a Tesla M40 GPU with CUDA 12.4. The purpose of this test is to ensure the GPU is properly engaged during inference. We expect to see memory utilization above 1000 MB and a measurable GPU-Util percentage while this sentence is being processed. The GPU should handle the floating-point operations and deep learning inference rather than relying solely on CPU cores, which would defeat the performance benefits of CUDA acceleration. This test sentence is deliberately long to exceed typical inference thresholds and force CUDA to activate kernels over multiple batches."

sudo docker run --rm --gpus device=0 \
  -e COQUI_TOS_AGREED=1 \
  -e CUDA_VISIBLE_DEVICES=0 \
  -v ~/tts-output:/root/tts-output \
  coqui-tts:cuda124-working \
  --text "$TEXT" \
  --out_path /root/tts-output/test-gpu-long.wav \
  --model_name tts_models/en/vctk/vits \
  --speaker_idx p225 \
  --use_cuda true
