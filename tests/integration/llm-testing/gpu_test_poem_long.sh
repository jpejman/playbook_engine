#!/bin/bash
# File: gpu_test_poem_long.sh
# Version: v.0.0.2

TEXT="Abandoning the computer dispensing with the airplane the train the rotary press gunpowder compass the printing press you have them scrapped the very subtle flower of your centuries of intelligence: the bloody man and his screams under concrete which the television placed ungarnished between the celery and the coq au vin on the evening’s tablecloth. Hello Lebanons hello Americas hi there and the East wasteland of atomic Russian philosophies is a prophecy is a future that is mostly here. I extract you all counting on you to extract me as well. I am still the master of my anamorphoses. To any taker I bequeath the benefit of real time as they say unacceptable to the slow identity of my flesh. With arms spread wide I make a hard turn back toward my bird which eats the worm of my esophagus which sustains itself on the grassy villi of my guts. I unpack all the species of myself. My horse body sleeps on my cliff body which reaches out to my ocean body."

sudo docker run --rm --gpus device=0 \
  -e COQUI_TOS_AGREED=1 \
  -e CUDA_VISIBLE_DEVICES=0 \
  -v ~/tts-output:/root/tts-output \
  coqui-tts:cuda124-working \
  --text "$TEXT" \
  --out_path /root/tts-output/test-gpu-poem.wav \
  --model_name tts_models/en/vctk/vits \
  --speaker_idx p225 \
  --use_cuda true
