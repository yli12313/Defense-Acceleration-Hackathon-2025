#!/bin/bash

export HF_TOKEN=HF-TOKEN
export HF_HOME="/home/ubuntu/.cache/huggingface"
export MODEL_REPO=huihui-ai/Llama-3.3-70B-Instruct-abliterated

sudo docker run \
        --gpus all \
        --ipc=host \
        -v "${HF_HOME}":/root/.cache/huggingface \
        -p 8000:8000 \
        --env "HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}" \
        vllm/vllm-openai --model "${MODEL_REPO}" \
        --disable-log-requests \
        --tensor-parallel-size 8

