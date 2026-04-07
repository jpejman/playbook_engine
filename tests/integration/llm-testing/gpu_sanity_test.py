import torch
import sys

def test_gpu():
    print(f"\n🔍 Python: {sys.executable}")
    print(f"🔢 torch version: {torch.__version__}")
    print(f"🧠 CUDA available: {torch.cuda.is_available()}")
    print(f"📊 GPU count: {torch.cuda.device_count()}")

    for i in range(torch.cuda.device_count()):
        try:
            device_name = torch.cuda.get_device_name(i)
            _ = torch.zeros(1).to(f"cuda:{i}")  # allocate on GPU
            print(f"✅ GPU {i}: {device_name} is working and memory allocatable.")
        except Exception as e:
            print(f"❌ GPU {i} error: {e}")

if __name__ == "__main__":
    test_gpu()
