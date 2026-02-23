#!/usr/bin/env python3
"""运行 Level2_control 测试"""
import os
import sys
import subprocess


def main():
    test_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("=" * 60)
    print("Running Level2_control Tests")
    print("=" * 60)
    
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "test_control.py", "-v", "-s"],
        cwd=test_dir
    )
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())