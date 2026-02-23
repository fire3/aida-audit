#!/usr/bin/env python3
"""
统一测试运行脚本
运行所有级别的测试用例
"""
import os
import sys
import subprocess


def run_level(level_name, level_dir):
    """运行指定级别的测试"""
    print(f"\n{'=' * 60}")
    print(f"Running {level_name}")
    print("=" * 60)
    
    run_script = os.path.join(level_dir, "run_test.py")
    if os.path.exists(run_script):
        result = subprocess.run([sys.executable, run_script])
    else:
        test_file = os.path.join(level_dir, f"test_{level_name.split('_')[1]}.py".lower().replace("level1_", "add").replace("level2_", "control").replace("level3_", "full") + ".py")
        if os.path.exists(test_file):
            result = subprocess.run([
                sys.executable, "-m", "pytest", 
                "-v", "-s",
                test_file
            ], cwd=level_dir)
        else:
            print(f"No test file found in {level_dir}")
            return 1
    return result.returncode


def main():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("=" * 60)
    print("AIDA EMU Integration Test Suite")
    print("=" * 60)
    
    levels = [
        ("Level1 Basic (add/sub/mul)", "level1_basic"),
        ("Level2 Control (max/factorial)", "level2_control"),
        ("Level3 Full (sum_array/str_len)", "level3_full"),
        ("Level4 Hooks (libc hooks)", "level4_hooks"),
    ]
    
    results = {}
    for name, level_dir in levels:
        level_path = os.path.join(tests_dir, level_dir)
        if os.path.exists(level_path):
            ret = run_level(name, level_path)
            results[name] = "PASS" if ret == 0 else "FAIL"
        else:
            results[name] = "SKIP"
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    for name, status in results.items():
        print(f"  {name}: {status}")
    
    all_passed = all(s == "PASS" for s in results.values())
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())