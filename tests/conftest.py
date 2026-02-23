import os
import sys
import pytest

# Add backend and test_support to path
backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")
test_support_dir = os.path.join(os.path.dirname(__file__), "test_support")

for p in [backend_dir, test_support_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(scope="session")
def test_root_dir():
    """测试根目录"""
    return os.path.dirname(__file__)


@pytest.fixture(scope="session")
def backend_dir():
    """backend 目录"""
    return os.path.join(os.path.dirname(__file__), "..", "backend", "aida_cli")


@pytest.fixture(scope="session")
def test_programs_dir():
    """测试程序源码目录"""
    return os.path.join(os.path.dirname(__file__), "programs")


@pytest.fixture
def compiler_cc():
    """C 编译器"""
    return "gcc"


@pytest.fixture
def compiler_cflags():
    """C 编译选项"""
    return "-O0 -g"


@pytest.fixture
def export_backend():
    """导出后端"""
    return "ida"