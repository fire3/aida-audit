from setuptools import setup, find_packages

setup(
    name="ida-mcp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
    ],
    entry_points={
        "console_scripts": [
            "ida-mcp=ida_mcp.cli:main",
        ],
    },
    include_package_data=True,
    description="IDA Project MCP Tool",
    author="User",
)
