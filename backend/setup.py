from setuptools import setup, find_packages

setup(
    name="aida-mcp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
    ],
    entry_points={
        "console_scripts": [
            "aida-mcp=aida_mcp.cli:main",
        ],
    },
    package_data={
        "aida_mcp": ["static/**/*", "static/*", "ghidra_export/**/*", "ghidra_export/*"],
    },
    include_package_data=True,
    description="AIDA MCP Tool",
    author="User",
)
