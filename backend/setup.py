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
        "aida_mcp": ["static/**/*", "static/*"],
    },
    data_files=[
        ("ghidra_export", ["ghidra_export/AidaExport.java"]),
    ],
    include_package_data=True,
    description="AIDA MCP Tool",
    author="User",
)
