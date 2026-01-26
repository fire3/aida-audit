from setuptools import setup, find_packages

setup(
    name="aida-cli",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.95,<1.0",
        "uvicorn>=0.22,<0.41",
        "h11",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "aida-cli=aida_cli.cli:main",
        ],
    },
    package_data={
        "aida_cli": [
            "static/**/*",
            "static/*",
            "ghidra_export/**/*",
            "ghidra_export/*",
            "skills/**/*",
            "skills/*",
        ],
    },
    include_package_data=True,
    description="AIDA CLI Tool",
    author="User",
)
