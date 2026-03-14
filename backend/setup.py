from setuptools import setup, find_namespace_packages

setup(
    name="aida-audit",
    version="0.1.0",
    packages=find_namespace_packages(include=["aida_audit*"]),
    install_requires=[
        "fastapi>=0.95,<1.0",
        "uvicorn>=0.22,<0.41",
        "h11",
        "rich",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "aida-audit=aida_audit.cli:main",
        ],
    },
    package_data={
        "aida_audit": [
            "static/**/*",
            "static/*",
            "ghidra_export/**/*",
            "ghidra_export/*",
            "skills/**/*",
            "skills/*",
            "templates/**/*",
            "templates/*",
        ],
    },
    include_package_data=True,
    description="AIDA CLI Tool",
    author="User",
)
