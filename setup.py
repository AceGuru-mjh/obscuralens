"""
ObscuraLens - Advanced OSINT Tool
Setup script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="obscuralens",
    version="1.0.0",
    author="AceGuru-mjh",
    description="Multi-source OSINT console for IPs, phone numbers, usernames, and emails",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AceGuru-mjh/ObscuraLens",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "obscuralens=obscuralens.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
