from setuptools import setup, find_packages

setup(
    name="indraa",
    version="2.0.1",
    description="Indraa is a powerful, versatile, and user-friendly Python-based network scanning and vulnerability assessment tool.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Eshan Singh",
    author_email="r0x4r@yahoo.com",
    url="https://github.com/R0X4R/indraa",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-Wappalyzer",
        "argparse"
    ],
    entry_points={
        "console_scripts": [
            "indraa = indraa.main:run_scan"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    python_requires=">=3.6",
)
