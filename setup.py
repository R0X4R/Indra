from setuptools import setup, find_packages

setup(
    name="indra",
    version="1.0.0",
    description="A versatile network scanning and vulnerability assessment tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Eshan",
    author_email="r0x4r@yahoo.com",
    url="https://github.com/R0X4R/Indra",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "requests",
        "Wappalyzer",
        "argparse"
    ],
    entry_points={
        "console_scripts": [
            "indra = indra.indra:run_scan"
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
