import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="zepu1chr3",
    version="0.0.2",
    author="CYB3RMX",
    author_email="cyb3rmx0@gmail.com",
    description="A Radare2 based Python module for Binary Analysis and Reverse Engineering.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CYB3RMX/Zepu1chr3",
    project_urls={
        "Bug Tracker": "https://github.com/CYB3RMX/Zepu1chr3/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)