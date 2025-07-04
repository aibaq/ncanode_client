from glob import glob
from os.path import basename
from os.path import splitext

from setuptools import find_packages, setup


classifiers = """
Development Status :: 1 - Alpha
Intended Audience :: Developers
License :: OSI Approved :: MIT License,
Operating System :: OS Independent
Programming Language :: Python
Programming Language :: Python :: 3.8
Programming Language :: Python :: 3.9
Programming Language :: Python :: 3.10
Programming Language :: Python :: 3.11
Programming Language :: Python :: 3.12
Topic :: Software Development :: Libraries :: Python Modules
"""

classifier_list = [c for c in classifiers.split("\n") if c]


setup(
    name="ncanode_client",
    version="1.0.7",
    author="Aibek Prenov",
    description="NCANode python client",
    url="https://github.com/aibaq/ncanode_client",
    packages=find_packages(exclude=("tests*",)),
    py_modules=[splitext(basename(path))[0] for path in glob("./**/*.py")],
    install_requires=[
        "requests>=2.31.0",
    ],
    classifiers=classifier_list,
    setup_requires=["pytest-runner"],
    tests_require=["tox", "pytest", "pytest-cov", "coverage"],
    include_package_data=True,
    python_requires=">=3.9",
    extras_require={},
)
