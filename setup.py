"""
Setup script for clotho.
"""
import pathlib

from pkg_resources import parse_requirements
from setuptools import find_packages, setup

with pathlib.Path("requirements.txt").open() as requirements_txt:
    install_requires = [
        str(requirement) for requirement in parse_requirements(requirements_txt)
    ]

with pathlib.Path("dev-requirements.txt").open() as dev_requirements_txt:
    install_requires += [
        str(requirement) for requirement in parse_requirements(dev_requirements_txt)
    ]

setup(
    name="shanghai_project",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={
        "": "src",
    },
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
