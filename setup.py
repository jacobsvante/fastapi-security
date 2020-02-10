from setuptools import find_packages, setup

install_requires = [
    "aiohttp",
    "fastapi",
    "pydantic",
    "pyjwt[crypto]",
]

extras_require = {
    "test": ["aioresponses", "black", "isort", "pytest >=4.0.0", "pytest-cov"],
}

extras_require["all"] = [
    dep for _, dependencies in extras_require.items() for dep in dependencies
]

setup(
    name="fastapi-security",
    version="0.1.0",
    description="Authentication and authorization as dependencies in FastAPI.",
    url="https://github.com/jmagnusson/fastapi-security",
    autho="Jacob Magnusson",
    author_email="m@jacobian.se",
    license="MIT",
    packages=find_packages(".", include=["fastapi_security"]),
    python_requires=">=3.6",
    install_requires=install_requires,
    extras_require=extras_require,
    classifiers=[
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development",
        "Typing :: Typed",
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Web Environment",
        "Framework :: AsyncIO",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
