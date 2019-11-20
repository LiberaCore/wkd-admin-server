import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="wkd-admin", # Replace with your own username
    version="1.0.0",
    author="liberacore",
    author_email="info@liberacore.org",
    description="HTTP API for managing public OpenPGP keys in a Web Key Directory",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/liberacore/wkd-admin",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPLv3 License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
          'flask',
          'flask-restplus',
          'Flask-Limiter',
          'python-gnupg'
      ],
    python_requires='>=3.6',
)
