from setuptools import setup, find_packages

setup(
    name='common_lib',
    version='0.1',
    author='Orik',
    packages=find_packages(),
    install_requires=[
        'flask==1.1.1'
    ]
)
