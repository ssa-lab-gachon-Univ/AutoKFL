from setuptools import setup, find_packages

packages = find_packages(include=['autokfl', 'autokfl.*'])

setup(
    name='autokfl',
    version='0.1.0',
    packages=packages,
    install_requires=[
        'pexpect',
        'requests',
        'langgraph',
        'langchain-anthropic',
        'langchain-openai',
        'langchain-google-genai',
        'python-dotenv',
        'pydantic',
        'libclang'
    ],
)