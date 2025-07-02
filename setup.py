from setuptools import setup, find_packages

# Read the contents of your requirements.txt file
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='webmer',
    version='2.0.0',
    author='Anas Erami',
    author_email='anaserami17@gmail.com', 
    description='An Advanced, AI-Driven Offensive Security Platform for Web Applications & APIs.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/anas-2003/webmer', 
    packages=find_packages(),
    py_modules=['webmer'], 
    install_requires=requirements,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security',
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'webmer = webmer:entry_point',
        ],
    },
)
