
from setuptools import setup, find_packages

deps = '''attrs==24.2.0
certifi==2024.7.4
charset-normalizer==3.3.2
idna==3.7
markdown-it-py==3.0.0
mdurl==0.1.2
Pygments==2.18.0
referencing==0.35.1
requests==2.32.3
rich==13.7.1
urllib3==2.2.2'''

with open('README.md', 'r') as f:
    desc = f.read()

# TODOS:
# [ ] Check compatibility for python versions
# [ ] Data folder, also want it to be easily editable

setup(
    name        = 'OverReacher',
    version     = '1.0.0',
    description = 'A scanner for CORS misconfiguration vulnerabilities',
    author      = 'Zipnx',
    author_email= 'zipnx@protonmail.com',
    url         = 'https://github.com/Zipnx/OverReacher',
    scripts     = ['./overreacher/overreacher.py'],
    packages    = ['overreacher', 'overreacher.data'],
    license     = 'MIT',
    entry_points= {
        'console_scripts':[
            'overreacher = overreacher:main'
        ]
    },
    
    package_dir = {'': './'},
    package_data= {'overreacher': ['*.ini'], 'overreacher.data': ['*.ini', '*.json']},

    include_package_data = True,
    long_description = desc,
    long_description_content_type = 'text/markdown',

    install_requires = deps.split('\n'),
    classifiers = [
        "Programming Language :: Python",
    ],
)
