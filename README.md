
# OverReacher - A Convient CORS Scanner

OverReacher is a security research tool, meant to scan and find CORS misconfiguration vulnerabilities.

Made this tool based on functionality from [Corsy](https://github.com/s0md3v/Corsy)

## Getting Started

First install the requirements by running

`
pip install -r requirements.txt
`

Then you can view the run options with

```
python3 overreacher.py -h

or 

python3 overreacher.py --help
```

## Usage

An attack can be tested again a certain url or a comma separated list of urls as such:

`
python3 overreacher.py -u https://example.com/,https://google.com/
`

Alternatively the url's can be loaded from a file

`
python3 overreacher.py -i [FILE]
`

Or piped through stdin

`
cat exampleurlfile.txt | python3 overreacher.py 
`
