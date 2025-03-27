
# OverReacher - A Convenient CORS Scanner

![Screenshot](https://raw.githubusercontent.com/Zipnx/OverReacher/master/screenshot.png)

OverReacher is a security research tool, meant to scan and find CORS misconfiguration vulnerabilities.

Made this tool based on functionality from [Corsy](https://github.com/s0md3v/Corsy)

## Getting Started

### Pipx install

OverReacher can be easily installed using:
```
pipx install overreacher
```

Afterwards you can check the usage with:
```
overreacher.py -h
```

### Pip install

A normal pip install also works:
```
pip install overreacher
```

But, unless it's a global install, which is not recommended, you need to do additional setup on your own

### Manual install

Instead of installing the package using pip or pipx, OverReacher can be setup manually.
Just git clone the repo and then do the following:

Setup a virtual environment using the tool you prefer (venv in this case), and activate it
```
python3 -m venv ./venv
source venv/bin/activate
```

Then install the base requirements
```
pip install -r requirements.txt
```

Afterwards you can run overreacher in the following ways:
```
python3 -m overreacher
```

Or through the run script, which you can alias or symlink to your liking:
```
chmod +x ./run
./run -h
```

NOTE: To run you still need to use the virtual environments python interpreter

## Configuration

OverReacher is made to be easily customizable. This is incredibly helpful in BugBounty, where you might say, want to customize headers/cookies depending on the target.
(eg. Setting a hackerone header, which some programs require)

In addition to configuration in the config.ini file, you can also customize attacks and add your own in the attacks.json file.

To make a new configuration, simply run
```
overreacher --make-config
```

This will make a local .overreacher directory which the tool will automatically be setup to use.
If the directory already exists, it will be set as the configuration of the tool with no additional changes.

In this fashion you can change configurations depending on your needs and projects, and reset to normal with:
```
overreacher --reset-config
```


## Usage

An attack can be tested against a certain url or a comma separated list of urls as such:

`
overreacher -u https://example.com/,https://google.com/
`

Alternatively the url's can be loaded from a file

`
overreacher.py -i [FILE]
`

Or piped through stdin

`
cat exampleurlfile.txt | overreacher 
`

## TODO:
In [TODO.md](./TODO.md)
