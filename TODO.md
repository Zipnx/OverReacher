
# TODO: 

## Inputs:
- [x] Input for 1 or more targets separated by commas
- [x] Input for a file containing a list of targets
- [x] If non of the above, read from stdin
- [x] Input for number of threads to use
- [x] Input for a path for an output file
- [x] Input for output type, TXT/JSON
- [x] Input for HTTP Header addition
- [ ] Input for limiting volume of requests per second

## Functionality:
- [x] Check for wildcard,suffix,prefix,etc...
- [x] Check different HTTP methods
- [ ] Add custom headers to requests
- [x] Multithreading
- [ ] Multiple save types
- [ ] Change the attack result functionality ffs
- [ ] EXAMPLE: If a host returns allow origin for arbitrary data, no need to continue scanning other attacks

## Eye Candy (using rich):
- [x] Progress bar
- [x] Display vulnerable stuff, obvs
- [x] Gotta do ASCII art (banner is more than enough)
- [ ] Possibly a minimal mode, also --no-color param and env reading
- [ ] Cluster results to a easily viewable format

# Bugs:
- [ ] The null origin sends "http://"
- [ ] Verify the scan output json schema

That attack setup shit was overengineers af, will prob delete everything and redo the scanning
