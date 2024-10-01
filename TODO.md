
# TODO: 

## Inputs:
- [ ] Input for limiting volume of requests per second

## Functionality:
- [x] Check for wildcard,suffix,prefix,etc...
- [ ] [BUG] Checks for wildcard dont work rn, gonna check later
- [ ] Add custom headers to requests
- [x] Multithreading
- [ ] Multiple save types
- [x] Change the attack result functionality ffs
- [ ] [PRIORITY] EXAMPLE: If a host returns allow origin for arbitrary data, no need to continue scanning other attacks

## Eye Candy (using rich):
- [ ] Possibly a minimal mode, also --no-color param and env reading
- [ ] Cluster results to a easily viewable format

# Bugs:
- [x] The null origin sends "http://"
- [ ] Verify the scan output json schema

That attack setup shit was overengineers af, will prob delete everything and redo the scanning
^ Still trash code. should've prob written this in golang
