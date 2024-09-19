
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
- [ ] Cluster results to a easily viewable format

## Functionality:
- [x] Check for wildcard,suffix,prefix,etc...
- [x] Check different HTTP methods
- [ ] Add custom headers to requests
- [x] Multithreading
- [ ] Multiple save types

## Eye Candy (using rich):
- [x] Progress bar
- [x] Display vulnerable stuff, obvs
- [x] Gotta do ASCII art (banner is more than enough)
- [ ] Possibly a minimal mode, also --no-color param and env reading

# Additional:
- [ ] Make it so if a host errors, it work be retried by other attacks or currently running threads
