
# TODO: 

## Inputs:
- [x] Input for limiting volume of requests per second
- [x] Instead of executing an attack, parse another attack's output JSON
- [x] Set a proxy to use
- [x] Request Timeout setting
- [ ] Ignore where ACAC is false and add option to track it

## Functionality:
- [x] Make the attacks customizable again, this new system is way more appropriate for it
- [ ] A config file in the proj directory that sets default options
- [ ] Maybe an option to keep track of the last scan results (in config)
- [x] Forgot the HTTP headers at the arg parsing
- [ ] Attack loading validation
- [ ] More options for the attack process, allowing for more funky payloads
- [ ] Also add in the attacks a way to customize based on the result

## Bugs:
- [x] When a host always returns ACAO null, its labeled as a 3rd Party
- [ ] Attacks should be loaded from the base path of the script

