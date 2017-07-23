# DNS Proxy (DNS64 and filter)

This is a DNS Proxy Server to filter out some DNS traffic and it is able to do DNS64 for NAT64 setups.
It supports differend modules which are loaded if they are stored in the `modules` directory.

## Modules
If the module raises an exception in the intitializer, it will not be loaded (for example if the config does not exist).
If the module is successfully loaded, the `process` method of the Object is called on each request
if the processing is not stopped by another module (for example the request has been blocked).

