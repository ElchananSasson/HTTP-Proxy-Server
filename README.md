## Description
The proxy server receives an HTTP request from the client and conducts predefined checks on it. If the request is deemed legal, it first searches for the requested file in its local filesystem. If the file is stored locally, the proxy creates an HTTP response and returns the file. Otherwise, it forwards the request to the appropriate web server and sends the response back to the client. If the request is deemed illegal, it sends an error response to the client without forwarding anything to the server. The proxy server only supports IPv4 connections.

## Files

- `proxyServer.c`: Contains the main program for the simple HTTP Proxy.
- `threadpool.c`: Includes the code for the thread pool section, responsible for handling the threads.
- `README`: Provides a detailed description of the proxy server.

## Remarks

- **Compilation**: Use the following command to compile the program: `gcc -Wall -Wextra -Wvla proxyServer.c threadpool.c -o proxy -lpthread`.
- **Execution**: After compilation, execute the program using `./proxy`.
