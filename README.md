# TLDBuster

TLDBuster is a tool designed to discover domain variants across different Top-Level Domains (TLDs). By providing a base domain, TLDBuster checks for the existence of that domain with various TLDs and gathers relevant information like IP addresses and WHOIS data.

Installation

    git clone https://github.com/r3dcl1ff/TLDBuster.git

    cd TLDBuster

    go build tldbuster.go

    cp tldbuster /usr/local/bin


Options

    -d string
    Domain to test against (single target).

    -dL string
    List of domains to test (e.g., domains.txt).

    -s
    Silent output mode.

    -v
    Verbose output mode.

    -o string
    Output file (.json or .txt).

    -debug
    Enable debugging mode.

Examples

    #Test a single domain:

    tldbuster -d example.com

    #Test multiple domains from a file:

    tldbuster -dL domains.txt

    #Save output to a JSON file:
    
    tldbuster -d example.com -o results.json


Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss changes.

License

This project is licensed under the MIT License.
