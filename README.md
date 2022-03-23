-d  --domain:           this option is used in conjunction with others such as -t, is used to pass the domain in which a desired action will be performed:-d domain.
com<br>
-t  --type:             Use this option to select one DNS register and doing a consult: -t CNAME, -t MX,TXT,HINFO<br>
-r  --resolve:          Use this option to do a resolve domain for IP: -r domain.com<br>
-rv --reverseresolve:   Use this option to do a reverse resolve IP for domain: -rv 192.168.0.1<br>
-z  --zonetransfer      Use this option to do one zone transfer: -z domain.com,ns1.domain.com -z domain.com,ns1.domain.com,ns2.domain.com,ns3.domain.com<br>
-s  --scan              Use this option to be able to do a full scan on the domain, with contultas in DNS records and also zone transfer: -s domain.com<br>
-w  --whois             Use this option to consult a WHOIS: -w domain.com<br>
-o  --output            Use this option to generate a file with a output the query: -o nameOfFile.txt<br>