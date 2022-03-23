import argparse
import socket
import re
import subprocess
import os 

import dns.reversename
import dns.resolver


class Utils:
    def checkIp(addr):
        if re.match(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", addr):
            return True

        else:
            return False


class Resolvers:
    def resolve(domain):
        if Utils.checkIp(domain) == False:
            try:
                ip = socket.gethostbyname(str(domain))
                return ip

            except Exception(err):
                print("Error !")
                print(err)
        
        else:
            return False

    
    def reverseResolve(address):
        if Utils.checkIp(address):
            try:
                return str(dns.resolver.resolve(address, "PTR")[0])

            except dns.resolver.NXDOMAIN:
                return "haven't one a ptr domain register in the host, in this case please pass the domain name"

            except Exception(err):
                print("Error !")
                print(err)
                
        else:
            return False


class Consult:
    def search(domain, dnsRegisters):
        domainRegisters = {}

        if Resolvers.resolve(domain) != False:
            if len(dnsRegisters) == 0:
                print("Pls pass one DNS register to check using: -t or --type A or A")

            else:
                for register in dnsRegisters:
                    """
                    if register == "NS" or register == "CNAME" or register == "MX" or register == "PTR" or register == "HINFO" or register == "TXT":
                        try:
                            query = dns.resolver.resolve(domain, str(register))
                            domainRegisters[register] = query[0]

                        except dns.resolver.NoNameservers and dns.resolver.NoAnswer:
                            print(f"Don't exists the domain register: {register}")
                            continue
                    
                    else:
                        try:
                            query = dns.resolver.resolve(domain, str(register))

                            domainRegisters[register] = query[0]

                        except dns.resolver.NXDOMAIN:
                            print(f"Don't exists the domain register: {register}")
                            continue
                    """


                    if register == "NS":
                        nameservers = []

                        try:
                            query = dns.resolver.resolve(domain, register)
                        
                        except dns.resolver.NoNameservers:
                            #print(f"Don't exists the domain register: {register}")
                            continue
                        
                        except dns.resolver.NoAnswer:
                            continue

                        except dns.rdatatype.UnknownRdatatype:
                            continue
                        
                        for ns in query:
                            nameservers.append(ns)
                            domainRegisters[register] = nameservers

                        continue

                    elif register == "MX":
                        mailServers = []

                        try:
                            query = dns.resolver.resolve(domain, register)
                        
                        except dns.resolver.NoNameservers:
                            #print(f"Don't exists the domain register: {register}")
                            continue
                        
                        except dns.resolver.NoAnswer:
                            continue

                        except dns.rdatatype.UnknownRdatatype:
                            continue
                        
                        for mailServ in query:
                            mailServers.append(mailServ)
                            domainRegisters[register] = mailServers

                        continue

                    elif register == "TXT":
                        Text = []

                        try:
                            query = dns.resolver.resolve(domain, register)
                        
                        except dns.resolver.NoNameservers:
                            #print(f"Don't exists the domain register: {register}")
                            continue
                        
                        except dns.resolver.NoAnswer:
                            continue

                        except dns.rdatatype.UnknownRdatatype:
                            continue

                        for txt in query:
                            Text.append(txt)
                            domainRegisters[register] = Text

                        continue

                    else:
                        try:
                            query = dns.resolver.resolve(domain, register)
                            domainRegisters[register] = query[0]

                        except dns.resolver.NoNameservers:
                            #print(f"Don't exists the domain register: {register}")
                            continue
                        
                        except dns.resolver.NoAnswer:
                            continue

                        except dns.rdatatype.UnknownRdatatype:
                            continue

                        except dns.resolver.NXDOMAIN:
                            continue
                
                if len(domainRegisters) == 0:
                    return None

                else:
                    return domainRegisters

        else:
            return False

    """
    on my machine the zone transfer dns.query method did not work, if on 
    your machine it works, feel free to modify the script and implement 
    the functionality.
    
    """
    def zoneTransfer(domain, ns):
        output = subprocess.run(f"host -l {domain} {ns}", shell=True, capture_output=True)

        if "Transfer failed" in output.stdout.decode():
            print("not possible to do the zone transfer")
            return False

        else:
            return output

    
    def whois(domain):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("whois.iana.org", 43))    
            
        sock.send(bytes(f"{domain}\r\n", "ascii"))
        data = sock.recv(1024)

        whois = str(data.decode("UTF-8"))

        return whois
        
    def scan(domain):
        resolved = {}

        for reg in ["A", "AAAA","CNAME", "NS", "PTR", "MX", "TXT", "HINFO"]:
            try:
                answer = dns.resolver.resolve(domain, reg)

            except dns.resolver.NoNameservers:
                #print(f"Don't exists the domain register: {register}")
                continue
                    
            except dns.resolver.NoAnswer:
                continue

            except dns.rdatatype.UnknownRdatatype:
                continue

            except dns.resolver.NXDOMAIN:
                continue

            except dns.resolver.NoAnswer:
                continue

            except Exception as err:
                print(err)
                exit()

            else:
                if reg == "NS":
                    namserver = []

                    for ns in answer:
                        namserver.append(ns)

                    resolved[reg] = namserver

                elif reg == "MX":
                    mails = []

                    for mail in answer:
                        mails.append(mail)

                    resolved[reg] = mails

                elif reg == "TXT":
                    text = []

                    for txt in answer:
                        text.append(txt)

                    resolved[reg] = text
                        
                else:
                    resolved[reg] = answer[0]

                continue
        
        try:
            for ns in resolved["NS"]:
                zone = None
                output = subprocess.run(f"host -l {domain} {ns}", shell=True, capture_output=True)
 
                if "Transfer failed" in output.stdout.decode("UTF-8"):
                    continue

                else:
                    zone = output.stdout.decode("UTF-8") 
                
        

        except KeyError:
            print("please check your DNS server, maybe he is the problem")      
        
        whois = Consult.whois(domain)

        return resolved, zone, whois      
        


parser = argparse.ArgumentParser()

parser.add_argument("-d", "--domain", help="this option is used in conjunction with others such as -t, is used to pass the domain in which a desired action will be performed: -d domain.com")
parser.add_argument("-t", "--type", help="Use this option to select one DNS register and doing a consult: -t CNAME, -t MX,TXT,HINFO") 
parser.add_argument("-r", "--resolve", help="Use this option to do a resolve domain for IP")  
parser.add_argument("-rv", "--reverseresolve", help="Use this option to do a reverse resolve IP for domain")  
parser.add_argument("-z", "--zonetransfer", help="Use this option to do one zone transfer: -z domain.com,ns1.domain.com -z domain.com,ns1.domain.com,ns2.domain.com,ns3.domain.com")
parser.add_argument("-s", "--scan", help="Use this option to be able to do a full scan on the domain, with contultas in DNS records and also zone transfer: -s domain.com")
parser.add_argument("-w", "--whois", help="Use this option to consult a WHOIS")
parser.add_argument("-o", "--output", help="Use this option to generate a file with a output the query")

arguments = parser.parse_args()



def main(args):
    if args.domain:
        if args.resolve or args.reverseresolve or args.zonetransfer or args.scan or args.whois:
            print("You is using another more options, do can't use more options in same time, case you want execute one completo scan, use the option: -s or --scan")
            exit()

        else:
            if args.output:
                if args.output == "":
                    print("pls pass the name of file")

                else:
                    file = open(str(args.output), "a")

                    domain = args.domain 

                    if args.type:
                        if "," in args.type:
                            registers = args.type.split(',')

                        else:
                            registers = [args.type]
                        
                        response = Consult.search(domain, registers)

                        if response == None:
                            os.remove(str(args.output))
                            exit()

                        elif response == False:
                            print(f"Can't possible resolve the domain...")
                            file.close()
                            os.remove(str(args.output))
                            exit()
                        
                        else:
                            for reg in registers:
                                if reg == "NS":
                                    for ns in response["NS"]:
                                        print(f"[+] Register {reg}: {ns}")
                                        file.write(f"[+] Register {reg}: {ns}")

                                elif reg == "MX":
                                    for mails in response["MX"]:
                                        print(f"[+] Register {reg}: {mails}")
                                        file.write(f"[+] Register {reg}: {mails}")

                                elif reg == "TXT":
                                    for txt in response["TXT"]:
                                        print(f"[+] Register {reg}: {txt}")
                                        file.write(f"[+] Register {reg}: {txt}")

                                else:
                                    print(f"[+] Register {reg}: {response[reg]}")
                                    file.write(f"[+] Register {reg}: {response[reg]}")

                        file.close()

                    else: 
                        print("pls use option -t")
                        exit()

            else:
                domain = args.domain

                if args.type:
                    args.type.upper()

                    if "," in args.type:
                        registers = args.type.split(',')

                    else:
                        registers = [args.type]
                    
                    response = Consult.search(domain, registers)

                    if response == None:
                        exit()

                    elif response == False:
                        print(f"Can't possible resolve the domain...")
                        exit()
                    
                    else:
                        for reg in response:
                            if reg == "NS":
                                for ns in response["NS"]:
                                    print(f"[+] Register {reg}: {ns}")

                            elif reg == "MX":
                                for mails in response["MX"]:
                                    print(f"[+] Register {reg}: {mails}")

                            elif reg == "TXT":
                                for txt in response["TXT"]:
                                    print(f"[+] Register {reg}: {txt}")

                            else:
                                print(f"[+] Register {reg}: {response[reg]}")

                else: 
                    print("pls use option -t")
                    exit()

    elif args.type:
        print("please use option -d or --domain, to inform a domain to do a query")
        exit()

    elif args.resolve:
        if args.domain or args.type or args.reverseresolve or args.zonetransfer or args.scan or args.whois:
            print("You is using another more options, do can't use more options in same time, case you want execute one completo scan, use the option: -s or --scan")
            exit()

        else: 
            if args.output:
                if args.output == "":
                    print("pls pass the name of file")

                else:
                    file = open(str(args.output), "a")

                    response = Resolvers.resolve(str(args.resolve))

                    if response == False:
                        print(f"Can't possible resolve the domain...")
                        file.close()
                        os.remove(str(args.output))
                        exit()
                    
                    else:
                        print(f"Domain resolve: {response}") 

                        file.write(f"Domain resolve: {response}")
                        file.close()
        
            else:
                response = Resolvers.resolve(str(args.resolve))
                print(f"Domain resolved: {response}")
        
    elif args.reverseresolve:
        if args.domain or args.type or args.resolve or args.zonetransfer or args.scan or args.whois:
            print("You is using another more options, do can't use more options in same time, case you want execute one completo scan, use the option: -s or --scan")
            exit()

        else:
            if args.output:
                if args.output == "":
                    print("pls pass the name of file")

                else:
                    file = open(str(args.output), "a")

                    response = Resolvers.reverseResolve(str(args.reverseresolve))

                    if response == False:
                        print(f"Can't possible resolve the ip...")
                        file.close()
                        os.remove(str(args.output))
                        exit()

                    else:
                        print(f"IP resolve: {response}")

                        file.write(f"IP resolve: {response}")
                        file.close()

            else:
                response = Resolvers.reverseResolve(str(args.reverseresolve))

                if response == False:
                    print(f"Can't possible resolve the ip...")
                    exit()

                else:
                    print(f"IP resolve: {response}")
        
    elif args.zonetransfer:
        if args.domain or args.type or args.resolve or args.reverseresolve or args.scan or args.whois:
            print("You is using another more options, do can't use more options in same time, case you want execute one completo scan, use the option: -s or --scan")
            exit()

        else:
            if len(args.zonetransfer.split(",")) >= 3:
                ls = args.zonetransfer.split(",")
                domain = ls[0]

                if args.output:
                    if args.output == "":
                        print("pls pass the name of file")

                    else:
                        for ns in ls[1:]:
                            file = open(str(args.output), "a")

                            try:
                                response = Consult.zoneTransfer(domain, ns)

                                if response.stdout:
                                    print(response.stdout.decode("UTF-8"))
                                    
                                    file.write(response.stdout.decode("UTF-8"))
                                    file.close()

                                else:
                                    print(f"not possible to do the zone transfer in {ns}")
                                    file.close()
                                    os.remove(args.output)
                            
                            except AttributeError:
                                print(f"not possible to do the zone transfer in {ns}")
                                file.close()
                                os.remove(args.output)
                                continue

                else:
                    for ns in ls[1:]:
                        try:
                            response = Consult.zoneTransfer(domain, ns)

                            if response.stdout:
                                print(response.stdout.decode("UTF-8"))
                            
                            else:
                                print(f"not possible to do the zone transfer in {ns}")

                        except AttributeError:
                            print(f"not possible to do the zone transfer in {ns}")
                            continue
                    

            else:
                domain, ns = args.zonetransfer.split(",")
            
                if args.output:
                    try:
                        file = open(str(args.output), "a")
                        response = Consult.zoneTransfer(domain, ns)
                        
                        print(response.stdout.decode("UTF-8"))
                        file.write(response.stdout.decode("UTF-8"))

                        file.close()

                    except AttributeError:
                        exit()
                    

                else:
                    try:
                        response = Consult.zoneTransfer(domain, ns)
                        print(response.stdout.decode("UTF-8"))

                    except AttributeError:
                        exit()



    elif args.scan:
        if args.domain or args.type or args.resolve or args.reverseresolve or args.zonetransfer or args.whois:
            print("You is using another more options, do can't use more options in same time, case you want execute one completo scan, use the option: -s or --scan")

        else:
            if args.output:
                if args.output == "":
                    print("pls pass the name of file")

                else:
                    file = open(str(args.output), "a")

                    check = Utils.checkIp(args.scan)

                    if check == True:
                        ipDom = Resolvers.reverseResolve(args.scan)
                        print(ipDom)
                        
                        file.close()
                        os.remove(args.output)

                    else:
                        domIP = Resolvers.resolve(args.scan)
                        
                        if domIP == False:
                            print("Can't possible resolve the domain !")
                            file.close()
                            os.remove(args.output)
                            exit()

                        else:
                            print(f"{args.scan}({domIP})\n\n")

                            regResolved, zone, whois = Consult.scan(str(args.scan))

                            print("[+] === DNS REGISTERS === [+]")
                            file.write("[+] === DNS REGISTERS === [+]\n")
                            print("================================================\n")
                            file.write("================================================\n\n")

                            for reg in regResolved:
                                if reg == "A" or reg == "AAAA" or reg == "CNAME" or reg == "PTR" or reg == "HINFO":
                                    print(f"[+] DNS Register {reg}: {regResolved[reg]}")
                                    file.write(f"[+] DNS Register {reg}: {regResolved[reg]}\n")
                                
                                elif reg == "NS":
                                    for nsReg in regResolved[reg]:
                                        print(f"[+] DNS Register {reg}: {nsReg}")
                                        file.write(f"[+] DNS Register {reg}: {nsReg}\n")

                                elif reg == "MX":
                                    for mxReg in regResolved[reg]:
                                        print(f"[+] DNS Register {reg}: {mxReg}")
                                        file.write(f"[+] DNS Register {reg}: {mxReg}\n")

                                elif reg == "TXT":
                                    for txtReg in regResolved[reg]:
                                        print(f"[+] DNS Register {reg}: {txtReg}")
                                        file.write(f"[+] DNS Register {reg}: {txtReg}\n")

                            print("================================================\n")
                            file.write("================================================\n\n")
                                
                            print("[+] === Zone Transfer === [+] ")
                            file.write("[+] === Zone Transfer === [+]\n")
                            print("================================================\n")
                            file.write("================================================\n\n")

                            if zone == None:
                                print("don't possible do one zone transfer")
                                file.write("don't possible do one zone transfer")

                            else:
                                print(zone)
                                file.write(zone)

                            print("================================================\n")
                            file.write("================================================\n\n")

                            print("[+] === WHOIS === [+]")
                            file.write("[+] === WHOIS === [+]\n")
                            print("================================================\n")
                            file.write("================================================\n\n")

                            print(whois)
                            file.write(whois)

                            print("================================================\n")
                            file.write("================================================\n\n")

                            file.close()




            else:
                check = Utils.checkIp(args.scan)

                if check == True:

                    ipDom = Resolvers.reverseResolve(args.scan)
                    print(ipDom)

                else:
                    
                    domIP = Resolvers.resolve(args.scan)

                    if domIP == False:
                        print("Can't possible resolve the domain !")
                        exit()

                    else:
                        regResolved, zone, whois = Consult.scan(str(args.scan))

                        print(f"{args.scan}({domIP})\n\n")
            
                        print("[+] === DNS REGISTERS === [+]")
                        print("================================================\n")

                        for reg in regResolved:
                            if reg == "A" or reg == "AAAA" or reg == "CNAME" or reg == "PTR" or reg == "HINFO":
                                print(f"[+] DNS Register {reg}: {regResolved[reg]}")
                            
                            elif reg == "NS":
                                for nsReg in regResolved[reg]:
                                    print(f"[+] DNS Register {reg}: {nsReg}")

                            elif reg == "MX":
                                for mxReg in regResolved[reg]:
                                    print(f"[+] DNS Register {reg}: {mxReg}")

                            elif reg == "TXT":
                                for txtReg in regResolved[reg]:
                                    print(f"[+] DNS Register {reg}: {txtReg}")

                        print("================================================\n")
                            
                        print("[+] === Zone Transfer === [+] ")
                        print("================================================\n")

            
                        if zone == None:
                            print("don't possible do one zone transfer")

                        else:
                            print(zone)
                        

                        print("================================================\n")

                        print("[+] === WHOIS === [+]")
                        print("================================================\n")
                        
                        print(whois)

                        print("================================================\n")

    elif args.whois:
        if args.domain or args.type or args.resolve or args.reverseresolve or args.zonetransfer or args.scan:
            print("You is using another more options, do can't use more options in same time, case you want execute one completo scan, use the option: -s or --scan")

        else:
            if args.output:
                if args.output == "":
                    print("pls pass the name of file")

                else:
                    file = open(str(args.output), "a")
                    whois = Consult.whois(str(args.whois))

                    print(whois)
                    file.write(whois)
                    file.close()

            else:
                whois = Consult.whois(str(args.whois))
                print(whois)

if __name__ == "__main__":
    main(arguments)