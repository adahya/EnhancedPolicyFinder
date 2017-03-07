import sys
import argparse
import re
import pprint
import ipaddress
import json


addrgrpobjdict = dict()
addrobjdict = dict()
fwpolicydict = dict()

def pp_json(json_str):
    print(json.dumps(json_str, sort_keys=True,indent=4,separators=(',', ': ')))

def expandips(Addr):
    OrigAddr = str(Addr)
    SplitedIPs = list()
    SplitedIPs += list(OrigAddr.split(' '))
    for i,e_entry in enumerate(SplitedIPs):
        if e_entry in addrgrpobjdict:
            SplitedIPs += addrgrpobjdict[e_entry]['member']
        else:
            SplitedIPs[i] = e_entry.replace('"','')
    Final_Splitted_IPs = list()
    for i, e_entry in enumerate(SplitedIPs):
        if e_entry not in addrgrpobjdict:
            Final_Splitted_IPs.append(e_entry)
    return Final_Splitted_IPs

def print_dict(dictionary):
    for keys, values in dictionary.items():
        print(keys)
        print(values)

if __name__ == '__main__':

    pp = pprint.PrettyPrinter(indent=2)

    parser = argparse.ArgumentParser(description="Process Fortigate configuration \
        and create communication matrix excel sheet.")
    parser.add_argument('-f', action='store',
                        metavar='<configuration-file>',
                        help='path to configuration file',
                        required=False)

    parser.add_argument('-m', action='store',
                        metavar='<matching-ip-address>',
                        help='matching ip address in format X.X.X.X/XX',
                        required=True)

    args = parser.parse_args()
    CONFIGFILE = vars(args)['f']

    print(("Parsing Configuration File: %s" % CONFIGFILE))

    matchingipaddress = vars(args)['m']
    TIP = ipaddress.IPv4Network(matchingipaddress)
    print(("Parsing for Match for IP Address : %s" % str(TIP)))

    filename = "fwry02-fwry13.conf"
    while filename == "":
        print("Please enter name of output file (without .xlsx): ")
        filename = input()

    addobj_dict = dict()

    #Creating Dictionary for Address Objects
    print("PHASE 1: Loading Configuration File %s" % filename)
    try:
        fullconfigstr = open(filename, 'r').read()
    except:
        print(("Error reading config file: %s" % filename))

    fullconfiglines = fullconfigstr.splitlines()

    alladdress = fullconfiglines[fullconfiglines.index('config firewall address') + 1:]
    alladdress = alladdress[:alladdress.index('end')]

    for line in alladdress:
        try:
            if line.strip().startswith('edit'):
                addrobjid = (re.match(r'edit (".*")', line.strip()).groups()[0]).replace('"','')
                addrobjdict[addrobjid] = dict()
            elif line.strip() != 'next' and line.strip().startswith('set'):
                key, val = re.match(r'^set (\S*) (.+)$', line.strip()).groups()
                addrobjdict[addrobjid][key] = val.replace('"','')
        except:
            print(("Error on line: %s" % line))
            raise

    alladdressgroups = fullconfiglines[fullconfiglines.index('config firewall addrgrp') + 1:]
    alladdressgroups = alladdressgroups[:alladdressgroups.index('end')]

    for line in alladdressgroups:
        try:
            if line.strip().startswith('edit'):
                addrgrpobjid = (re.match(r'edit (".*")', line.strip()).groups()[0]).replace('"','')
                addrgrpobjdict[addrgrpobjid] = dict()
            elif line.strip() != 'next' and line.strip().startswith('set'):
                key, val = re.match(r'^set (\S*) (.+)$', line.strip()).groups()
                addrgrpobjdict[addrgrpobjid][key] = val.split(''" "'')
                for i, item in enumerate(addrgrpobjdict[addrgrpobjid][key]):
                    addrgrpobjdict[addrgrpobjid][key][i] = (addrgrpobjdict[addrgrpobjid][key][i]).replace('"','')
        except:
            print(("Error on line: %s" % line))
            raise

    allserviceports = fullconfiglines[fullconfiglines.index('config firewall service custom') + 1:]
    allserviceports = allserviceports[:allserviceports.index('end')]

    serviceportsdict = dict()

    for line in allserviceports:
        try:
            if line.strip().startswith('edit'):
                serviceportid = (re.match(r'edit (".*")', line.strip()).groups()[0]).replace('"','')
                serviceportsdict[serviceportid] = dict()
            elif line.strip() != 'next' and line.strip().startswith('set'):
                key, val = re.match(r'^set (\S*) (.+)$', line.strip()).groups()
                serviceportsdict[serviceportid][key] = val.replace('"','')
        except:
            print(("Error on line: %s" % line))
            raise

    allfwpolicies = fullconfiglines[fullconfiglines.index('config firewall policy') + 1:]
    allfwpolicies = allfwpolicies[:allfwpolicies.index('end')]

    for line in allfwpolicies:
        try:
            if line.strip().startswith('edit'):
                fwpolicyid = re.match(r'edit (\d*)', line.strip()).groups()[0]
                fwpolicydict[fwpolicyid] = dict()
            elif line.strip() != 'next' and line.strip().startswith('set'):
                key, val = re.match(r'^set (\S*) (.+)$', line.strip()).groups()
                fwpolicydict[fwpolicyid][key] = val.replace('"','')
        except:
            print(("Error on line: %s" % line))
            raise

    print("PHASE 2: Parsing Configuration File ")

    match = list()
    try:
        matchingipnetaddress = ipaddress.IPv4Network (matchingipaddress)
    except:
        print ('Error wrong Format for IP Address')
        raise

    f = open('test','w')

    for PID in fwpolicydict:
        fwpolicydict[PID]['srcaddr'] = expandips(fwpolicydict[PID]['srcaddr'])
        fwpolicydict[PID]['dstaddr'] = expandips(fwpolicydict[PID]['dstaddr'])

    print(("Total Address Objects      : %d" % len(list(addrobjdict.keys()))))
    print(("Total Address Group Objects: %d" % len(list(addrgrpobjdict.keys()))))
    print(("Total Custom Services      : %d" % len(list(serviceportsdict.keys()))))
    print(("Total Firewall Policies    : %d" % len(list(fwpolicydict.keys()))))

    fd = open('test-output.txt', 'w')
    fd.write(json.dumps({
        "addrobjdict": addrobjdict,
        "addrgrpobjdict": addrgrpobjdict,
        "serviceportsdict": serviceportsdict,
        "fwpolicydict": fwpolicydict,
    }, sort_keys=True,indent=4,separators=(',', ': ')))
    fd.close()

    for i,key in enumerate(fwpolicydict):
        pol = fwpolicydict[key]
        pp_json(pol)
        for obj in pol["srcaddr"]:
            try:
                if 'type' in (addrobjdict[obj]).keys():
                    #print(addrobjdict[obj])
                    continue
                elif 'subnet' in (addrobjdict[obj]).keys():
                    print(addrobjdict[obj])
            except:
                pp_json(pol)
                pp_json(pol)
                raise


