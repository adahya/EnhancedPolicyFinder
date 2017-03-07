import sys
import argparse
import re
import pprint
import ipaddress
import json
import openpyxl


addrgrpobjdict = dict()
addrobjdict = dict()
fwpolicydict = dict()

def pp_json(json_str):
    print(json.dumps(json_str, sort_keys=True,indent=4,separators=(',', ': ')))

def in_supersubnet(IP,IPSubnet):
    i = IP.prefixlen
    if i < IPSubnet.prefixlen and IP.overlaps(IPSubnet):
        return True
    for i in range(0):
        if IP.supernet(new_prefix=i) == IPSubnet:
          return True
    return False

def in_Range(IP,IPRange):
    Decision = False
    Match = IPRange[0]
    while Match != IPRange[1]:
        if IP == Match:
            print(str(IP) + ' Matches the Range ' + IPRange[0] + ' - ' + IPRange[1] )
            Decision = True
            break
        Match += 1
    return Decision


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
    filename = vars(args)['f']

    print(("Parsing Configuration File: %s" % filename))

    matchingipaddress = vars(args)['m']
    TIP = ipaddress.IPv4Network(matchingipaddress)
    print(("Parsing for Match for IP Address : %s" % str(TIP)))

    if filename is None:
        while filename == None:
            print("Please enter name of output file (without .xlsx): ")
            filename = input()

    addobj_dict = dict()

    #Creating Dictionary for Address Objects
    print("PHASE 1: Loading Configuration File %s" % filename)
    try:
        fullconfigstr = open(filename, 'r').read()
    except FileNotFoundError:
        print(("Error reading config file: %s" % filename))
        sys.exit(FileNotFoundError.errno)

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

    try:
        matchingipnetaddress = ipaddress.IPv4Network(matchingipaddress)
    except:
        print ('Error wrong Format for IP Address')
        raise
    sys.stdout.write ('\nPHASE 2: Parsing Configuration File \n')

    Targetpolicydict = dict()
    matched = 0
    for i,key in enumerate(fwpolicydict):
        sys.stdout.write ('\rProcessing POLICY ID %s --- %d/%d POLICIES MATCHED/TESTED' % (key.rjust(5), matched, len(list(fwpolicydict.keys()))))
        pol = fwpolicydict[key]
        #pp_json(pol)
        for obj in pol["srcaddr"]:
            if addrobjdict[obj] == None:
                print('Error No Match in Address Object ')
            try:
                if 'iprange' == addrobjdict[obj].get('type'):
                    #pp_json(addrobjdict[obj])
                    IPRange = list()
                    IPRange.append(ipaddress.IPv4Address (str(addrobjdict[obj].get('start-ip'))))
                    IPRange.append(ipaddress.IPv4Address (str (addrobjdict[obj].get ('end-ip'))))
                    if in_Range(matchingipnetaddress,IPRange) :
                        Targetpolicydict[key] = pol
                        matched += 1
                        break
                elif 'ipmask' == addrobjdict[obj].get('type'):
                    #pp_json(addrobjdict[obj])
                    IPSubnet = str(addrobjdict[obj].get('subnet')).replace(' ','/')
                    policyaddr = ipaddress.IPv4Network(IPSubnet)
                    if in_supersubnet (matchingipnetaddress, policyaddr):
                        Targetpolicydict[key] = pol
                        matched += 1
                        break
                    elif matchingipnetaddress == policyaddr:
                        #sys.stdout.write('Exact Match %s in Policy $s' % str(matchingipnetaddress) , key)
                        Targetpolicydict[key] = pol
                        matched += 1
                        break

            except:
                pp_json(pol)
                pp_json(pol)
                raise
    sys.stdout.write ('\rProcessed                   %d/%d POLICIES MATCHED/TESTED' % (matched, len (list (fwpolicydict.keys ()))))
    sys.stdout.write ('\nPHASE 3: Saving Matched policies into %s.xlsx File ' % (filename) )
    f = open("MatchingPolicies",'w')
    f.write(json.dumps(Targetpolicydict, sort_keys=True,indent=4,separators=(',', ': ')))
    f.close()

    outxlsx = openpyxl.Workbook()
    outsheet = outxlsx.active
    outsheet.title = 'Matched Policies'

    # Write the header
    outsheet['A1'] = 'Policy ID#'
    outsheet['B1'] = 'Action'
    outsheet['C1'] = 'Source Interface'
    outsheet['D1'] = 'Destination Interface'
    outsheet['E1'] = 'Source Addresses'
    outsheet['F1'] = 'Destination Addresses'
    outsheet['G1'] = 'Service'
    outsheet['H1'] = 'Status'

    row = 2
    # Write Matched Policies in ExcelSheet
    for i, key in enumerate (Targetpolicydict):
        outsheet.cell (row=row, column=1).value = key
        outsheet.cell (row=row, column=2).value = str(Targetpolicydict[key].get('action'))
        outsheet.cell (row=row, column=3).value = str(Targetpolicydict[key].get('srcintf'))
        outsheet.cell (row=row, column=4).value = str(Targetpolicydict[key].get('dstintf'))
        outsheet.cell (row=row, column=5).value = str(Targetpolicydict[key].get('srcaddr'))
        outsheet.cell (row=row, column=6).value = str(Targetpolicydict[key].get('dstaddr'))
        outsheet.cell (row=row, column=7).value = str(Targetpolicydict[key].get('service'))
        outsheet.cell (row=row, column=8).value = str(Targetpolicydict[key].get('status'))
        row += 1
        sys.stdout.write ('\rWriting POLICIES to File --- %d/%d POLICIES MATCHED/TESTED' % ((i+1), len(list(fwpolicydict.keys()))))
    sys.stdout.write ('\n\rSaving File POLICIES to File ')

    #Check the non matching Policies for checking
    outxlsx.save (filename + '.xlsx')
    outsheet = outxlsx.create_sheet("None Match Sheet")


    # Write the header
    outsheet['A1'] = 'Policy ID#'
    outsheet['B1'] = 'Action'
    outsheet['C1'] = 'Source Interface'
    outsheet['D1'] = 'Destination Interface'
    outsheet['E1'] = 'Source Addresses'
    outsheet['F1'] = 'Destination Addresses'
    outsheet['G1'] = 'Service'
    outsheet['H1'] = 'Status'

    #Remove the Match Policies from the Dict
    temp = dict()
    for i,key in enumerate(fwpolicydict):
        if key in Targetpolicydict:
            continue
        else:
            temp[key] = fwpolicydict[key]

    #Write the Non Match Policies to Excel
    row = 2
    # Write Matched Policies in ExcelSheet
    for i, key in enumerate (temp):
        outsheet.cell (row=row, column=1).value = key
        outsheet.cell (row=row, column=2).value = str(temp[key].get('action'))
        outsheet.cell (row=row, column=3).value = str(temp[key].get('srcintf'))
        outsheet.cell (row=row, column=4).value = str(temp[key].get('dstintf'))
        outsheet.cell (row=row, column=5).value = str(temp[key].get('srcaddr'))
        outsheet.cell (row=row, column=6).value = str(temp[key].get('dstaddr'))
        outsheet.cell (row=row, column=7).value = str(temp[key].get('service'))
        outsheet.cell (row=row, column=8).value = str(temp[key].get('status'))
    outxlsx.save (filename + '.xlsx')
    print('\n----OPERATION COMPLETED----\n')
