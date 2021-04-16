#frame.number;frame.time;ip.src;tcp.srcport;ip.dst;tcp.dstport;ip.proto;ip.len;Proto;Info

#--------- Incomplete 'find most common IP' - add numbers together and print them for each line
#This program is somewhat 'hard coded' for a certain kind of log, but it could be changed to work for
#many other types of log is an IP check is added, and used to 'scan' the first line for which arguments
#would contain IPs. Might need to add another argument for specifying if client or server IP comes first
#to use the second function.. but then I could easily have it scan for the most common host IP too!

#!/usr/bin/env python3

# IMPORT NECESSARY LIBRARIES
import sys


#-----CREATE HELPER FUNCTIONS-----

def parseLog(args, log):
#To be run when no parsing data is provided
#This should be able to: record the data to be used in other methods if the target log doesn't already have parsing data, pass on that data to method(s) being run, join the two dictionaries used in findPortScans by turning
#the scanCountDict into a set within a destination dictionary within source dictictionaries inside the base portScanDict dictionary, (allow for muiltiple methods to be called at once),
#(and add an option to save the results to a file which will be read later.)
    print("")
#-------If log file is True-------
#For each argument in args(This should only include valid arguments as others were stripped in main - main should also now send valid requests here instead of determining method)
#For each 
#-------If log file is False-------

#Posts results in a list. Requires a string to be printed as the header, a string to print if no results are found, a dictionary with the counts of results, and a dictionary with port numbers if using portScans, and maximum output list length.
#If not port scanning, give the last argument an empty dictionary.
def postResults(resultsHeader, noResultsResponse, countDictionary, optionalPortDictionary, outputNum):
#shortened variables, to give clear descriptors without making these long to use.
    countDict = countDictionary;
    portDict = optionalPortDictionary;
    if bool(countDict):
#create 'printList' list to be used for searching for keys/values
        printList = [];
#Set counter to 'outputNum' for iterating while loop. This is the maximum list length, and is configurable.
        counter = outputNum;
#Re-orders countDict into ascending order of values(so that keys with higher 'counts' are posted last).
        res = {val[0] : val[1] for val in sorted(countDict.items(), key = lambda x: (x[1], x[0]))}
#Adds dictionary keys to a list and iterates on them.
        countKeys = countDict.keys()
        for key in countKeys
#While counter is greater than 0(maximum list size has not been reached)..
            if counter>0:
#add current key to printList
                printList.append(key)
#subtract 1 to stop iterating after outputNum.
                counter-=1;
#set 'counter' to the length of printList (this will help create a neat list)
        counter = len(printList);
#If any possible port scans/IPs/other target data were detected above...
        if printList != []:
#Wrap the custom header provided by the module in a neat box.
            underline = ""
            for i in resultsHeader:
                underline = str(underline)+"-"
            print(underline)
            print(resultsHeader)
            print(underline)
#For each IP in re-ordered 'printList'.. (max outputNum, lower if less end results - refer to the above iteration for loop creating printList)
            for i in printList:
#print the counter, followed by a period, and the lowest-count IP to make it onto the printList.
            print(str(counter)+". "+str(i));
            if bool(portDict):
#If the length of the IP's scanned ports list(or other key value) does not pass 80 characters..
                if (len(portDict.get(i))<80):
#print that list of scanned ports.
                        print("Ports scanned: "+str(portDict.get(i)))
                    else:
                        print("Destination ports exeed listing limit")
                else:
                    print("Count in log: "+str(countDict.get(i)))
#subtract '1' from counter for visual list
                counter-=1;
#Else if no possible port scans were detetected above..
        elif bool(portDict) is False:
#            def Reverse(list):
#                return [nln for nln in reversed(list)]
#            for i in Reverse(printList):
            for i in (printList):
#print the counter, followed by a period, and the lowest-count IP that scanned enough ports to make it onto the printList.
                print(str(counter)+". "+str(i));
#subtract '1' from counter
                counter-=1;
        else:
#Print "No Port Scans Detected for target IP."
            print(noResultsHeader);
     else: print("No Results detected. Please check the arguments and that the file is a UFW log.")


def findPortScans(args):
# open the file used in command
    file = open(args[0], 'r');
#set variable for the lines in file
    chars = file.read();
#create dictionary for each IP connecting to target IP with the destination ports as keys
    portScanDict = {};
#create dictionary for the number of ports an IP has attempted to connect to(used as reference for portScanList)
    scanCountDict = {};
#set target IP to be checked against destination IP
    targetIP = args[1];
#set current source IP  -to be deleted each line
    srcIP = "";
#set current destination IP  -to be deleted each line
    dstIP = "";
#set current argument for appending up to the next delimiter.
    currentArg = "";
#set to true if source IP does not match the target
    skip = False;
#set a string used for finding port numbers as substrings, before being promptly erased.
    check = "";
#for each character in 'lines'
    for i in chars:
#If skip equals true(because the dstIP doesn't equal target destination IP)
        if skip == True:
#If the current character is a new line, clear values and stop skipping.
            if i == '\n' or i == '\r\n':
                srcIP = ""; dstIP = ""; currentArg = "";
                skip = False;
#If the current character is a delimiter(hardcoded to space for now)
        elif i == " ":
#check if the current argument is an IP using UFW format #Ideally, I would check if current IP matches IP format instead, but those have a LOT of rules to consider..
            if "SRC" in currentArg or "DST" in currentArg:
#Strip currentArg of its tag to get the raw IP
                currentArg = str(currentArg[:4])
#check if source IP is blank.
                if srcIP == "":
#set 'srcIP' to the current argument
                    srcIP = currentArg;
#else if 'srcIP' is not blank
                else:
#set 'dstIP' to the current argument.
                    dstIP = currentArg;
#Check if dst does not match the target IP
                    if dstIP !=targetIP:
#If so, then skip the rest of the line.
                        skip = True;
#else check if the current argument is a destination port
            elif "DTP" in currentArg:
#Strip currentArg of its tag to get the raw IP
                currentArg = str(currentArg[:4])
#If argument is a destination port, check if the source IP doesn't match an existing key(is not in the dictionary yet)
                if srcIP not in portScanDict:
#                    print("New IP Found: "+currentArg);
#If source IP does not match a key, create a new one with the destination port its value
                    portScanDict[srcIP] = currentArg;
#create port scan count value for that source IP to the destination IP
                    scanCountDict[srcIP] = 1;
#If source IP does match a key, create a string check if the destination port has not been requested before.
                else:
                    check = portScanDict.get(srcIP);
#If the destination port is not already listed
                    if currentArg not in check:
#Add the new port to the string value of that IP(add to a human-readable list)
                        portScanDict[srcIP] = str(portScanDict[srcIP])+", "+str(currentArg)
#Add +1 to the ports scanned count for that source IP.
                        scanCountDict[srcIP] = scanCountDict[srcIP]+1;
#                    value = scanCountDict.get(currentArg)
#                    value+=1
#                    scanCountDict[currentArg] = value
#                    print("+1 Existing IP: "+currentArg);
#after the argument has been interpretted, set currentArg and check back to ""
            currentArg="";
            check = "";
#else if current character is a newline(other 'unimportant' characters are ignored)
        elif i == '\n' or i == '\r\n':
#set source IP, destination IP, and currentArg blank
            srcIP = "";
            dstIP = "";
            currentArg = "";
#else concatinate the current character to currentArg
        else:
            currentArg=(currentArg+str(i));
#                print("Current Arg: "+currentArg);
#Use the 'postResults' function with local variables.
    postResults("| Likely port scanning IPs in ascending order |", "No Port Scans Detected for target IP.", scanCountDict, portScanDict); 


def findMostCommonIP(log):
# open the file used in command, whether only a file location or more arguments are provided.
    if isinstance(log, str):
        file = open(log, 'r');
    else:
        file = open(log[0], 'r');
#set variable for the lines in file
    chars = file.read();
#create dictionary for each IP with their counts as keys
    IPDict = {};
#For passing to Post Results
    emptyDict = {};
#set current IP for appending up to the next semicolon.
    currentArg = "";
#for each character in 'lines'
    for i in chars:
#If the current character is a delimiter(hardcoded to space for now)
        if i == " ":
#check if the current argument is an IP using UFW format #Ideally, I would check if current IP matches IP format instead, but those have a LOT of rules to consider..
            if "SRC" in currentArg or "DST" in currentArg:
#Strip currentArg of its tag to get the raw IP
                currentArg = str(currentArg[4:])
#If the argument is an IP, check if currentArg doesn't match an existing key(is not in the dictionary) #Ideally, I woulc check if current IP matches IP format here, but those have a LOT of rules to consider..
                if currentArg not in IPDict:
#                    print("New IP Found: "+currentArg);
#If currentArg does not match a key, create a new one and add 1 to its value
                    IPDict[currentArg] = 1
#If currentArg does match a key, set the value of that key +1
                else:
                    IPDict[currentArg] = IPDict[currentArg]+1;
#                    value = scanCountDict.get(currentArg)
#                    value+=1
#                    scanCountDict[currentArg] = value
#                    print("+1 Existing IP: "+currentArg);
#after the argument has been interpretted, set currentArg back to ""
            currentArg="";
#else if current character is a newline
        elif i == '\n' or i == '\r\n':
#set currentArg back to none.
            currentArg = "";
#If character is not a delimiter, concatinate it to currentArg
        else:
            currentArg=currentArg+str(i);
#Use postResults to list the most common IPs in asending order.
    postResults("| Most common IPs in ascending order |", "No IPs included in file.", IPDict, emptyDict, 10);
#           print("Current IP: "+currentArg);
#print the most common IP in IPDict, which I think is possible with max and get
#    mostCommonIP = max(IPDict, key=IPDict.get)
#now print that value and the IP sorted(IPList.items[0])
#    print("Most Common IP: "+str(mostCommonIP)+" Count: "+str(IPDict.get(mostCommonIP)))






def findMostCommonSourceIP(log):

# open the file used in command, whether only a file location or more arguments are provided.
    if if isinstance(log, str)::
        file = open(log, 'r');
    else:
        file = open(log[0], 'r');
#set variable for the lines in file
    lines = file.readlines();
#create dictionary for each IP with their counts as keys
    IPDict = {};
#For passing to Post Results
    emptyDict = {};
#set current Argument for appending up to the next delimiter(hardcoded to space)
    currentArg = "";
#set to true after source IP is found.
    skip = False
#for each line in 'lines'
    for line in lines:
#set variable for current line
        currentLine = line;
#for each character in 'line'
        for i in currentLine:
#if arg is the counting arguement(0)
#        if arg==0:
#print the character count for checking for packet type(and/or  other variables)
#            print("char: ":i)
#            print("Argument: "+str(arg));
#            print("Counter: "+str(checkCounter));
#            print("Current IP: "+currentArg);
            if skip == True:
#If the current character is a new line, clear values and stop skipping.
                if i == '\n' or i == '\r\n':
                    skip = False;
                    currentArg="";
#If the current character is a delimiter(hardcoded to space for now)
            elif i == " ":
#check if the current argument is an IP using UFW format #Ideally, I would check if current IP matches IP format instead, but those have a LOT of rules to consider..
                if "SRC" in currentArg:
#Strip currentArg of its tag to get the raw IP
                    currentArg = str(currentArg[4:])
#Take the saved IP and check if currentArg doesn't match an existing key(is not in the dictionary) #Ideally, I would check if current IP matches IP format here, but those have a LOT of rules to consider..
                    if currentArg not in IPDict:
#                    print("New IP Found: "+currentArg);
#If currentArg does not match a key, create a new one and add 1 to its value
                        IPDict[currentArg] = 1
#If currentArg does match a key, set the value of that key +1
                    else:
                        IPDict[currentArg] = IPDict.get(currentArg)+1;
                        skip = True
#                        value = IPDict.get(currentArg)
#                        value+=1
#                        IPDict[currentArg] = value
#                        print("+1 Existing IP: "+currentArg);
#after the argument has been interpretted, set currentArg back to "" and skip the rest of the line
                currentArg="";
#else if current character is a newline
            elif i == '\n' or i == '\r\n':
#set currentArg back to none.
                currentArg = "";
#If character is not a delimiter, concatinate it to currentArg
            else:
                currentArg=currentArg+str(i);
#               print("Current IP: "+currentArg);
#Use postResults to list the most common IPs in asending order.
    postResults("| Most common IPs in ascending order |", "No IPs included in file.", IPDict, emptyDict, 10);
#print the most common Source IP in IPDict and its count, not including responses sent by a server.
#    mostCommonIP = max(IPDict, key=IPDict.get)
#now print that value and the IP sorted(IPDict.items[0])
#    print("Most Common Source IP: "+str(mostCommonIP)+" Count: "+str(IPDict.get(mostCommonIP)))




#-----CREATE A MAIN FUNCTION TO CALL HELPER FUNCTIONS-----

def main(args):

    #check if looking for any most common IP, or only clients.
    if (sys.argv[1] == "anyIP") or (sys.argv[1] == "a"):
    #call the correct helper function
        findMostCommonIP(args);
    elif (sys.argv[1] == "srcIP") or (sys.argv[1] == "s"):
    #call the correct helper function
        findMostCommonSourceIP(args);
    elif (sys.argv[1] == "whoScanned") and isinstance(args, str) is False or (sys.argv[1] == "w") and isinstance(args, str) is False:
        findPortScans(args);
    else:
    #end script early and give the user an error message if format is incorrect.
        print("Please use one of these formats: ./netFish (srcIP/anyIP) (file name) [verbose]");
        print("./netFish (whoScanned) (file name) (destinationIP) [verbose]");
        print("./netFish --help");

#-----CHECK TO SEE IF THIS SCRIPT IS THE MAIN SCRIPT AND ALLOW HELP CALL-----

if __name__ == '__main__':

    if len(sys.argv)<2:
        print("./netFish (clientIP/anyIP) (file name) [verbose]")
        print("verbose will display every time a new IP is found, or an existing one is added.")
        print("'anyIP' option will find all instances of an IP in a log.")
        print("'srcIP' option will count packets sent by an IP, NOT when that IP recieves a packet.")
        print("./netFish (whoScanned) (file name) (destination IP) [verbose]")
        print("'whoScanned' option will find all IPs connecting to unsually high numbers of ports for the destination IP.")
        print("All options can be shortened to their first character")
    elif sys.argv[1] == "--help":
        print("./netFish (clientIP/anyIP) (file name) [verbose]")
        print("verbose will display every time a new IP is found, or an existing one is added.")
        print("'anyIP' option will find all instances of an IP in a log.")
        print("'srcIP' option will count packets sent by an IP, NOT when that IP recieves a packet.")
        print("./netFish (whoScanned) (file name) (destination IP) [verbose]")
        print("'whoScanned' option will find all IPs connecting to unsually high numbers of ports for the destination IP.")
        print("All options can be shortened to their first character")
    elif (len(sys.argv)<3) or (len(sys.argv)>5):
#end script early and give the user an error message if format is incorrect.
        print("Please use one of these formats: ./netFish (sourceIP/anyIP) (file name) [verbose]");
        print("./netFish whoScanned (file name) (destination IP) [verbose]");
    else:
#check for the number of arguments
        if (len(sys.argv)>3):
            arg_list = sys.argv[2:]
        else:
            arg_list = sys.argv[2]     # adjust this for the number of args you need sys.argv[-2:] would take the last two.
        main(arg_list)          # call your main function
