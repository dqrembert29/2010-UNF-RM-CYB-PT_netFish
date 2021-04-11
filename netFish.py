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


def findPortScans(log, IP):

# open the file used in command
    file = open(log, 'r');
#set variable for the lines in file
    chars = file.read();
#create dictionary for each IP connecting to target IP with the destination ports as keys
    portScanDict = {};
#create dictionary for the number of ports an IP has attempted to connect to(used as reference for portScanList)
    scanCountDict = {};
#set target IP to be checked against destination IP
    targetIP = IP;
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
        if skip == True;
#If the current character is a delimiter(hardcoded to space for now)
            if i == '\n' or i == '\r\n':
                skip = False;
#If the current character is a delimiter(hardcoded to space for now)
        elif i == " ":
#check if the current argument is an IP using UFW format #Ideally, I would check if current IP matches IP format instead, but those have a LOT of rules to consider..
            if (currentArg.find("SRC")) or (currentArg.find("DST")):
#Strip currentArg of its tag to get the raw IP
                currentArg = (str(currentArg[:4]))
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
            elif (currentArg.find("DPT") == -1):
#Strip currentArg of its tag to get the raw IP
                currentArg = (str(currentArg[:4]))
#If argument is a destination port, check if the source IP doesn't match an existing key(is not in the dictionary yet)
                if portScanDict.get(srcIP)==None:
#                    print("New IP Found: "+currentArg);
#If source IP does not match a key, create a new one with the destination port its value
                    portScanDict[srcIP] = currentArg;
#If source IP does match a key, create a string check if the destination port has not been requested before.
                else:
                    check = portScanDict.get(srcIP);
#If the destination port is not already listed(-1 means nothing was found)
                    if check.find(currentArg)==-1:
#Add the new port to the string value of that IP(add to a human-readable list)
                        portScanDict[srcIP] = ", "+str(portScanDict[srcIP])
#Add +1 to the ports scanned count for that source IP.
                        scanCountDict[currentArg] = scanCountDict.get(currentArg)+1;
#                    value = scanCountDict.get(currentArg)
#                    value+=1
#                    scanCountDict[currentArg] = value
#                    print("+1 Existing IP: "+currentArg);
#after the argument has been interpretted, set currentArg back to ""
            currentArg="";
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
#Create a 'postResults' function with 'counter' and 'printList' local variables.
    def postResults():
#create 'printList' list to be used for searching for keys/values
        printList = [];
#Set counter to '10' for iterating while loop
        counter = 10;
        while (int(counter)>0):
#use the 'max' function to find the key with the highest value in scanCountDict and assign it to currentArg
            currentArg = max(scanCountDict, key=scanCountDict.get)
#subtract 1 from 'counter' to stop iterating after 10.
            counter-=1;
#If that IP has attempted connections to the target IP with at least 5 destination ports..(hardcoded, could add option for this to be changed by user).
            if scanCountDict[currentArg]>5:
#add currentArg to printList
                printList.append(currentArg);
#delete the currentArg key from scanCountDict
                del scanCountDict[currentArg]
#set 'counter' to the length of printList (this will help create a neat list)
        counter = int(printList.count());
#If any possible port scans were detected above..
        if printList != []:
#For each IP in reversed 'printList' - this creates an ascending list of possible port scans. (max 10, lower if less than 10 IPs tried to connect to over 4 destination ports - refer to the above 10 iteration for loop creating printList)
            for i in Reverse(printList):
#print the counter, followed by a period, and the lowest-count IP that scanned enough ports to make it onto the printList.
                print(str(counter)+". "+str(i));
#If the length of the IP's scanned ports list(key value) does not pass 50 characters..
                if len(portScanDict.get(i))<50:
#print that list of scanned ports.
                    print(portScanDict.get(i))
#subtract '1' from counter
                counter=-1;
#Else if no possible port scans were detetected above..
        else:
#Print "No Port Scans Detected for target IP."
            print("No Portscans Detected for target IP.");
    postResults();


def findMostCommonIP(log):
# open the file used in command
    file = open(log, 'r');
#set variable for the lines in file
    chars = file.read();
#create dictionary for each IP with their counts as keys
    IPList = {};
#set current IP for appending up to the next semicolon.
    currentArg = "";
#set to true if source IP does not match the target
    skip = False;
#for each character in 'lines'
    for i in chars:
        if skip == True:
#If the current character is a delimiter(hardcoded to space for now)
            if i == '\n' or i == '\r\n':
                skip = False;
#If the current character is a delimiter(hardcoded to space for now)
        elif i == " ":
#check if the current argument is an IP using UFW format #Ideally, I would check if current IP matches IP format instead, but those have a LOT of rules to consider..
            if (currentArg.find("SRC")) or (currentArg.find("DST")):
#If the argument is an IP, check if currentArg doesn't match an existing key(is not in the dictionary) #Ideally, I woulc check if current IP matches IP format here, but those have a LOT of rules to consider..
                if IPList.get(currentArg)==None:
#                    print("New IP Found: "+currentArg);
#If currentArg does not match a key, create a new one and add 1 to its value
                    IPList[currentArg] = 1
#If currentArg does match a key, set the value of that key +1
                else:
                    IPList[currentArg] = (IPList.get(currentArg)+1);
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
            currentArg=(currentArg+str(i));
#           print("Current IP: "+currentArg);
#other 'unimportant' characters skip resetting the currentArg
#        else:
#            continue
#print the most common IP in IPList, which I think is possible with max and get
    mostCommonIP = max(IPList, key=IPList.get)
#now print that value and the IP sorted(IPList.items[0])
    print("Most Common IP: "+str(mostCommonIP)+" Count: "+str(IPList.get(mostCommonIP)))






def findMostCommonSourceIP(log):

# open the file used in command
    file = open(log, 'r');
#set variable for the lines in file
    lines = file.readlines();
#create dictionary for each IP with their counts as keys
    IPList = {};
#set current Argument for appending up to the next delimiter(hardcoded to space)
    currentArg = "";
#set to true if source IP does not match the target
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
#If the current character is a delimiter(hardcoded to space for now)
                if i == '\n' or i == '\r\n':
                    skip = False;
#If the current character is a delimiter(hardcoded to space for now)
            elif i == " ":
#check if the current argument is an IP using UFW format #Ideally, I would check if current IP matches IP format instead, but those have a LOT of rules to consider..
                if (currentArg.find("SRC")):
#Strip currentArg of its tag to get the raw IP
                    currentArg = (str(currentArg[4:]))
#Take the saved IP and check if currentArg doesn't match an existing key(is not in the dictionary) #Ideally, I would check if current IP matches IP format here, but those have a LOT of rules to consider..
                    if IPList.get(currentArg)==None:
#                    print("New IP Found: "+currentArg);
#If currentArg does not match a key, create a new one and add 1 to its value
                        IPList[currentArg] = 1
#If currentArg does match a key, set the value of that key +1
                    else:
                        IPList[currentArg] = (IPList.get(currentArg)+1);
#                        value = IPList.get(currentArg)
#                        value+=1
#                        IPList[currentArg] = value
#                        print("+1 Existing IP: "+currentArg);
#after the argument has been interpretted, set currentArg back to "" and skip the rest of the line
                currentArg="";
                skip = True
#else if current character is a newline
            elif i == '\n' or i == '\r\n':
#set currentArg back to none.
            currentArg = "";
#If character is not a delimiter, concatinate it to currentArg
            else:
                currentArg=(currentArg+str(i));
#               print("Current IP: "+currentArg);
#print the most common Client IP in IPList and its count, not including responses sent by a server.
    mostCommonIP = max(IPList, key=IPList.get)
#now print that value and the IP sorted(IPList.items[0])
    print("Most Common Client IP: "+str(mostCommonIP)+" Count: "+str(IPList.get(mostCommonIP)))




#-----CREATE A MAIN FUNCTION TO CALL HELPER FUNCTIONS-----

def main(args):

    #check if looking for any most common IP, or only clients.
    if (sys.argv[1] == "anyIP"):
    #call the correct helper function
        findMostCommonIP(args);
    elif (sys.argv[1] == "srcIP"):
    #call the correct helper function
        findMostCommonSourceIP(args);
    elif (sys.argv[1] == "whoScanned"):
        findPortScans(args);
    else:
    #end script early and give the user an error message if format is incorrect.
        print("Please use one of these formats: ./netFish (srcIP/anyIP) (file name) [verbose]");
        print("./netFish (whoScanned) (file name) (destinationIP) [verbose]");
        print("./netFish --help");

#-----CHECK TO SEE IF THIS SCRIPT IS THE MAIN SCRIPT AND ALLOW HELP CALL-----

if __name__ == '__main__':

    if sys.argv[1] == "--help":
        print("./netFish (clientIP/anyIP) (file name) [verbose]")
        print("verbose will display every time a new IP is found, or an existing one is added.")
        print("'anyIP' option will find all instances of an IP in a log.")
        print("'srcIP' option will count packets sent by an IP, NOT when that IP recieves a packet.")
        print("./netFish (whoScanned) (file name) (destination IP) [verbose]")
        print("'whoScanned' option will find all IPs connecting to unsually high numbers of ports for the destination IP.")
    elif (len(sys.argv)<3) or (len(sys.argv)>5):
#end script early and give the user an error message if format is incorrect.
        print("Please use one of these formats: ./netFish (sourceIP/anyIP) (file name) [verbose]");
        print("./netFish whoScanned (file name) (destination IP) [verbose]");
    else:
#check for the number of arguments
        if (len(sys.argv)>3):
            arg_list = sys.argv[-2:]
        else:
            arg_list = sys.argv[2]     # adjust this for the number of args you need sys.argv[-2:] would take the last two.
        main(arg_list)          # call your main function