#frame.number;frame.time;ip.src;tcp.srcport;ip.dst;tcp.dstport;ip.proto;ip.len;Proto;Info

#--------- Incomplete 'find most common IP' - add numbers together and print them for each line
#This program is somewhat 'hard coded' for a certain kind of log, but it could be changed to work for
#many other types of log is an IP check is added, and used to 'scan' the first line for which arguments
#would contain IPs. Might need to add another argument for specifying if client or server IP comes first
#to use the second function.. but then I could easily have it scan for the most common host IP too!

# IMPORT NECESSARY LIBRARIES
import sys

#!/usr/bin/env python3

#-----CREATE HELPER FUNCTIONS-----

def findMostCommonIP(log):
# open the file used in command
    file = open(log, 'r');
#set variable for the lines in file
    chars = file.read();
#create dictionary for each IP with their counts as keys
    IPList = {};
#set string for the current argument in line, starting with 0
    arg = 0;
#set current IP for appending up to the next semicolon.
    currentIP = "";
#for each character in 'lines'
    for i in chars:
#check for semi colons, skip each character until one is reached #Deleted for now, redundant
#        if i == ";":
#when a semi colon is found, add +1 to arg(current argument) #Deleted for now, redundant
#            arg+=1;
#if arg is the counting arguement(0)
#        if arg==0:
#print that count
#            print(i)
#If arg equals a source or destination IP argument
        if arg==2 or arg==4:
#check if the character is a semi colon
            if i == ";":
#If character is a semi colon, check if currentIP doesn't match an existing key(is not in the dictionary) #Ideally, I woulc check if current IP matches IP format here, but those have a LOT of rules to consider..
                if IPList.get(currentIP)==None:
#                    print("New IP Found: "+currentIP);
#If currentIP does not match a key, create a new one and add 1 to its value
                    IPList[currentIP] = 1
#If currentIP does match a key, set the value of that key +1
                else:
                    IPList[currentIP] = (IPList.get(currentIP)+1);
#                    value = IPList.get(currentIP)
#                    value+=1
#                    IPList[currentIP] = value
#                    print("+1 Existing IP: "+currentIP);
#after the key has been added, set currentIP back to ""
                currentIP="";
#At the end of semicolon True=yes function, arg+=1
                arg+=1;
#If character is not a semicolon, concatinate it to currentIP
            else:
                currentIP=(currentIP+str(i));
#                print("Current IP: "+currentIP);
#else if character is a semi colon
        elif i == ";":
#set arg +1
                arg+=1;
#else if current character is a newline(other 'unimportant' characters are ignored)
        elif i == '\n' or i == '\r\n':
#set arg to zero
            arg = 0;
#other 'unimportant' characters skip resetting the currentIP
#        else:
#            continue
#print the most common IP in IPList, which I think is possible with max and get
    mostCommonIP = max(IPList, key=IPList.get)
#now print that value and the IP sorted(IPList.items[0])
    print("Most Common IP: "+str(mostCommonIP)+" Count: "+str(IPList.get(mostCommonIP)))



def findMostCommonClientIP(log):
# open the file used in command
    file = open(log, 'r');
#set variable for the lines in file
    lines = file.readlines();
#create dictionary for each IP with their counts as keys
    IPList = {};
#set string for the current argument in line, starting with 0
    arg = 0;
#set current IP for appending up to the next semicolon.
    currentIP = "";
#set counter for checking packet type(request or response)
    checkCounter = 0;
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
#            print("Current IP: "+currentIP);
#if arg equals the packet type arguement 8
            if arg==9:
#If checkCounter equals 2 is also true(its the divergent character in the log) and it equals q
                if checkCounter==2 and i=="q":
#Take the saved IP and check if currentIP doesn't match an existing key(is not in the dictionary) #Ideally, I would check if current IP matches IP format here, but those have a LOT of rules to consider..
                    if IPList.get(currentIP)==None:
#                        print("New IP Found: "+currentIP);
#If currentIP does not match a key, create a new one and add 1 to its value
                        IPList[currentIP] = 1
#If currentIP does match a key, set the value of that key +1
                    else:
                        IPList[currentIP] = (IPList.get(currentIP)+1);
#                        value = IPList.get(currentIP)
#                        value+=1
#                        IPList[currentIP] = value
#                        print("+1 Existing IP: "+currentIP);
#if checkCounter equals 2, but i does not equal q, break out of line.
#                elif checkCounter > 2:
#                    checkCounter = 0;
#                    break
#if checkCounter is less than 2, add 1 to checkCounter to get to the correct character.
                elif checkCounter<2:
                    checkCounter+=1;
#If arg equals the source IP argument
            if arg==2:
#check if the character is a semi colon
                if i == ";":
#If character is a semi colon, arg+=1
                    arg+=1;
#If character is not a semicolon, concatinate it to currentIP
                else:
                    currentIP=(currentIP+str(i));
#else if character is a semi colon
            elif i == ";":
#set arg +1
                    arg+=1;
#else if current character is a newline(other 'unimportant' characters are ignored)
            elif i == '\n' or i == '\r\n':
#set arg to zero
                arg = 0;
#after the line has ended, set currentIP back to "" and checkCounter to 0
                currentIP="";
                checkCounter = 0
#other 'unimportant' characters skip resetting the currentIP
#        else:
#            continue
#print the most common Client IP in IPList and its count, not including responses sent by a server.
    mostCommonIP = max(IPList, key=IPList.get)
#now print that value and the IP sorted(IPList.items[0])
    print("Most Common Client IP: "+str(mostCommonIP)+" Count: "+str(IPList.get(mostCommonIP)))



#-----CREATE A MAIN FUNCTION TO CALL HELPER FUNCTIONS-----
def main(args):
    #check if looking for any most common IP, or only clients.
    if (sys.argv[1] == "any"):
    #call the correct helper function
        findMostCommonIP(args);
    elif (sys.argv[1] == "client"):
    #call the correct helper function
        findMostCommonClientIP(args);
    else:
    #end script early and give the user an error message if format is incorrect.
        print("Please use this format: ./commonIP (client/any) (file name) [verbose] ");


#-----CHECK TO SEE IF THIS SCRIPT IS THE MAIN SCRIPT-----
if __name__ == '__main__':
    if 3>len(sys.argv)>1:
        if sys.argv[1] == --help:
            print("./commonIP (client/any) (file name) [verbose]")
            print("verbose will display every time a new IP is found, or an existing one is added.")
            print("'any' option will find all instances of an IP in a log.")
            print("'client' option will ONLY count packets where a client makes a request, NOT responses.")
    elif (len(sys.argv)<3):
#end script early and give the user an error message if format is incorrect.
        print("Please use this format: ./commonIP (client/any) (file name) [verbose]");
        
    else:
        arg_list = sys.argv[2]     # adjust this for the number of args you need sys.argv[-2:] would take the last two.
        main(arg_list)          # call your main function