import hashlib, argparse

parser = argparse.ArgumentParser(description='Input file names')
parser.add_argument('wordlistfile')                # File argument
parser.add_argument('passwordsfile')
args = parser.parse_args()

def HPsha256(Password):                          # a function used for encrypting passwords to compare the ones given on the list to
    sha256_hash = hashlib.sha256()
    sha256_hash.update(Password.encode('utf-8'))
    return sha256_hash.hexdigest()

wordlist = open(args.passwordsfile, 'r')
hashpswdfile = open(args.wordlistfile, 'r')

lines = hashpswdfile.readlines()     #accesses the data of the file containing hashed passwords and usernames
rawlist = []                
for line in lines:
    rawlist.append(line.rstrip())    #adds them onto a list 
hashpswdfile.close()                 

usernamelist = []
hashpswdlist = []
for user in rawlist:
    user = user.split(':')  # Splits the username and password
    x = user[1]   
    y = user[0]    
    usernamelist.append(y)   # Creates a list of usernames                 
    hashpswdlist.append(x)   # Creates a list of the given hashes
passlist = []                

lines2 = wordlist.readlines()
testlist = []
for line2 in lines2:
    testlist.append(line2.rstrip())     # Adds the raw passwords to a list and strips unnescessary characters
wordlist.close()          
hashlist = []
for password in testlist:
    hashed = HPsha256(password)   # Hashes the password in sha256
    hashlist.append(hashed)


for variable in hashpswdlist:    # Checks if the given hash for the user is in the hashed list of words
    if variable in hashlist:
        location = hashlist.index(variable)
        print(usernamelist[hashpswdlist.index(variable)]+':'+testlist[location])    # Prints it out in the requested format