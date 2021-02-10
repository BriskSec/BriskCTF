# From: http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html

import hashlib,re

f = open("wordlist","r").readlines()
findit = re.compile("^0e[0-9]{8}") #\d supports unicode, 0-9 is faster
for entry in f:
        entry = entry.rstrip("\n") # strip new line
        m = hashlib.md5(str(entry)).hexdigest() # save md5 hash instead of reference
        m = m[0:10] # substr(m,0,10)
        if (findit.search(m) != None):  # if match found
                print("%s: " % str(m)), # print hash: 
                print(str(entry))       # print wordlist entry

# wordlist containing 000000-999999
# Check if 1st 10 digits of each resulting MD5 is 0e followed by numbers. 