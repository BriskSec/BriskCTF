import pickle

with open('/tmp/serial', 'r') as f:
    pickle.loads(f.read())
