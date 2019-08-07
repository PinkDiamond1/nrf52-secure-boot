from pybitcointools import *

def read_the_dump(path):
    f = open(path, "r")
    lines = f.readlines()

    bytes = []

    for line in lines:
        temp = line.split(" ")[1:9]
        for two_byte in temp:
            bytes.append(two_byte[0:2])
            bytes.append(two_byte[2:4])

    bytes.reverse()
    f.close()

    return bytes

def make_the_keys(bytes):
    keys = []

    for i in range(len(bytes)):
        temp = bytes[i: i+32]
        key_string = ''.join(temp)
        if key_string == "0000000000000000000000000000000000000000000000000000000000000000":
            continue
        keys.append(''.join(temp))
    print("Total number of private keys formed: " + str(len(keys)) )
    return keys

def main():
    user_path = raw_input("Enter the path of SRAM hex dump")
    bytes = read_the_dump(user_path)
    keys = make_the_keys(bytes)

    error_keys = []
    keys_checked = 0
    found_flag = False
    found_priv_key = ''
    found_pub_key = ''

    for key in keys:

        try:
            temp_pub_key = privtopub(key)[2:66]
            if keys.index(temp_pub_key.lower()) >= 0:
                found_flag = True
                found_priv_key = key
                found_pub_key = keys[keys.index(temp_pub_key.lower())]
                break
        except Exception as e:
            if repr(e) == "Exception('Invalid privkey',)":
                error_keys.append(key)

        keys_checked = keys_checked + 1

        if keys_checked%1000 == 0:
            print("Number of keys checked till now: " + str(keys_checked))

    print ("Number of invalid keys: " + str(len(error_keys)) )
    if found_flag:
        print("Found the private key: 0x" + found_priv_key)
        print("Found the public key: 0x" + found_pub_key)
    else:
        print("You might wanna try out these Error Keys(Not checked)")
        print(error_keys)

main()
