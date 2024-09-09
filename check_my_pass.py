import requests
import hashlib
import sys

# REQUESTS
def request_api_data(query_char:str) -> str:
    """
    request_api_data(): Takes in an argument(query_char) in upper case and returns a response.
        query_char: The first 5 characters of a hashed password
    """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again.")
    return res

#COUNT
def get_password_leak_count(hashes, hash_to_check) -> str:
    """
    get_password_leak_count(): Takes in two arguments and returns a string accordingly.
        hashes: a response from a url.
        hash_to_check: the tail part of a hashed password
    """
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

#HASHING
def pwned_api_check(password:str) -> str:
    """
    pwned_api_check(): Takes in a password of type string and returns a count.
    """
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)

#RETURNED MESSAGES
def main(args) -> str:
    """
    main(): Takes in an argument of single or multiple passwords checks them and returns a message.
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was found {count} times... you should probably change it.")
        else:
            print(f"{password} was NOT found. Carry on!")
    return "done!"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))