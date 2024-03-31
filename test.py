import hashlib #work on this later again
import bcrypt
import msvcrt
import random

unallowed=[",", "}", "{", "\\", "|", ";", ">", "<", "[", "]", "%", ":", "/", "*", "$", "@", "!", "^", "&", ".", "#", "+", "=", "-"," "]

salt = bcrypt.gensalt(12)

def masked_input(prompt):
    print(prompt, end='', flush=True)
    password = ''

    while True:
        char = msvcrt.getch().decode('utf-8')
        if char == '\r' or char == '\n':
            break
        
        elif char == '\b':  # for backspace
            if len(password) > 0:
                password = password[:-1]
                print('\b \b', end='', flush=True)  # erase the character
        else:
            password += char
            print('*', end='', flush=True)

    print()
    return password

def sign_up():
    print('---Sign up---')
    userName = input("Enter a username: ").strip()
    
    length = len(userName)
    print(f'Username is {length} long') #r
    if len(userName) <= 3:
        print('Username must be greater then or equal to 4 characters long')
        matchesL = True
        while matchesL == True:
            userName = input('Username: ')
            if len(userName) >= 8:
                print("Username is suceful") #r
                break

    with open("account_sys-lite-\\details.txt",'r') as file:
        content = file.readlines()
        print(content)
        if (f'Username: {userName}\n') in content:
            print("that username already exists. try another one")
            exists = True
            while exists == True:
                userName = input("Username: ").strip()
                if not userName:
                    print("name cannot be empty")
                    exit()
                for i in userName:
                    if i in unallowed:
                        print(f"Username cannot contain '{i}' try again")
                        unallowed_char = True
                        while unallowed_char == True:
                            userName = input("Username: ").strip()
                            if userName not in unallowed:
                                print('succeful')
                                unallowed_char = False
                if userName not in content:
                    exists = False
            
    userPass = masked_input("Enter a password: ").strip()
    
    length = len(userPass)
    print(f'Userpass is {length} long') #r
    if len(userPass) <= 7:
        print('Password must be greater then or equal to 8 characters long')
        matchesL = True
        while matchesL == True:
            userName = masked_input("Enter a password: ")
            if len(userName) >= 8:
                print("Password is suceful") #r
                break
    #make it to so where if the password is too common among all users then they cant use it and make it to so there password requirements for security
    bytesPass = userPass.encode('utf-8')
    hash_pass = bcrypt.hashpw(bytesPass, salt)

    if not userPass:
        print("Password cannot be empty try again later.")
        exit()
        
    userPassConfirm = masked_input("Confirm your password: ").strip() 
    bytesPassConfirm = userPassConfirm.encode('utf-8')

    if not userPassConfirm:
        print("Password cannot be empty try again later.")
        exit()
        
    if bcrypt.checkpw(bytesPassConfirm, hash_pass) != True:
        for i in reversed(range(1,4)):
            print("Passwords do not match try again.")
            print(f'{i} more tries available')
            userPass = masked_input("Enter a password: ").strip()
            bytesPass = userPass.encode('utf-8')
            hash_pass = bcrypt.hashpw(bytesPass, salt)
            userPassConfirm = masked_input("Confirm your password: ").strip()
            bytesPassConfirm = userPassConfirm.encode("utf-8")
            op = bcrypt.checkpw(bytesPassConfirm, hash_pass)
            if op == True:
                print("Password confirmed")
                break
            
    hash_pass = bcrypt.hashpw(bytesPassConfirm, salt)
    
    with open("account_sys-lite-\\details.txt", 'a') as file:
        content = file.write(f'---{userName}---\n')
        length = len(userName)
        file.write(f"Username: {userName}\n")
        file.write(f'Password: {hash_pass}\n')
        # i = '-'
        file.write(f"---{'-'*length}---\n")


sign_up()

#in sign in function make it pull the password from the line under the username it found
#search 2 lines under username for pass in signin function

# print(bcrypt.checkpw(passwrd, hash_pass))

# print(hash_pass, end='\n\n')

# sha512_hasher = hashlib.sha512()
# sha512_hasher.update(username)
# hash_user = sha512_hasher.hexdigest()

# print(hash_user)