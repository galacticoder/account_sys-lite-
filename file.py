import hashlib #work on this later again #add id system #only problem left in sign in function is bcrypt generation of different hashes with same text find way to fix that then sign in function done and then able to work on security and cutomization of the script and ID SYSTEM 
import bcrypt
import msvcrt
import random

unallowed=[",", "}", "{", "\\", "|", ";", ">", "<", "[", "]", "%", ":", "/", "*", "$", "@", "!", "^", "&", ".", "#", "+", "=", "-"," "]

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

salt = bcrypt.gensalt(12)

def sign_up():
    print('---Sign up---')
    userName = input("Enter a username: ").strip()
    
    length = len(userName)
    print(f'Username is {length} long') #r
    if len(userName) <= 3:
        print('Username must be greater then or equal to 4 characters long')
        matchesL = True
        while matchesL == True:
            userName = input('Enter a username: ')
            if len(userName) >= 8:
                print("username is suceful") #r
                break

    with open("account_sys-lite-\\details.txt",'r') as file:
        content = file.readlines()
        print(content)
        if (f'Username: {userName}\n') in content:
            print("that username already exists. try another one")
            exists = True
            while exists == True:
                userName = input("Enter a username: ").strip()
                if not userName:
                    print("name cannot be empty")
                    exit()
                for i in userName:
                    if i in unallowed:
                        print(f"username cannot contain '{i}' try again")
                        unallowed_char = True
                        while unallowed_char == True:
                            userName = input("Enter a username: ").strip()
                            if userName not in unallowed:
                                print('succeful')
                                unallowed_char = False
                if userName not in content:
                    exists = False
    sha512_hasher = hashlib.sha512()             
    sha512_hasher.update(userName.encode('utf-8'))
    hash_user = sha512_hasher.hexdigest()
            
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
    
    with open("account_sys-lite-\\details.txt", 'ab') as file: #ab append bytes
        length = len(userName)
        content = file.write(f'---{userName}---\n'.encode('utf-8'))
        file.write(f"Username: {userName}\n".encode('utf-8'))
        file.write(f'Password = {hash_pass} , Username: {userName}\n'.encode('utf-8'))
        file.write(f'{hash_user}'.encode('utf-8'))
        file.write('\n'.encode('utf-8'))
        file.write(hash_pass+'\n'.encode('utf-8'))
        # file.write('\n'.encode('utf-8'))
        file.write(f"---{'-'*length}---\n".encode('utf-8'))

def sign_in():
    # try:
        with open('account_sys-lite-\\details.txt', 'rb') as file: #open bytes #only problem left is wrong hashes
            readable = file.readlines()
            print(f'"{readable}"')
            userName = input("Username: ")
            sha512_hasher = hashlib.sha512()
            sha512_hasher.update(userName.encode('utf-8'))
            hash_user = sha512_hasher.hexdigest()
            print(hash_user,end='\n')
            indexingHash = readable.index(f'Username: {userName}\n'.encode('utf-8'),0,-1)+2
            print(readable[indexingHash])
            if f'---{userName}---\n'.encode("utf-8") in readable and f'Username: {userName}\n'.encode('utf-8') in readable and hash_user.encode('utf-8') in readable[indexingHash]:
                print("found user")
                # for line in readable:
                user = readable.index(f'---{userName}---\n'.encode('utf-8'),0,-1) #line number
                userC = readable.index(f'Username: {userName}\n'.encode('utf-8'),0,-1) #line number
                
                print(user) #r
                
                list = [] #r
                print("som") #r
                
                print(readable[user]) #r
                print(readable[userC]) #r
                
                # print(file.readlines(f'---{userName}---\n'))
                userPass = masked_input("Password: ").strip()
                userPassBytes = userPass.encode('utf-8')
                print(userPassBytes)
                userPassHash = bcrypt.hashpw(userPassBytes, salt) #r
                print(userPassHash)
                userPassHash = userPassHash+'\n'.encode('utf-8')
                print(userPassHash)
                
                # userHashStr = userC+1#line number #gives value error if wrong hash
                print(f"line is {userC+3}") #r
                
                passLine = readable[userC+3]#password line
                
                print(passLine, end='\n')
                # print(f"Password = {userPassBytes} , Username: {userName}\n")

                if bcrypt.checkpw(userPassBytes,passLine) == True:
                    print("account entered")
                else:
                    print("wrong hash")
                
            else:
                print("not found") #user not found
    # except ValueError:
    #     print("wrong hash")
    #     print("failed to enter account")



sign_up()
# sign_in()

#in sign in function make it pull the password from the line under the username it found
#search 2 lines under username for pass in signin function

# print(bcrypt.checkpw(passwrd, hash_pass))

# print(hash_pass, end='\n\n')

# sha512_hasher = hashlib.sha512()
# sha512_hasher.update(username)
# hash_user = sha512_hasher.hexdigest()

# print(hash_user)