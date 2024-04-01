import hashlib #Only problem left is hashes not matching verification even with same inputs
import msvcrt
import argon2
import os

unallowed=[",", "}", "{", "\\", "|", ";", ">", "<", "[", "]", "%", ":", "/", "*", "$", "@", "!", "^", "&", ".", "#", "+", "=", "-"," "]

def masked_input(prompt):
    print(prompt, end='', flush=True)
    password = ''

    while True:
        char = msvcrt.getch().decode('utf-8')
        if char == '\r' or char == '\n':
            break
        
        elif char == '\b':
            if len(password) > 0:
                password = password[:-1]
                print('\b \b', end='', flush=True)
        else:
            password += char
            print('*', end='', flush=True)

    print()
    return password

salt = os.urandom(16)

def sign_up():
    print('---Sign up---')
    userName = input("Enter a username: ").strip()
    
    length = len(userName)
    if len(userName) <= 3:
        print('Username must be greater then or equal to 4 characters long')
        matchesL = True
        while matchesL == True:
            userName = input('Enter a username: ')
            if len(userName) >= 4:
                break

    with open("PATH\TO\DETAILS.TXT\FILE",'r') as file:
        content = file.readlines()
        if (f'Username: {userName}\n') in content:
            print("That username already exists. Try another one")
            exists = True
            while exists == True:
                userName = input("Enter a username: ").strip()
                if not userName:
                    print("Username cannot be empty")
                    exit()
                for i in userName:
                    if i in unallowed:
                        print(f"username cannot contain '{i}' try again")
                        unallowed_char = True
                        while unallowed_char == True:
                            userName = input("Enter a username: ").strip()
                            if userName not in unallowed:
                                unallowed_char = False
                if userName not in content:
                    exists = False
    
    sha512_hasher = hashlib.sha512()             
    sha512_hasher.update(userName.encode('utf-8'))
    hash_user = sha512_hasher.hexdigest()
            
    userPass = masked_input("Enter a password: ").strip()
    
    length = len(userPass)
    if len(userPass) <= 7:
        print('Password must be greater then or equal to 8 characters long')
        matchesL = True
        while matchesL == True:
            userPass = masked_input("Enter a password: ")
            if len(userPass) >= 8:
                break
        
    hash_pass = argon2.low_level.hash_secret(userPass.encode('utf-8'),salt,time_cost=16,memory_cost=2**15, parallelism=2,hash_len=32,
                                         type=argon2.low_level.Type.ID)
        
    userPassConfirm = masked_input("Confirm your password: ").strip()
        
    if argon2.low_level.verify_secret(hash_pass, userPassConfirm.encode('utf-8'), type=argon2.low_level.Type.ID) != True:
        for i in reversed(range(1,4)):
            print("Passwords do not match try again.")
            print(f'{i} more tries available')
            userPass = masked_input("Enter a password: ").strip()
            hash_pass = argon2.low_level.hash_secret(userPass.encode('utf-8'),salt,time_cost=16,memory_cost=2**15, parallelism=2,hash_len=32,
                                         type=argon2.low_level.Type.ID)
            userPassConfirm = masked_input("Confirm your password: ").strip()
            op = argon2.low_level.verify_secret(hash_pass, userPassConfirm.encode('utf-8'), type=argon2.low_level.Type.ID)
            if op == True:
                break
            
    hash_pass = argon2.low_level.hash_secret(userPassConfirm.encode('utf-8'),salt,time_cost=16,memory_cost=2**15, parallelism=2,hash_len=32,
                                         type=argon2.low_level.Type.ID)
    
    with open("PATH\TO\DETAILS.TXT\FILE", 'ab') as file: #Ab append bytes
        length = len(userName)
        content = file.write(f'---{userName}---\n'.encode('utf-8'))
        file.write(f"Username: {userName}\n".encode('utf-8'))
        file.write(f'Password = {hash_pass} , Username: {userName}\n'.encode('utf-8'))
        file.write(f'{hash_user}'.encode('utf-8'))
        file.write('\n'.encode('utf-8'))
        file.write(hash_pass+'\n'.encode('utf-8'))
        file.write(f"---{'-'*length}---\n".encode('utf-8'))
        print("Account created.")

def sign_in():
    with open('PATH\TO\DETAILS.TXT\FILE', 'rb') as file: #Open bytes #only problem left is wrong hashes
        readable = file.readlines()
        userName = input("Username: ")
        sha512_hasher = hashlib.sha512()
        sha512_hasher.update(userName.encode('utf-8'))
        hash_user = sha512_hasher.hexdigest()
        indexingHash = readable.index(f'Username: {userName}\n'.encode('utf-8'),0,-1)+2
        if f'---{userName}---\n'.encode("utf-8") in readable and f'Username: {userName}\n'.encode('utf-8') in readable and hash_user.encode('utf-8') in readable[indexingHash]:
            print("found user")
            userC = readable.index(f'Username: {userName}\n'.encode('utf-8'),0,-1) #Line number
            
            userPass = masked_input("Password: ").strip() #Password
            passLine = readable[userC+3] #Password hash line

            try:
                if argon2.low_level.verify_secret(passLine, userPass.encode('utf-8')+'\n'.encode("utf-8"), type=argon2.low_level.Type.ID) == True:
                    print("account entered")
            except argon2.exceptions.VerificationError:
                print("password hashes dont match")
            
        else:
            print("User not found. Consider signing up.") #User not found

options = input("what would you like to do?(su\\si): ")

if options == 'su':
    sign_up()

elif options == 'si':
    sign_in()