# import bcrypt

# #tagged in 'r' means remove during actual release only implented for testing

# with open('account_sys-lite-\\details.txt', 'r') as file:
#     readable = file.readlines()
#     print(f'"{readable}"')
#     userName = input("Username: ")
#     if f'---{userName}---\n' in readable and f'Username: {userName}\n' in readable:
#         print("found user")
#         # for line in readable:
#         user = readable.index(f'---{userName}---\n',0,-1) #line number
#         userC = readable.index(f'Username: {userName}\n',0,-1) #line number
        
#         print(user) #r
        
#         list = []
#         print("som")
        
#         print(readable[user])
#         print(readable[userC])
        
#         # print(file.readlines(f'---{userName}---\n'))
#         userPass = input("Password: ").strip()
#         bytesPass = userPass.encode('utf-8')
#         hash_userpass = bcrypt.hashpw(bytesPass, salt)
        
#         userHashStr = readable.index(f'Password: {userPass} :: Username: {userName}\n',0,-1) #line number
#         passBytes = userHashStr.encode('utf-8') 
#         st = 'Password: '.strip()
#         print(st) #r
#         for sub in st:
#             replacing = userHashStr.replace(' ' + sub + ' ', ' ') #replacing = line of pass word
#         print(replacing)
            
#         bytes = userPass.encode('utf-8')
#         bcrypt.checkpw(bytes, )
#     else:
#         print("not found")

# import bcrypt

# salt = bcrypt.gensalt(12)

# test = '$2b$12$V6vesAyoLgC1qfbej5epyuBvxjZs86SJjNNiC/u6wPMTAS.3mYzb2'.encode('utf-8')
# print(test)

# testing = bcrypt.hashpw(test,salt)
# print(bcrypt.hashpw('someone'.encode('utf-8'),salt))


# print(bcrypt.checkpw(test,testing))



# import hashlib

# userName = "someone"
# sha512_hasher = hashlib.sha512()
# sha512_hasher.update(userName.encode('utf-8'))
# hash_user = sha512_hasher.hexdigest()

# print(hash_user,end='\n')

# name = 'someone'
# sha512_hasher = hashlib.sha512()
# sha512_hasher.update(name.encode('utf-8'))
# namehash = sha512_hasher.hexdigest()
# print(namehash)










import bcrypt

some = bcrypt.gensalt(12)
salt = bcrypt.gensalt(12)
print(bcrypt.hashpw('text'.encode('utf-8'),some))

print(bcrypt.hashpw('text'.encode('utf-8'),salt))




















