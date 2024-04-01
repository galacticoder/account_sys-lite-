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

# import bcrypt

# some = bcrypt.gensalt(12)

# text = "someone"

# data = bcrypt.hashpw(text.encode('utf-8'),some)
# with open('something.txt','w') as file:
#     writableD = file.write(str(data))

# with open('something.txt','r') as file:
#     readableD = file.read()
#     readableD = readableD.encode('utf-8').strip()
#     print(readableD)

#     data = bcrypt.hashpw(text.encode('utf-8'),some)

#     # some = str(data).encode("utf-8")
#     # print(some)

#     print(bcrypt.checkpw(data,readableD))
# # print(bcrypt.hashpw('text'.encode('utf-8'),salt))
import bcrypt

salt = bcrypt.gensalt(12)

def hashing(x,y):
    hashX = bcrypt.hashpw(x.encode('utf-8'),salt)
    hashy = bcrypt.hashpw(y.encode('utf-8'),salt)
    print('\n')
    # print(bcrypt.checkpw(hashy,hashX))
    # print(str(hashX),'\n'+str(hashy).strip())
    with open('something.txt','ab') as file:
        file.writelines(["pass: ".encode('utf-8')+hashX,'\n'.encode('utf-8'),'passy: '.encode('utf-8')+hashy])
        file.writelines(["\nsomething".encode('utf-8')])
    # with open('something.txt','a') as file:
    #     file.write("\n---")
    with open('something.txt', 'rb') as file:
        readable = file.read()
        print(readable)
        # print("\n")
        # print(readable[])
        
    
    


hashing('text','text')
















