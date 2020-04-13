# SecureWebApp   

A LOTR style groupchat that the admin has full control over. Only users added by the admin can decrypt the posts/post a message themself. 
It implements a Hybrid Crypto System using RSA and AES in mode CBC - RSA as each user has a public and private key, and AES as the group 
itself has a symmetric key in which all posts are encrypted in. Two libraries are used to do this - Cryptography for AES and 
Pycryptodome for RSA. The web framework used is Django and the front end was enhanced using bootstrap.

### Adding a new user:
When a new user is added, the current symmetric key is gotten from the 
Fellowship group. It is then encrypted using their public key and stored in the SQLITE database with their other information. When a user
clicks "decode messages" the encoded symmetric key is decoded using their private key and then that decoded symmetric key is used to 
decrypt the posts.

### Removing a user:
When a user is removed, the symmtric key has to be updated. This means a new one is generated and all the messages are decrypted 
using the old key and re-encrypted using the new key. All users have their version of the symmetric key encoded with their 
public key and stored back in the database.

## Master Branch  
This is the branch that has been deployed on heroku: https://lotrsecuregroupchat.herokuapp.com/signup_show  
TODO: Add in error handling and a way to download the private key onto the local database.

## localsecurewebapp Branch  
This is the branch that can be run locally.   
Git clone this branch and navigate to the folder.  
To get the dependencies, set up the database and get the code running run -   
pip install -r requirements.txt   
python manage.py makemigrations  
python manage.py migrate  
python manage.py runserver 8080  
Go to localhost:8080 and the sign up page should appear. This is the admin sign up page.  
Sign up using the username: Admin and the password can be whatever you want. Do this only 
once. After that sign up use the url that ends in "signup_show".

