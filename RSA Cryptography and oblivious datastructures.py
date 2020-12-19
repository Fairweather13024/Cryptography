#!/usr/bin/env python
# coding: utf-8

# ---
# 
# # Fairweather's CS110 Final Project 
# # Cryptographic Algorithms and Oblivious Datastructures
# 
# ---

# In[42]:


NAME = "Mark Eric Fairweather"
COLLABORATORS = "Mark Gacoka"


# ---
# 

# # Cryptography

# ## #context
# When sending a file over the internet, we run the risk of the file being intercepted and being read or altered by the interceptor. If this happens, great problems may arise because either the transmitted information was supposed to be confidential, or the sent information will convey the wrong message or cause the execution of the wrong instructions. Therefore, encryption of data is especially useful in:
# 
# a) Rendering HTTP requests where information is retrieved from a server
# 
# b) Securing information on one's personal computer
# 
# c) Sending sensitive files across the internet such as confidential emails
# 
# d) Transacting over the internet, and
# 
# e) Authentication systems with user signatures
# 
# In our situation, we need to transmit large messages securely between users. This serves as a solid foundation for the application of various cryptographic techniques. I will therefore implement a cryptographic technique that satisfies the 5 cryptographic pillars listed below.
# 
# #### The Pillars Of Cryptography:
# 
# a)Confidentiality - ensuring that information is kept private.
# 
# b)Integrity - detecting unauthorized interception and alteration of the information.
# 
# c)Authentication - verifying the identity of the receiver.
# 
# d)Authorization - determining the user's privilege to access the information.
# 
# e)Non-repudiation - verifying receipt of information.
# 
# #### Relevance
# It is becoming increasingly important to have secure data with the advancement of computational technologies because humans are automating their complex lives and generating more intimate data about themselves with each passing day. This data needs to be secure because breeches would be potentially paralyzing to the smooth operation of people's lives. Moreso, with data comes the power to convince, advance or manipulate society, therefore, as the power of individual data is being realized, it is best that it remains secure until a well-developed framework is implemented to make use of people's data with their consent.
# 
# 
# Historically, cryptography was especially important in wartime because it allowed for the execution of strategic moves, or to prepare for the enemy accordingly.  
# Also, because the proliferation of cloud computing is becoming an ever more imminent reality, shared cloud services need to be very secure with people's information in order for the business model to work. This warrants the application of encryption on data stored on remote servers which run the cloud services. 
# 
# Cryptology - Developments during World Wars I and II | Britannica. (2020). In Encyclopædia Britannica. Retrieved from https://www.britannica.com/topic/cryptology/Developments-during-World-Wars-I-and-II
# ‌
# 
# Cryptography in the Cloud: Securing Cloud Data with Encryption. (2015, June 8). Retrieved December 16, 2020, from Digital Guardian website: https://digitalguardian.com/blog/cryptography-cloud-securing-cloud-data-encryption#:~:text=A%20Definition%20of%20Cryptography%20in,providers%20is%20protected%20with%20encryption.

# ---

# ## Question 0 [#responsibility]

# In[2]:


from IPython.display import Image
Image(filename=r"cs110.PNG")


# ---

# ## 1. Implementing The RSA Algorithm
# 
# The RSA algorithm is one of the most widely used and most developed encryption/decryption standards today. 
# The RSA algorithm implements an asymmetric key application, where there is a distinct public and private key. 
# The public key is shared between users while the private key is not. 
# 
# The algorithm relies on the computational difficulty of computing the product of two large prime numbers which creates a massive probability space with which the actual key is hidden within (for example 2^128 permutations). 
# The RSA algorithm is often secured using SHA-128, SHA-192 or SHA-256 which are hashing algorithms that compute up to 32 bit words (SHA stands for Secure Hashing Algorithms). 

# In[2]:


import random, math, numpy
from pprint import pprint


# In[67]:


class RSA:
    '''
    The RSA implementation in its standard form uses variables that need to be 
    defined initially for clarity because they take simle letter forms.

    n - Modular encryption key
    e - Encryption key

    n - Modular key for decryption
    d - reverse decryption key
    phiN - Secret key that gives the exponent of

    x - Decrypting key
    y - g^x%p used in the encryption process
    

    The private key will be a function of e and N
    The public key with be a function of d and N

    This implementation is constructed from Oktaviana, et. al. (ND) Comparative Analysis of 
    RSA and ElGamal Cryptographic Public-key Algorithms. Retrieved from https://osf.io/x56df/download#:~:text=RSA%20produces%20six%20variables%20(P,the%20time%20of%20key%20generation. 
    '''
    
    
    
    def __init__(self, text):
        '''
        Calls the main function which executes the ecbcyption and decryption
        
        Inputs
        ____
        text - str
        Message to be encrypted and decrypted
        '''
        self.mainRSA1(text)
        
    

    def egcd(self, a, b):
        '''Generates the greatest common denominator of e

        Parameters
        _____
        a, b  - Former encryption keys to be transformed

        Outputs
        _____
        old_r, old_s, old_t - The gcd, and x and y keys

        '''
        #The old___ help us store information that will be used in back subsitution
        s = 0
        old_s = 1
        t = 1
        old_t = 0
        r = b
        old_r = a

        #Base case as long as the gcd is not 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        #returns gcd, x, y
        return old_r, old_s, old_t


    

    def modularInverse(self, a, b):
        '''Generates the modular inverse 
        
        Inputs
        ____
        a,b - Encryption keys for the modular calculation by the gcd
        
        Output
        ____
        
        x -  Generates a decryption key that is derived from the gcd

        '''
        gcd, x, y = self.egcd(a, b)

        #If x is negative we add back the modular and return x
        if x < 0:
            x += b
        return x
    
    
    

    def encrypt(self, e, N, text):
        '''
        Encrypts the text using the ord() builtin function and constructs a cipher text using the power method
        
        Inputs
        ______
        e - encryption key whihc is determined initially
        N - product of 2 prime numbers to give a 2048 bit key
        text - plain text to be encrypted
        
        Outputs
        ______
        cipher - str
        Constructed cipher text
        
        '''
        cipher = ""    #Initiating the text to be returned
        
        #Looping over the input text and converting all characters into bits
        for i in text:
            current_char = ord(i)
            
            #Constructing the cipher text using the power function
            cipher += str(pow(current_char, e, N)) + " "

        return cipher

    
    
    
    
    def decrypt(self, d, N, cipher):
        '''
        Decrypts the text using the int() builtin function and constructs a plain text using the power method
        
        Inputs
        ______
        d - decryption key whihc is determined initially
        N - product of 2 prime numbers to give a 2048 bit key
        cipher - encrypted text to be decrypted
        
        Outputs
        ______
        msg - str
        Decrypted plain text
        
        '''
        message = ""   #Initiating the plain text string to be returned

        #Accessing each character in the cipher text
        parts = cipher.split()
        for i in parts:
            if i:
                current_char = int(i)    #Converting each byte into an int to comouet the reverse operation
                message += chr(pow(current_char, d, N))    #Constructing the plain text using characters

        return message

    def mainRSA1(self, text):
        '''This function calls the encryption and decryption functions and prints the encrypted 
        and decrypted messages for verification.
        
        Inputs
        _____
        text - str
        Text to be encrypted 
        
        Output
        ______
        Encrypted message - The text displayed as cipher text
        Decrypted message - The cipher text displayed as plain text
        '''
        
        keysize = 32
        #Setting the prime numbers to construct N
        p = 11
        q = 13
        N = p*q   #Encryption and decryption key
        phiN = (p-1)*(q-1) #This is the secret key for the exponent of d

        e = 13
        d = self.modularInverse(e, phiN)

        #Calls the functions to encrypt and decrpyt the messages using RSA
        encrypted_message = self.encrypt(e, N, text)
        decrypted_message = self.decrypt(d, N, encrypted_message)

        #Displaying the message as is transmitted and when it is decrypted
        print(f"Encrypted message: {encrypted_message}")
        print(f"Decrypted message: {decrypted_message}")
        return encrypted_message


# In[68]:


plain_text = "Hello RSA"
rsa = RSA(plain_text)


# ### Edge Cases
# 
# I implement the following edge cases to test for:
# 
# 1. Whether the algorithm writes non-existing values into the input and outputs
# 
# 2. Whether blank spaces are encrypted correctly. This ensures that the encrypted text will contain the same structural format as legible plain text while I also test whether the modular function works correctly.
# 
# 3. Whether symbols are encrypted correctly. This ensures that the meaning of the decrypted text will not have been changed after encryption. 
# 
# 4. Whether punctuation marks are encrypted correctly. This ensures that the meaning of the decrypted text will not have been changed after encryption. 
# 
# I also run the test cases multiple times to assertain that the correct values were not generated by luck, but will deterministically by encrypted and decrypted the same way.

# In[5]:


assert rsa.encrypt(13, 143, "") == ""
assert int(rsa.encrypt(13, 143, " ")) == 32
assert int(rsa.encrypt(13, 143, ".")) == 85 
assert int(rsa.encrypt(13, 143, "!")) == 33 


# ### Sample Cases
# 
# I implement the following sample cases to test for:
# 
# 1. Whether plain text is encrypted and decrypted correctly.
# 2. Whether a sentence is encrypted and decrypted correctly.
# 3. Whether numbers are encrypted and decrypted correctly.

# In[6]:


RSA('Hello')
RSA('My name is Mark Eric Fairweather. I have just successfully completed my fall semester of Sophomore year!')
RSA('Hello, here is my SSN incase you are cheeky: 123 -12-1234')


# ## Stress Case
# 
# I chose an exceedingly long txt file provided by minerva in the Trie tree assignment because this particular implementation grows in time complexity very rapidly. Therefore, it is worth knowing how much data one can pass before the output throws an error. 
# 
# This allows me to suggest to the user that they can ave the encrypted message in a txt file and decode it later without necessarily printing the output. 

# In[11]:


import urllib.request
response = urllib.request.urlopen('http://bit.ly/CS110-Shakespeare')
words = str()


for line in response:
    line = line.decode(encoding = 'utf-8')
    #line = filter(lambda i: i not in bad_chars, line)
    words += " ".join(line)

         
RSA(words[:1000])


# ## Discussion
# 
# This algorithm works, but like a toy cryptographic algorithm because one must create the encryption keys for the modular inverse as prime numbers to begin with.
# 
# A better implementation generates the keys internally, based on a probabilistic implementation, hereby affording the RSA algorithm more security.

# # #Part 2
# 
# ---

# In[89]:


class RSA2:
    '''
    This implementation generates its own keys for encryption, which contributes to its security.
    The RSA implementation in its standard form uses variables that need to be 
    defined initially for clarity because they take simle letter forms.

    n - Modular encryption key
    e - Encryption key

    n - Modular key for decryption
    d - reverse decryption key
    phiN - Secret key that gives the exponent of

    x - Decrypting key
    y - g^x%p used in the encryption process
    

    The private key will be a function of e and N
    The public key with be a function of d and N

    This implementation is constructed from Oktaviana, et. al. (ND) Comparative Analysis of 
    RSA and ElGamal Cryptographic Public-key Algorithms. Retrieved from https://osf.io/x56df/download#:~:text=RSA%20produces%20six%20variables%20(P,the%20time%20of%20key%20generation. 
    '''
    def __init__(self, text):
        '''
        Passing the main operation to encrypt and decrypt the information
        '''
        self.mainRSA2(text)


    def rabinMiller(self, n, d):
        '''
        Uses probability to determine if a number is prime
        
        Inputs
        -____
        n,d - Encryption keys for the modular function
        
        Ouutput
        _____
        Boolean - Is the number prime or not
        
        '''
        a = random.randint(2, (n - 2) - 2)
        x = pow(a, int(d), n) # a^d%n
        if x == 1 or x == n - 1:
            return True

        # square key x
        while d != n - 1:
            x = pow(x, 2, n)
            d *= 2
        #Checking if x is prime
            if x == 1:
                return False
            elif x == n - 1:
                return True
        return False

    
    
    def isPrime(self, n):
        """
            return True if n prime
            fall back to rabinMiller if uncertain
        """

        # 0, 1, -ve numbers not prime
        if n < 2:
            return False

        # low prime numbers to save time
        lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

        # if in lowPrimes
        if n in lowPrimes:
            return True

        # if low primes divide into n
        for prime in lowPrimes:
            if n % prime == 0:
                return False

        #Generating number c such that c * 2 ^ r = n - 1
        c = n - 1 
        while c % 2 == 0:
            # makes c odd
            c /= 2 

        # prove not prime 128 times
        for i in range(128):
            if not self.rabinMiller(n, c):
                return False

        return True

    def generateKeys(self, keysize=1024):
        '''
        Uses prime numbers to generate internal keys for the modular functions.
        
        Parameters
        _____
        Keysize = The key size to be generated mathematically
        
        '''
        e = d = N = 0

        # get prime nums, p & q
        p = self.generateLargePrime(keysize)
        q = self.generateLargePrime(keysize)

        N = p * q #Encyption key with modulus function
        phiN = (p - 1) * (q - 1) 

        # choose e
        # e is coprime with phiN & 1 < e <= phiN
        while True:
            e = random.randrange(2 ** (keysize - 1), 2 ** keysize - 1)
            if (self.isCoPrime(e, phiN)):
                break

        # Generating key 'd'
        # d is mod inv of e with respect to phiN, e * d (mod phiN) = 1
        d = self.modularInv(e, phiN)

        return e, d, N

    def generateLargePrime(self, keysize):
        """
            Generates and returns a random large prime number of keysize bits in size
        """

        while True:
            num = random.randrange(2 ** (keysize - 1), 2 ** keysize - 1)
            if (self.isPrime(num)):
                return num

    def isCoPrime(self, p, q):
        """
        Checks if the GCD is = 1
    
        """

        return self.gcd(p, q) == 1

    def gcd(self, p, q):
        """
        Updates and exchanges p and q as remainders of their inverse computation
        
        """

        while q:
            p, q = q, p % q
        return p

    def egcd(self, a, b):
        '''
        Euclidan algorithm to find x and y
        
        '''

        s = 0; old_s = 1
        t = 1; old_t = 0
        r = b; old_r = a

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        # return gcd, x, y
        return old_r, old_s, old_t

    def modularInv(self, a, b):
        '''Generates the modular inverse 
        
        Inputs
        ____
        a,b - Encryption keys for the modular calculation by the gcd
        
        Output
        ____
        
        x -  Generates a decryption key that is derived from the gcd

        '''
        gcd, x, y = self.egcd(a, b)

        if x < 0:
            x += b

        return x

    def encrypt(self, e, N, text):
        '''
        Encrypts the text using the ord() builtin function and constructs a cipher text using the power method
        
        Inputs
        ______
        e - encryption key whihc is determined initially
        N - product of 2 prime numbers to give a 2048 bit key
        text - plain text to be encrypted
        
        Outputs
        ______
        cipher - str
        Constructed cipher text
        
        '''
        cipher = ""    #Initiating the text to be returned
        
        #Looping over the input text and converting all characters into bits
        for i in text:
            current_char = ord(i)
            
            #Constructing the cipher text using the power function
            cipher += str(pow(current_char, e, N)) + " "

        return cipher

    def decrypt(self, d, N, cipher):
        '''
        Decrypts the text using the int() builtin function and constructs a plain text using the power method
        
        Inputs
        ______
        d - decryption key whihc is determined initially
        N - product of 2 prime numbers to give a 2048 bit key
        cipher - encrypted text to be decrypted
        
        Outputs
        ______
        msg - str
        Decrypted plain text
        '''
        message = ""   #Initiating the plain text string to be returned

        #Accessing each character in the cipher text
        parts = cipher.split()
        for i in parts:
            if i:
                current_char = int(i)    #Converting each byte into an int to comouet the reverse operation
                message += chr(pow(current_char, d, N))    #Constructing the plain text using characters

        return message

    def mainRSA2(self, text):
        '''This function calls the encryption and decryption functions and prints the encrypted 
        and decrypted messages for verification.
        
        Inputs
        _____
        text - str
        Text to be encrypted 
        
        Output
        ______
        Encrypted message - The text displayed as cipher text
        Decrypted message - The cipher text displayed as plain text
        '''

        keysize = 32
        
        #Applying the generate key method for the encryption keys
        e, d, N = self.generateKeys(keysize)

        #Calls the functions to encrypt and decrpyt the messages using RSA
        encrypted_message = self.encrypt(e, N, text)
        decrypted_message = self.decrypt(d, N, encrypted_message)

        #Displaying the message as is transmitted and when it is decrypted
        print(f"Encrypted message: {encrypted_message}")
        print(f"Decrypted message: {decrypted_message}")


# In[90]:


plain_text = "Hello RSA"
rsa2 = RSA2(plain_text)


# In[94]:


#Edge cases
rsa3 = RSA2('')
rsa4 = RSA2('.')
rsa5 = RSA2('!')


#Sample cases

rsa6 = RSA2('My name is Mark Eric Fairweather. I have just successfully completed my fall semester of Sophomore year!')
rsa7 = RSA('Hello, here is my SSN incase you are cheeky: 123 -12-1234')


# In[95]:


import urllib.request
response = urllib.request.urlopen('http://bit.ly/CS110-Shakespeare')
words = str()


for line in response:
    line = line.decode(encoding = 'utf-8')
    #line = filter(lambda i: i not in bad_chars, line)
    words += " ".join(line)

         
RSA2(words[:1000])


# ### Discussion 
# ### #complexityanalysis
# 
# Given that the encryption methods of the RSA algorithm rely on the length of the key, the modular function, the Euclidian GCD and exponentiation, the time complexity of this algorithm is O(N^3) where is the size of the input. 
# 
# The modular inverse function operates on each input value as a division/multiplication operation log n times. Given that we pass N inputs, we expect an upper and lower bound of $\theta$ (n log n). Each multiplication/ division operation also takes O(log n) time complexity, hence, overall the modular inverse method takes $\theta$ (log n^3).
# 
# The Euclidian GCD takes O(N) time complexity because the divisions continue until the remainders are kept for each input operation. 
# 
# Lastly, the inverse of each input is calculated with a time complexity of O(log n^2). 

# # Part 3 
# ---

# ## Constructing My Algorithm
# ‌
# I will implement an algorithm that is inspired by the Advanced Encryption Standard (AES) algorithm and the Rivest, Shamir, Adleman algorithm (RSA). I have chosen to implement a structural algorithm that transforms plain text into secure cypher text using a public and private key (asymmetric key) as RSA would, but with an AES algorithm's speed. I have also incorporated random generators within the algorithm to expand the probability space of a particular combination of operations occurring. This is simplistic, but it accounts for how difficult it is to permute over 2^256 combinations, let alone random permutations of the same. 
# 
# The algorithm takes the following form:
# 
# a) The binary text is transformed into a matrix within an oblivious "graph" like parent structure.
# 
# b) The size of the matrix is randomly selected in order to randomly dictate the size of the padding, or "noise" to make the matrices identical.
# 
# c) The matrix data is scrambled using another matrix which should ideally be periodically changed (we will not do this). A simple shuffle should suffice. Since this scrambling matrix is stored locally, the decyphering phase would just reconstruct the words using the matrix and the operation that was conducted.
# 
# d) The order of the matrixes which is stored in the private key is then generated and hashed in order to scramble the order of the matrices.
# 
# e) The public key then hashes all the information in the matrices, and this is what is sent or stored. 
# 
# The decryption reverses steps e, d, c, and a. However, between c and a, the algorithm removes the padding from the last matrix.  
# 
# My implementation applies an oblivious data structure for extra security. An oblivious data structure does not give any information about its inner operations, and only displays a return value. My data structure takes the form of a tree with all leaves/nodes at depth 1 but a pseudorandom function determines the nodes' size. The matrix/ 2D array size at the node determines the inner operations, and the data passed. Therefore, there is no way for an attacker to determine which operations were conducted by just looking at large amounts of encrypted data. 
# 
# The root of the tree is a key which is made up of all the values of the order in which the corresponding matrices/grids were created. The keys are created by incrementing from the prime numbers between 1000 to 9999 for an ample number of matrices to be generated, and for each matrix to have a key with the same length. This root/key forms the asymmetrical portion of my algorithmic implementation. The user or any other party will never access the generated key; hence, they will never know its range or composition. Also, being that the keys for each node are prime numbers, there is no simple mathematical relationship that can be used to derive the next key if one does not know that prime numbers are in use, or their range. 
# 
# ### Comparison
# The AES algorithm, though intensive, offers only three levels of security where in the event of a generation of a related key, the security of the system could be jeopardised. Related keys allow the attacker to use a lot of data to develop the keys using mathematical relationships that are unknown to them but can be derived. Therefore, my algorithm solves this by generating an internal key that only stores information about the order of operations. Therefore, in the very unlikely event that someone knows how large the key is, and what its values are, they would only be able to find out the order of matrices whose size they do not know, and whose information they cannot decipher without the internal scrambling matrix. 

# In[86]:


from IPython.display import Image
Image(filename=r"crypto.PNG")


# In[87]:


from IPython.display import Image
Image(filename=r"Oblivious datastructure.PNG")


# ### #ComputationalSolutions
# 
# The thorough decomposition of the effective RSA algorithms and its shortcomings allowed me to construct an algorithm out of methods and processes that are well developed in the RSA and AES algorithmic implementations. My algorithm details the workings of the asymmetrical key system, the randomization technique and its efficacy as well as the rationale behind having an oblivious datastructure for the simple algorithmic implementation. I go forward to combine my implementation with the modular hashing function hat makes RSA so powerful, as well as the matrix sramble from AES. This further enhances the solution that my algorithm provides for the encryption and decryption of texts.

# In[107]:


from operator import ixor
import functools
xor_4 = [[10110111, 0b01101001],
         [0b00011011, 10101000]]

xor_9 = [[0b01101100, 0b01110101, 0b01100111],
        [0b01101011, 0b01101100, 0b01110101],
        [0b01100101, 0b01101011, 0b00100000],
        [0b01101100, 0b01100101, 0b01110101]]

xor_16 = [[0b01101100, 0b01110101, 0b01100111, 0b01100111],
        [0b01101100, 0b01101011, 0b01101100, 0b01110101],
        [0b01100101, 0b01100111, 0b01101011, 0b00100000],
        [0b01101100, 0b01100101, 0b01110101, 0b00100000]]

xor_25 = [[0b01101100, 0b01010101, 0b01101100, 0b01101011, 0b01100111],
        [0b01101011, 0b01101100, 0b00011011, 10101000, 0b01110101],
        [0b01100101, 0b01101011, 0b00100100, 0b01101011, 0b00100000],
        [0b01101100, 0b01100101, 0b01110101, 0b00011011, 1010100],
        [0b01100101, 0b01101011, 0b01101011, 0b01101011, 0b00111000]]

xor_36 = [[0b01101100, 0b01110101, 0b01100111, 0b01100111, 0b01101011, 0b01111011],
        [0b01101100, 0b00100011, 0b01001011, 0b01101011, 0b01101100, 0b01110101],
        [0b00100011, 0b01001011, 0b01100101, 0b01100011, 0b01101011, 0b00100000],
        [0b01101011, 0b01101100, 0b01100101, 0b01110101, 0b00100011, 0b01001011],
        [0b01101011, 0b01011011, 0b01110101, 0b01101011, 0b01111011, 0b00100110],
        [0b00100011, 0b01001001, 0b00100101, 0b01000011, 0b01100011, 0b00100000]]

#res = functools.reduce(lambda x, y: x ^ y, xor_4)
res = functools.reduce(ixor, xor_4) 
print(res)


# In[113]:


random.seed(3)

class Node:
    def __init__(self, key, block):
        self.key = key  #The order that the block was inserted in
        self.block = block   #This is a grid of random size (128, 192, 256) 
                             #which contains bits for the stored elements

class ObliviousTree:
    def __init__(self, password, plain_text):
        self.password = password   #setting the private key as a password
        self.preparation(plain_text)
        self.nodes = []
    
    def preparation(self, text):
        '''This method converts the text into bits, finds how many blocks the text fits and
        passes them as input for each node.
        
        Inputs
        _____
        text: Characters to be converted into bits
        
        Output
        _____
        text - text as bits
        no_of_blocks - number of blocks
        size - the number of characters in the whole text in bits
        '''
        #Converts words into bits
        text_list = []
        for i in text:
            word = f"{ord(i):08b}"
            text_list.append(word)
        #print(text_list)
        
        
        block_size = int(random.choice([4, 9, 16, 25, 36]))   #Randomly selects the number of letters for each block
        
        
        size = len(text_list)   #Number of characters in the text 
        print('size',size)
        padding = size%block_size  #Calculates the amount of space left to fill a grid/block/matrix
        print('padding', padding)
        no_of_blocks = math.ceil(size/block_size)   #Calculates how many nodes we will create
        print('no_of_blocks',no_of_blocks)
        
        prime_keys = [1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069]
        
        #for i in range(no_of_blocks + 1):
            #self.insert(prime_keys[i],     #text_list from the beginning to end in chunks of 
                                           #block_size**0.5 and that no of times)
        

        mat_of_mats = []  #meta structure of all matrices
        count = len(text_list)-1


        for i in range(no_of_blocks+1): #Creates n matrices and populates the matrices with bit characters
            matrix = []   #One matrix
            
            #Generates the empty matrices
            for x in range(0, int(block_size**0.5)):
                matrix.append([])
                for y in range(0,int(block_size**0.5)):
                    matrix[x].append(None)
            
            #popultaes the matrix with bit strings
            for b in range(0,int(block_size**0.5)):

                for j in range(0,int(block_size**0.5)):
                    index = (b*int(block_size**0.5))+j
                    if index <= len(text_list):
                        matrix[b][j] = text_list[index]

            mat_of_mats.append(matrix)
        pprint(mat_of_mats)
        
    def insert(self, key, value):
     
        '''
        Takes the text_list elements and inserts them into the blocks/matrices
        
        Inputs
        ____
        key - prime number from prime keys. This will construct the overarching key
        
        Value - the matrix corresponding to the first nth characters in the input
        '''
        for k in range(len(prime_keys)+1):
            self.nodes.append(Node(key = prime_keys[k], value = mat_of_mats[k])) 
                   
        
    def encrypt(self, block):
        '''Takes each block and iteratively scrambles the contents of the block using xor operator. 
        The method hashes the internal key, adds it to the last block and then hashes 
        all the blocks withthe private key provided.
        
        input
        _____
        block - the meta array which contains the nodes
        
        output
        _____
        cipher - encrypted text
        
        '''
        for mat in mat_of_mats:
            cipher += str(pow(mat, e=11, N=143)) + " "
        return cipher
    
    
    
    def decrypt(self, cipher):
        '''
        Takes the ciphered text and transforms it into a readable string
        
        inputs
        ____
        cipher - Encypted text
        
        output
        _____
        message - Decrypted string
        
        '''
        message = ""   #Initiating the plain text string to be returned

        #Accessing each character in the cipher text
        parts = cipher.split()
        for i in parts:
            if i:
                current_char = int(i)    #Converting each byte into an int to comouet the reverse operation
                message += chr(pow(current_char, d=15, N=143))    #Constructing the plain text using characters

        return message
    


# In[114]:


text = 'I am a bag. You are a purse'
crypt = ObliviousTree(password = "password", plain_text = text)


# ### *
# 
# 
# This algorithm does not work as desired, and I do not have enough time to deconstruct the problem and implement a solution.
# 
# The xor operation is limited by python's inability to perform the bitise operation on a list. The solution to this would be to simply write the elements in string form, however, this would warrant the recreation of the debugging algorithm to split strings and operate on the bits as strings in the input. For this reason, there is a missing xor step in the encrypt and decrypt algorithms. 
# 
# The padding computation needs to be updated to not include the length of the key stored in the last matrix element. This is an iterative meta calculation that continuously changes as the insert function works on the input. 

# # #computationalcritique
# 
# I will be comparing the algorithms based on the pillars of cryptography:
# 
# a)Confidentiality - ensuring that information is kept private.
# 
# b)Integrity - detecting unauthorized interception and alteration of the information.
# 
# c)Authentication - verifying the identity of the receiver.
# 
# d)Authorization - determining the user's privilege to access the information.
# 
# e)Non-repudiation - verifying receipt of information.
# 
# Even though I could not implement the AES algorithm without libraries, since my own implementation borrows heavily from it, I will include it in my analysis. 
# 
# The AES algorithm, though intensive, offers only three levels of security where in the event of a generation of a related key, the security of the system could be jeopardised. Related keys allow the attacker to use a lot of data to develop the keys using mathematical relationships that are unknown to them but can be derived. Therefore, my algorithm solves this by generating an internal key that only stores information about the order of operations. Therefore, in the very unlikely event that someone knows how large the key is, and what its values are, they would only be able to find out the order of matrices whose size they do not know, and whose information they cannot decipher without the internal scrambling matrix. The RSA implementation applies the product of two large prime numbers to create the modular keys. The size of the key will make it computationally impossible to compute the permutation of the key eg 2^128, hereby implementing the gold standard of confidentiality.
# 
# All of the algorithms maintain integrity of the encrypted data where the transmitted data and the encrypted data can be compared for discrepancies. Furthermore, inaccurate keys will not be able to pass the conditionals to decrypt the data.
# 
# RSA, implements a shared key which should be kept private by the user. Even though it can be intercepted, the internal variables that make up the modular inverse provide sufficient internal security if the attacker does not know them. AES implements an asymmetric key system where the the shared key also operates like the RSA key to ensure that only the desired user can access the information. Lastly, my algorithm uses teh heuristic of a passowrd as the shared key instead of generating one, which makes it less secure when authenticating the user, however, without that, one cannot feasibly crack the code with mathematical computations. 
# 
# 
# Besides the above pillars, the RSA algorithm is limited by its computational time complexity to mosty encrypting small data such as passwords very securely. AES thrives on large data, files and general inputs. My agorithm implements the advantage of AES, however, the algorithm is quite taxing on space. Each data value is duplicated into the data structure and mathematically manipulated, which gives a space complexity of o(m*n). This worthwhile to consider since the users definitelly have limited RAM. 

# ## #randomizationtechniques
# 
# Throughout the paper, I discuss how the implementation of randomization in the selection of the prime numbers in RSA affords the user extra security due to la larger probability space which makes up the encryption keys. I go ahead and implement it in my own algorithm as a measure to 
# 
# 1. Select the grid sizes, and
# 2. Scramble the data
# 
# This prevents a brute force mathematical approach from cracking the code from multiple inputs within a feasible amount of time. With every extra size of grid to choose from, the probability space doubles eg from 2^127 to 2^128. Which is warrants the implementation. Also, the fact that my algorithm uses the inputs to determine the key orders and corresponding xor encrypted data, this acts in a non-deterministic way because the inputs will vary from execution to execution, which aso counts as a randomization technique. 

# # HCs
# ### #critique
# I used this HC to inform my approach for the construction of my algorithm and the implementation of RSA that suited this environment, critically engaging with and assessing methods that would present different strengths and limitations under varying conditions.
# As I was constructing my own cryptographic algorithm, I considered the limitation of the Advanced Encryption Standard and the RSA algorithm as theoretically depicted. I then consolidated the solutions to each of the identified problems and critically evaluated the extent to which their implementations meshed together to give the desired result.
# This critical work led to the elimination of a randomly generated key, the row and column swapping methods and a key generation function as observed in the RSA algorithm. This is because we are trying to maximize objectivity and same on run-time. Therefore, the extra non-deterministic implementations were not necessarily adding greatly to the security, the swapping was not solving the problem of ordered text and the key generation would jeopardize the run-time speeds if the key was too large, all of which fo marginal security improvements which draws on the use of #estimation.
# 
# ### #analogies
# I draw on the context in which the AES and RSA algorithms work best, as well as noting their weaknesses to construct my own algorithm which draws on each strength to reverse engineer an algorithm that works well for its environment. I dwell on the algorithmic similarities of RSA, AES, and my algorithm in my critical analysis to exploit the justification of applying either of these algorithms as strong security standards.
# I explore their differences in order to highlight areas where some applications are better than others and how my algorithm seeks to address each of their contextual weaknesses. 
# I also discuss the drawbacks of my algorithm that step outside the realm that the RSA algorithm covers, allowing any user to conduct a well informed cost-benefit analysis if they were to use these implementations.
# 
# ### #designthinking
# By informing the solution based on the typical user who would like to send an encrypted text message to someone, I was able to iteratively come up with an algorithm that met their needs while also approximating the pillars of cryptography as closely as I could. I iteratively designed the algorithm, updating features based on how feasibly their implementation would contribute to a thorough outcome. Furthermore, I expanded upon the algorithm by including controls that catered for specific situations that we would commonly encounter. I also divided the algorithmic methods into specific methods that performed one task only to improve the readability and debugging process. 

# In[ ]:




