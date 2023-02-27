from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import math

class KeyPair():
    
    def __init__(self, key_size=1024, public_exponent=65537, p=None, q =None) -> None:
        self.p = p
        self.q = q
        self.public_exponent=public_exponent
        self.key_size=key_size
        
        # generate multiple keypairs
        # for i in range(5):
        #     publ, priv = self.create_keypair()
        #     self.save_pem(publ, priv, name=i)       

        # generate one key
        publ, priv = self.create_keypair()
        self.save_pem(publ, priv, name="weak")       


    
    def __create_private(self):
        if self.p == None or self.q == None:
            print("Creating new private key")
            private_key = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.key_size,
                backend=default_backend()
            )
            
            p = private_key.private_numbers().p
            q = private_key.private_numbers().q
            
            return private_key
        
        else:
            print("Warning: Using supplied values of p and q. \nYou should ONLY use it if you’re 100% absolutely sure that you know what you’re doing.")

            n = self.p * self.q # here calculate public modulus
            public_numbers = rsa.RSAPublicNumbers(self.public_exponent,n)
            phi = (self.p-1)*(self.q-1)
            d = pow(self.public_exponent,-1,phi)
            
            private_exponent = d
            iqmp = rsa.rsa_crt_iqmp(self.p,self.q)
            dmp1 = rsa.rsa_crt_dmp1(private_exponent, self.p)
            dmq1 = rsa.rsa_crt_dmq1(private_exponent, self.q)
            return rsa.RSAPrivateNumbers(self.p,self.q,d,dmp1=dmp1,dmq1=dmq1,iqmp=iqmp,public_numbers=public_numbers).private_key()
            
    def create_keypair(self):
        private_key = self.__create_private()
        public_key = private_key.public_key()
               
        return public_key, private_key
    
    def save_pem(self, public_key, private_key, name=None):
        # Serialize the private key to PEM format
        # Serialize the public key to PEM format
        
        # Save private key to file
        with open(f"private_key{name}.pem", "wb") as f:
            f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

        # Save public key to file
        with open(f"public_key{name}.pem", "wb") as f:
            f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

# keypair = KeyPair()

###########
# SOLVING #
###########

def load_publ_key(name=None):
    with open(f"public_key{name}.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    return public_key


def load_priv_key(name=None):
    with open(f"private_key{name}.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

        return private_key


# key1 = load_publ_key(1)
# key2 = load_publ_key(4)

# print(key1.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo,
# ).decode())

# print(key2.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo,
# ).decode())


# print(type(key1))
# print(key1.public_numbers().n)
# print(key2.public_numbers().e)
# # print(key1.private_numbers().p)

##########################
## Create two weak keys ##
##########################
def create_weak_key():
    first_key_publ = load_publ_key(1)
    first_key_priv = load_priv_key(1)
    print("Loaded first key..")
    print("n = ", first_key_publ.public_numbers().n)
    print("p = ", first_key_priv.private_numbers().p)
    print("q = ", first_key_priv.private_numbers().q)

    second_key_publ = load_publ_key(4)
    second_key_priv = load_priv_key(4)
    print("Loaded second key..")
    print("n = ", second_key_publ.public_numbers().n)
    print("p = ", second_key_priv.private_numbers().p)
    print("q = ", second_key_priv.private_numbers().q)

    new_keypair = KeyPair(key_size=1024, public_exponent=65537, p=first_key_priv.private_numbers().p, q =second_key_priv.private_numbers().q)

#####################
# Exploit weak keys #
#####################
first_key_publ = load_publ_key(1)
second_key_publ = load_publ_key("weak")

n1 = first_key_publ.public_numbers().n
n2 = second_key_publ.public_numbers().n

first_key_publ = load_publ_key(1)
first_key_priv = load_priv_key(1)
print("Loaded first key..")
print("n = ", first_key_publ.public_numbers().n)
print("p = ", first_key_priv.private_numbers().p)
print("q = ", first_key_priv.private_numbers().q)

second_key_publ = load_publ_key("weak")
second_key_priv = load_priv_key("weak")
print("Loaded second key..")
print("n = ", second_key_publ.public_numbers().n)
print("p = ", second_key_priv.private_numbers().p)
print("q = ", second_key_priv.private_numbers().q)

print("GCD = ", math.gcd(n1, n2))
