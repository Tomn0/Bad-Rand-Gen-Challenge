from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class KeyPair():
    
    def __init__(self, key_size=1024, public_exponent=65537, p=None, q =None) -> None:
        self.p = p
        self.q = q
        self.public_exponent=public_exponent
        self.key_size=key_size
        
        publ, priv = self.create_keypair()
        self.save_pem(publ, priv)       
    
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
            
            return private_key, p, q
        
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
        private_key, p, q = self.__create_private()
        public_key = private_key.public_key()
               
        return public_key, private_key
    
    def save_pem(self, public_key, private_key):
        # Serialize the private key to PEM format
        # Serialize the public key to PEM format
        
        # Save private key to file
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

        # Save public key to file
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

keypair = KeyPair()

# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )
# public_key = private_key.public_key()

# # Serialize the private key to PEM format
# private_key_pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption(),
# )

# # Serialize the public key to PEM format
# public_key_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo,
# )

# print("Decode")
# print(private_key_pem.decode())
# print("No decode")
# print(private_key_pem)
# print(public_key_pem)

# p = private_key.private_numbers().p
# q = private_key.private_numbers().q
# print()
# print(p)
# print(q)

