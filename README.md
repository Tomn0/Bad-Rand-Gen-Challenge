# Bad-Rand-Gen-Challenge  
Bad Random Generator Challenge for SFI 18 CTF competition  
SFI is a Computer Science festival organized by students and for students: https://sfi.pl/en/

## To generate challenge files
Create a secret flag in the project directory  
```echo sfi18_ctf{BadRandGenerat0r} > flag.txt```  

Generate keys - this will create 5 keypairs and 2 of them will share a common prime (by default second and last)  
```python bad_random_generator.py ```  

Generate self-signed certificates  
```python cert_sign.py```  

Encrypt the flag with the each key  
```python encrypt.py```
