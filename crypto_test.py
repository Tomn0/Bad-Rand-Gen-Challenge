from subprocess import call

cmd = "openssl prime -generate -bits 2048 -hex 1>&2"
decrypted = call(cmd, shell=True)
print (decrypted)