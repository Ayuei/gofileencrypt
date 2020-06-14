## Encrypt a file or decrypt a file.

**Key generation**
```
./gofileencrypt.exe -generate-key -fp test.key
```

**Encryption**
```
./gofileencrypt.exe -encrypt -fp test -kp test.key
```

**Decryption**
```
./gofileencrypt.exe -decrypt -fp test.encrypt -kp test.key
```
