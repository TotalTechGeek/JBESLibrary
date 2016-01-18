# Basyl Encryption Standard
Ever need to protect your data? Encryption is the answer. The problem is, as computers get more powerful, encryption algorithms need to become stronger as well. Many other algorithms ([AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) or [Triple DES](https://en.wikipedia.org/wiki/Triple_DES)) that encrypt your data are based on [Feistel Networks](https://en.wikipedia.org/wiki/Feistel_cipher). Feistel networks require design for each possible key size, which makes it  impossible for them to adapt dynamically. The Basyl Encryption Standard is different. Designed to model the [Vernam Cipher](https://en.wikipedia.org/wiki/One-time_pad), also known as a [One-Time Pad](https://en.wikipedia.org/wiki/One-time_pad), the Basyl Encryption Standard absorbs as much information as you pass into it, and each encryption scheme is unique. There is no restricted key size at all!

You might want to compare this project against the [C# version](https://github.com/TheCreatorJames/BESLibrary) or [C++ version](https://github.com/TheCreatorJames/BESLibraryCPP) of the library.

Also, unlike other encryption schemes, BES is easy to modify and adapt for your purposes.

The Basyl Encryption Standard uses a [carefully designed PRNG](https://github.com/TheCreatorJames/BESLibrary/blob/master/PRNG.md) resistant to cryptanalysis to encrypt your data with. This implementation allows you to use BES in the Java Programming Language.


### Standard BES

The original Basyl Encryption standard uses a key generator to [XOR](https://en.wikipedia.org/wiki/Exclusive_or) against your file. The advantage of this version of the encryption scheme is that it allows random access to your files. Bruteforcing files using this encryption scheme requires petabytes (or zettabytes and beyond depending on the length of your password) of data to be computed each second to even crack it in a century. To ensure that two files are never encrypted the same way, a 32 byte hash of the file is used to seed the generator. An additional 8 bytes guarantee even the same hash is never encrypted twice.

This encryption scheme is slightly susceptible to a plaintext attack that allows them to replace some of the data in the file. However, because the hash of the original file is already included, this type of attack is easily prevented.



One way to encrypt is to use the BasylOutputStream, which can be constructed from a BasylKeyGenerator.
```Java
BasylKeyGenerator bob = new BasylKeyGenerator("Password");
BasylOutputStream bos = new BasylOutputStream(fileStream, bob, true);
byte[] buf = new byte[1024];
//write code to add stuff to buf.
bos.write(buf);
```
And then you are able to use the BasylInputStream in a similar way, but you must reconstruct the original key generator. The BasylInputStream is able to read the key in from the stream on its own.

```Java
BasylKeyGenerator bkg = BasylInputStream.ReadFromStream(fileStream, pass, /* some generation size info  */, null /* You can pass in a BasylPseudoAdaptor */); 
```

You could also encrypt directly with the Basyl Key Generators. As it is XOR based, decrypting is the same as encrypting.

```Java
BasylKeyGenerator bob = new BasylKeyGenerator("Password");
byte x = 100;
x = bob.EncryptByte(x); //encrypts the byte.
```

To decrypt, using this key generator specifically, since it is XOR based, you could optionally call either EncryptByte (again) or DecryptByte, as they perform the same task. To decrypt, you must construct an exact copy of the initial key generator, which requires you to harvest the seed data (such as the hash, key1, and key2). You could read one in like seen with the BasylInputStream above. 

```Java
BasylKeyGenerator bob = new BasylKeyGenerator("Password", /* All the options factors */, hash, key1Random, key2Random, true);
bob.DecryptByte(ref inputByte); //decrypts the byte.
```


### Cipher BES
To prevent any sort of tampering and remove any sort of derivable (indirect) XOR key, Cipher BES was created. This has an internal shuffle cipher, similar in concept to the [enigma machine](https://en.wikipedia.org/wiki/Enigma_machine). This is "more secure" than standard BES in the sense that it prevents a plaintext modification attack, but it prevents random access to the file. The file must be decrypted up to the point you are trying to access.

You can encrypt in this mode using the BESCipher class.
```Java
BasylKeyGenerator bob = new BasylKeyGenerator("Password");
BESCipher cipher = new BESCipher(bob);
cipher.EncryptRight(bytes);
```

To decrypt, you must reconstruct the cipher with the same key generator, using methods stated in the previous section.
```Java
cipher.EncryptLeft(bytes);
```
