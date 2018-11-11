# Basyl Encryption Standard
This is a simple stream cipher I designed in my senior year of High School (back in 2015). I would **highly discourage** someone from attempting the use it in production. 

It was designed to be memory intensive, making brute-force computation quite difficult to accomplish. 

You might want to compare this project against the [C# version](https://github.com/TotalTechGeek/BESLibrary) or [C++ version](https://github.com/TotalTechGeek/BESLibraryCPP) of the library.

The Basyl Encryption Standard uses a [custom PRNG](https://github.com/TotalTechGeek/BESLibrary/blob/master/PRNG.md) designed to be resistant to cryptanalysis. 

### Standard BES

The original Basyl Encryption standard performs an [XOR operation](https://en.wikipedia.org/wiki/Exclusive_or) against its input. The advantage of this version of the encryption scheme is that it could allows random access to your file data. 

The disadvantage of this scheme is that the encryption itself is malleable, but this is mitigated by the use of a hash as part of its  initialization vector. 

One method to encrypt is to use the BasylOutputStream, which can be constructed from a BasylKeyGenerator.
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
outputByte = bob.DecryptByte(inputByte); //decrypts the byte.
```


### Cipher BES
To prevent any sort of tampering (and intentionally increase error propagation), Cipher BES was created. This has an internal shuffle cipher, slightly similar in concept to the [enigma machine](https://en.wikipedia.org/wiki/Enigma_machine). This is "more secure" than standard BES in the sense that it prevents a plaintext modification attack, but it prevents random access to the file. The file must be decrypted up to the point you are trying to access.

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
