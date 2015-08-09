package beslibrary.encryption;

public class BESCipher 
{
	 private byte[] cipher;
     private byte[] cipherB;
     private IBasylKeyGenerator generator;

     private static int Unsigned(byte x)
     {
     	return x & 0xFF;
     }
     
     public BESCipher(IBasylKeyGenerator generator)
     {
         cipher = new byte[256];
         cipherB = new byte[256];
         
         for (int i = 0; i <= 255; i++)
         {
             cipherB[i] = cipher[i] = (byte)i;
         }


         this.generator = generator;
         Shuffle(10);
     }

     public IBasylKeyGenerator GetKeyGenerator()
     {
         return generator;
     }

     /// <summary>
     /// Shuffles the arrays. This is mainly used to randomize the starting positions of the cipher.
     /// </summary>
     /// <param name="times"></param>
     public void Shuffle(int times)
     {
         byte b;
         byte pos;
         for (int j = 0; j < times; j++)
         {
             for (int i = 0; i <= 255; i++)
             {
                 pos = generator.GetRandomByte();
                 b = cipher[Unsigned(pos)];
                 cipher[Unsigned(pos)] = cipher[i];
                 cipher[i] = b;
             }
         }

         RefreshOther();
         
     }


     /// <summary>
     /// Refreshes the secondary array.
     /// </summary>
     private void RefreshOther()
     {
         for (int i = 0; i <= 255; i++)
         {
             cipherB[Unsigned(cipher[i])] = (byte)i;
         }
     }



     /// <summary>
     /// Shuffles the position of bytes in the array.
     /// This shuffles what is output-ed when you pass in a byte at that position.
     /// </summary>
     /// <param name="pos"></param>
     public void ShufflePosition(byte pos)
     {
    	 
         byte pos2 = generator.GetRandomByte();
         if(pos == pos2)
         {
             RefreshOther();
             return;
         }

         cipherB[Unsigned(cipher[Unsigned(pos2)])] = pos;
         cipherB[Unsigned(cipher[Unsigned(pos)])] = pos2;

         byte b = cipher[Unsigned(pos2)]; 
         cipher[Unsigned(pos2)] = cipher[Unsigned(pos)];
         cipher[Unsigned(pos)] = b;
     }

   
     /// <summary>
     /// Encrypts "to the right", to reverse this, "encrypt" to the left.
     /// </summary>
     /// <param name="byt"></param>
     public byte EncryptRight(byte byt)
     {
         byte pos = byt;
         byt = cipher[byt];
         ShufflePosition(pos);
         return byt;
     }

     /// <summary>
     /// Encrypts "to the left", to reverse this, "encrypt" to the right.
     /// </summary>
     /// <param name="byt"></param>
     public byte EncryptLeft(byte byt)
     {
        
         byt = cipherB[byt];

         ShufflePosition(byt);
         return byt;
     }


     /// <summary>
     /// Encrypts "to the right", to reverse this, "encrypt" to the left.
     /// </summary>
     /// <param name="byt"></param>
     public void EncryptRight(byte[] byt)
     {
         for (int i = 0; i < byt.length; i++)
         {
             byt[i] = EncryptRight(byt[i]);
         }
     }


     /// <summary>
     /// Encrypts "to the left", to reverse this, "encrypt" to the right.
     /// </summary>
     /// <param name="byt"></param>
     public void EncryptLeft(byte[] byt)
     {
         for(int i = 0; i < byt.length; i++)
         {
             byt[i] = EncryptLeft(byt[i]);
         }
     }
	
	
}
