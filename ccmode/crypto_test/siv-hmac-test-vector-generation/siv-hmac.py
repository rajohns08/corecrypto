# Copyright (c) (2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii


#There is a lot of debugging print lines that are included below that are commented out. They can be commented back in for future debugging purposes.

def h2s(hs):
    return binascii.hexlify(hs)

def encode_length_be(val):
    buf=bytearray (b'\x00\x00\x00\x00\x00\x00\x00\x00')
    for i in range(0,8):
         x = (val >> ((7-i)*8)) & 0xFF
         #print "i=="+str(i)
         #print str(x)
         buf[i]=x
    return buf

def hash_update(hmac, data, type):
#def hash_update(hmac, data):
    #print "ad:" + h2s(ad)
    hmac.update(bytes(data))
    el = encode_length_be(len(data))
    #print "ad LENGTH ENCODING:" + h2s(el)
    hmac.update(bytes(el))
    hmac.update(bytes(type))

def create_tag(hm, authenticated_data, nonce, plaintext):
    for ad in authenticated_data:
        hash_update(hm, ad,'A')
    if len(nonce)!=0:
            hash_update(hm, bytes(nonce),'N')
    if len(plaintext)!=0:
        hash_update(hm, bytes(plaintext),'P')
    return hm.finalize()

def siv_hmac_enc(key, authenticated_data_prime, nonce, plaintext, tag_length): 
        #make sure key length is 32 (We support only same size AES and HMAC Keys current code only 128 bit keys)
        nonce=bytearray.fromhex(nonce)
        key=bytearray.fromhex(key)
        
        #authenticated_data=authenticated_data_prime[:]
        authenticated_data=map(bytearray.fromhex, authenticated_data_prime[:])
        authenticated_data=map(bytes,authenticated_data)
        if (len(key)!=32):
            print "Error in key length"
            return -1;
            
        #split key: AES First, then HMAC.     
        aes_key=key[0:16]
        hmac_key=key[16:32]
        #print "HMAC KEY = " + h2s(bytes(hmac_key))
        #print "AES KEY = " + h2s(bytes(aes_key))
        
        #setup HMAC
        hm = hmac.HMAC(bytes(hmac_key), hashes.SHA256(), backend=default_backend())
        #digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        
        if (len(authenticated_data)==0 and len (nonce)==0 and len(plaintext)==0):
            hm.update(bytes(b'\x01\x02\x03\x04'))
            tag=hm.finalize()
            return (tag[0:tag_length],'')
        
        #add nonce to the end of authenticated data list

        #Generate Tag
        #print "Encryption Authenticated Data String"
        """for ad in authenticated_data:
            hash_update(hm, ad)
        if len(nonce)!=0:
            hash_update(hm, bytes(nonce))
        if len(plaintext)!=0:
            hash_update(hm, bytes(plaintext))
        tag=hm.finalize()"""
        tag = create_tag(hm, authenticated_data, nonce, plaintext)
        #print "tag:" + h2s(tag  )
        #print "Computed Tag is:" + binascii.hexlify(tag)
        iv=bytearray(tag[0:16])
        gen_key = rekey(aes_key, iv)
        
        iv[8]&=0x7F
        iv[12]&=0x7F
        
        
        #print "Tag = " + h2s(tag[0:16])
        cipher = Cipher(algorithms.AES(bytes(gen_key)), modes.CTR(bytes(iv)), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) 
        #print "Encrypted Plaintext ="+plaintext 
        encryptor.finalize()
        #print "Returned Ciphertext is:" + binascii.hexlify(ciphertext)
        return (tag[0:tag_length], ciphertext)

def siv_hmac_dec(key, authenticated_data_prime, nonce, ciphertext, tag, tag_length): 
        #make sure key length is 32 (We support only same size AES and HMAC Keys current code only 128 bit keys)
        nonce=bytearray.fromhex(nonce)
        key=bytearray.fromhex(key)
        authenticated_data=map(bytearray.fromhex, authenticated_data_prime[:])
        authenticated_data=map(bytes,authenticated_data)
        if (len(key)!=32):
            print "Error in key length"
            return -1;
        if (len(tag)<16 or len(tag)<tag_length):
            print  "Tag too small"
            return -1;
            
        #split key: AES First, then HMAC.     
        aes_key=key[0:16]
        hmac_key=key[16:32]
        iv=bytearray(tag[0:16])
        gen_key = rekey(aes_key, iv)
        #print "genKey:" + h2s(bytes(gen_key))
        iv[8]&=0x7F
        iv[12]&=0x7F

        #print "Tag = " + h2s(tag[0:16])
        cipher = Cipher(algorithms.AES(bytes(gen_key)), modes.CTR(bytes(iv)), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) 
        #print "Decrypted Plaintext = " + plaintext
        decryptor.finalize()
        #print "Decrypted Text is" + plaintext
        #setup HMAC
        hm = hmac.HMAC(bytes(hmac_key), hashes.SHA256(), backend=default_backend())
        #digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        
        if (len(authenticated_data)==0 and len(nonce)==0 and len(plaintext)==0):
            hm.update(bytes(b'\x01\x02\x03\x04'))
            ver_tag=hm.finalize()
            #print "NULL SPECIAL TAG Computed Tag:" + binascii.hexlify(ver_tag)
            if ver_tag[0:tag_length]==tag:
                return ('')
            else:
                print "------------------Tags do not verify-------------------------"
                print "Given Tag:" + binascii.hexlify(tag)
                print "Computed Tag:" + binascii.hexlify(ver_tag[0:tag_length])
                return "Tags do not verify"

        #Generate Tag
        ver_tag = create_tag(hm, authenticated_data, nonce, plaintext)

        #print "Computed Tag is:" + binascii.hexlify(ver_tag)
        if ver_tag[0:tag_length]==tag:
            return (plaintext)
        else:
            print "------------------Tags do not verify-------------------------"
            print "Given Tag:" + binascii.hexlify(tag)
            print "Computed Tag:" + binascii.hexlify(ver_tag[0:tag_length])
            return "Tags do not verify"   
            

def rekey (master_key, iv):
      zIV = iv[:]
      zIV[15] &= 0x7F
      keyGenCipher = Cipher(algorithms.AES(bytes(master_key)), modes.ECB(), backend=default_backend())
      keyGenEncryptor = keyGenCipher.encryptor()
      ciphertext = keyGenEncryptor.update(bytes(zIV))
      ciphertext0 = ciphertext[0:8]
      #print "zIV0:" + h2s(bytes(zIV))
      #print "ciphertext0:" + h2s(bytes(ciphertext0))
      zIV[15] += 1
      ciphertext = keyGenEncryptor.update(bytes(zIV))
      ciphertext1 = ciphertext[0:8]
      #print "zIV1:" + h2s(bytes(zIV))
      #print "ciphertext1:" + h2s(bytes(ciphertext1))
      finalKey = ciphertext0 + ciphertext1
      #print "finalkey:" + h2s(bytes(finalKey))
      return finalKey
    
    
"""    Q[block_size-1] &= 0x00;
    uint8_t zero_pad[_CCMODE_SIV_HMAC_KEYSIZE(ctx)], temp_key[_CCMODE_SIV_HMAC_KEYSIZE(ctx)];
    memset(zero_pad, 0, _CCMODE_SIV_HMAC_KEYSIZE(ctx));
    rc = ccctr_one_shot(ctr, _CCMODE_SIV_HMAC_KEYSIZE(ctx) / 2, _CCMODE_SIV_HMAC_CTR_KEY(ctx), Q, _CCMODE_SIV_HMAC_KEYSIZE(ctx), zero_pad, temp_key);
   
    size_t base = block_size/2;
    for (size_t i = 0; i < (_CCMODE_SIV_HMAC_KEYSIZE(ctx)/block_size)/2; i++ ){
        for (size_t j=0; j<block_size/2; j++){
            temp_key[base+j]=temp_key[base+block_size+j];
        }
        base+=block_size;
    }
"""



def ha2s(ad):
    weird_index_Names=["","2"]
    i=1
    for s in ad:
        if i<=2:
            middle=weird_index_Names[i-1]
        else:
            middle=str(i)
            
        print "\t.aData"+middle+"Str=\""+s+"\","
        i=i+1
    return
        
"""
        .keyStr="7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
                .aDataStr="00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
                .aData2Str="102030405060708090a0",
                .init_ivStr="09f911029d74e35bd84156c5635688c0",
                .ptStr="7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
                .ctStr="7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"},
"""
         
def one_go_test(master_key, ad, iv, plaintext, tag_length):
    (t,c) = siv_hmac_enc(master_key, ad, iv, plaintext, tag_length) 
    result = siv_hmac_dec(master_key, ad, iv, c, t, tag_length)
    if (result==plaintext):
        print "{"
        print "\t.keyStr = \"" + master_key + "\","
        ha2s(ad)
        print "\t.init_ivStr = \"" + iv + "\","
        print "\t.ptStr = \""+ h2s(plaintext) +"\","
        print "\t.ctStr = \""+ h2s(t)+h2s(c)+"\","
        print "\t.tagStr = \""+ h2s(t) +"\","
        print "},"
    else:
        print "Decryption Error!!!!"+plaintext+result
    return


master_key = b'01020304050607080102030405060708f1f2f3f4f5f6f7f8f1f2f3f4f5f6f7f8'

def perform_testsdef():
    one_go_test(master_key, [],'','plaintext only test', 20)
    one_go_test(master_key, [], b'a1a2a3a4', 'plaintext only test', 20)
    one_go_test(master_key, [b'b1b2b3b4'], b'a1a2a3a4', 'plaintext only test', 20)
    one_go_test(master_key, [b'1234',b'ff00ff00'],b'a1a2a3a4a5a6a7a8a9','text to encrypt', 20)
    one_go_test(b'7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f', [b'00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100',b'102030405060708090a0'],b'09f911029d74e35bd84156c5635688c0',"7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",30)
    one_go_test(b'7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f', [b'abcdef'], b'',"This  is a plaintext test", 32)
    one_go_test(b'7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f', [], '', "Thus is a plaintext test", 32)    
    one_go_test(master_key,[],b'',b'',20)
    
    return
    
    
perform_testsdef()
