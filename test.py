
import hashlib

if __name__ == '__main__':
    '''This code is used to verify that test.c is calculating the correct hash for a given file or other input.'''
    f = open('testDataFile.csv','rb')
    msg = f.read()
    f.close()
    digest = hashlib.sha256(msg)
    print(digest.hexdigest())
