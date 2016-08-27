import os

def readlines(filename):
    path = os.path.join(os.path.dirname(__file__), 'data', filename)

    with open(path, 'r') as f:
        for line in f:
            yield line.strip()

def read(filename):
    return ''.join(line for line in readlines(filename))
