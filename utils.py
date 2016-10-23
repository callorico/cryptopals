import os

def abs_path(filename):
    return os.path.join(os.path.dirname(__file__), 'data', filename)

def readlines(filename):
    path = abs_path(filename)

    with open(path, 'r') as f:
        for line in f:
            yield line.strip()

def read(filename):
    return ''.join(line for line in readlines(filename))
