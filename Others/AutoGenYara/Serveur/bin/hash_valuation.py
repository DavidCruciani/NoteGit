import glob, os, hashlib, ssdeep, tlsh, json

data = []

with open('/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/listingmachine.txt', 'r') as read_file:
    for line in read_file.readlines():
        filename = line[1:]
        filename = "./mnt" + filename 
        if not os.path.isdir(filename.rstrip('\n')):
            md5Glob = hashlib.md5(open(filename.rstrip('\n'), 'rb').read()).hexdigest()
            sha1Glob = hashlib.sha1(open(filename.rstrip('\n'), 'rb').read()).hexdigest()
            sha256Glob = hashlib.sha256(open(filename.rstrip('\n'), 'rb').read()).hexdigest()
            sha512Glob = hashlib.sha512(open(filename.rstrip('\n'), 'rb').read()).hexdigest()
            tlshGlob = tlsh.hash(open(filename.rstrip('\n'), 'rb').read())
            ssdeepGlob = ssdeep.hash(open(filename.rstrip('\n'), 'rb').read())

    data.append(
            {
                'FileName': filename.rstrip('\n'),
                'FileSize': os.path.getsize(filename.rstrip('\n')),
                'md5': md5Glob,
                'sha-1': sha1Glob,
                'sha-256': sha256Glob,
                'sha-512': sha512Glob,
                'tlsh': tlshGlob,
                'ssdeep': ssdeepGlob
            }
        )

with open('/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/AutoGene/bin/jsonHash.txt', 'w') as outfile:
    json.dump(data, outfile, indent=4)
