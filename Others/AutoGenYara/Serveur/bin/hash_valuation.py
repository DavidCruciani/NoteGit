import glob, os, hashlib, ssdeep, tlsh, json

data = []

for filename in glob.iglob('/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/AutoGene/bin' + '**/**', recursive=True):
    #print(filename)
    if not os.path.isdir(filename):
        md5Glob = hashlib.md5(open(filename, 'rb').read()).hexdigest()
        sha1Glob = hashlib.sha1(open(filename, 'rb').read()).hexdigest()
        sha256Glob = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
        sha512Glob = hashlib.sha512(open(filename, 'rb').read()).hexdigest()
        tlshGlob = tlsh.hash(open(filename, 'rb').read())
        ssdeepGlob = ssdeep.hash(open(filename, 'rb').read())

        with open('/home/dacru/Desktop/WorkSpace/Rule_Generator_WorkSpace/AutoGene/bin/Hash_result.txt', 'a') as hashWrite:
            hashWrite.write('%s: \n' % (filename))

            hashWrite.write('\t md5: %s\n' % (md5Glob))
            hashWrite.write('\t sha1: %s\n' % (sha1Glob))
            hashWrite.write('\t sha256: %s\n' % (sha256Glob))
            hashWrite.write('\t sha512: %s\n' % (sha512Glob))
            hashWrite.write('\t tlsh: %s\n' % (tlshGlob))
            hashWrite.write('\t ssdeep: %s\n' % (ssdeepGlob))

            hashWrite.write('FileSize: %s\n' % (os.path.getsize(filename)))

        data.append(
            {
                'FileName': filename,
                'FileSize': os.path.getsize(filename),
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
