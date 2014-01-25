import sys
import bencode

filename = sys.argv[1]

fd = open(filename, "rb")

data = bencode.bdecode(fd.read())
data["announce-list"] = []
data["announce-list"].append(["udp://tracker.publicbt.com:80/announce"])

nfd = open("stage1-" + filename, "wb")
nfd.write(bencode.bencode(data))
nfd.close()

data["announce-list"] = []
data["announce-list"].append(["http://localhost:8080/announce"])

nfd = open("stage2-" + filename, "wb")
nfd.write(bencode.bencode(data))
nfd.close()
