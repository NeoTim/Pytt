#!/usr/bin/env python

import bencode
import sys


def do_edit(tracker_list, torrent_file):

    with open(torrent_file, "rb") as f:
        data = bencode.bdecode(f.read())

    existing_trackers = data['announce-list']

    with open(tracker_list, "rb") as f:
        for tracker in f:
            tracker = tracker.strip()
            if tracker.startswith("#"):
                continue
            if tracker not in existing_trackers:
                sys.stdout.write("[^] adding %s\n" % tracker)
                data['announce-list'].append([tracker])

    new_torrent_file = "updated_" + torrent_file
    with open(new_torrent_file, "wb") as f:
        f.write(bencode.bencode(data))

    sys.stdout.write("[+] new torrent file is %s\n" % new_torrent_file)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        msg = "Usage: %s <tracker list file> <.torrent file>\n"
        sys.stderr.write(msg % sys.argv[0])
        sys.exit(-1)

    do_edit(*sys.argv[1:3])
