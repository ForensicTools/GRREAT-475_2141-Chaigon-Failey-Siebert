#!/usr/bin/env python
import ssdeep
import os
import sys
import math
import argparse

SPAMSUM_LENGTH = 64


"""Reads the blacklist file.

The blacklist file must follow NIST's NSLR format.

Args:
	blacklist_file: Location of the blacklist file on disk.

Returns:
	A Python array containing the hashes, the filenames and the blocksizes.
"""
def read_hashlist(blacklist_file):
	hashes = []
	fh = open(blacklist_file)
	for line in fh:
		infos = line.split(',')
		if len(infos) == 2:
			infos_hash = infos[0].split(':')
			if len(infos_hash) == 3:
				filename = infos[1][1:-1]
				blocksize = int(infos_hash[0])
				piecewise_hash = {'blocksize': blocksize, 'hash': infos[0], 'filename': filename}
				hashes.append(piecewise_hash)
	fh.close()
	return hashes


"""Computes the minimum and maximum filesize from the blocksize of a ssdeep hash.

From the implementation of ssdeep we know that:
blocksize = min_blocksize * 2 ^ bi.
bi is the smallest integer such that blocksize > filesize.
From this we can deduce that:
min_blocksize * 2 ^ (bi - 1) < filesize <= min_blocksize * 2 ^ bi.

Args:
	blocksize: The ssdeep blocksize.

Returns:
	The minimum and maximum filesize as a tuple.
"""
def compute_filesize_approximation(blocksize):
	max_filesize = SPAMSUM_LENGTH * blocksize
	min_filesize = math.ceil(max_filesize / 2)
	return (min_filesize, max_filesize)


"""Searches for a file by its ssdeep hash.

Doesn't search for partial matches.
Thanks to this limitation, we can use the filesize approximation.
See compute_filesize_approximation.

Args:
	directory: The directory where to search.
	ref_hash: The ssdeep hash to search for.

Returns:
	The matches as a Python array.
	The array contains the filepath and the ssdeep score.
"""
def search_by_hash(directory, ref_hash):
	matches = []

	blocksize = int(ref_hash.split(':')[0])
	(min_filesize, max_filesize) = compute_filesize_approximation(blocksize)
	
	for root, dirs, filenames in os.walk(directory):
		for filename in filenames:
			filepath = os.path.join(root, filename)
			if os.path.isfile(filepath):
				filesize = os.path.getsize(filepath)
				if filesize >= min_filesize and filesize < max_filesize:
					piecewise_hash = ssdeep.hash_from_file(filepath.decode('utf-8'))
					ssdeep_score = ssdeep.compare(ref_hash, piecewise_hash)
					if ssdeep_score > 0:
						matches.append((filepath, ssdeep_score))
	return matches


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Find files using ssdeep piecewise hashes.")
	parser.add_argument("directory", help="The directory to search in.", type=str)
	parser.add_argument("hash", help="Piecewise hash from ssdeep.", type=str)
	args = parser.parse_args()

	matches = search_by_hash(args.directory, args.hash)
	for match in matches:
		print("%d - %s" % (match[1], match[0]))
