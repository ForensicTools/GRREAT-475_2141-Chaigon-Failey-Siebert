#!/usr/bin/env python
import ssdeep
import os
import sys
import math
import argparse
import sets

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


"""Computes approximations of the filesizes from the blocksize of the ssdeep hashes.

The approximation of the filesize for each file/hash is a minimum and a maximum value.
For each hash, the two values make an interval.
Then, the set of intervals is reduced by taking the union of the set.
The union is computed with a sweep line algorithm.

Args:
	hashes: A Python array containing the hashes, the filenames and the blocksizes.

Returns:
	The best set of approximations of the filesizes.
"""
def compute_filesize_approximations(hashes):
	# Compute the filesize approximation for each hash (based on the blocksize):
	all_approximations = []
	for piecewise_hash in hashes:
		filesize_approximation = compute_filesize_approximation(piecewise_hash['blocksize'])
		all_approximations.append(filesize_approximation)

	# Sorts the approximations based on the minimum filesize.
	all_approximations.sort(key=lambda tuple: tuple[0])

	# Remove the duplicates from the list of approximations:
	approximations = [all_approximations[0]]
	for approx in all_approximations:
		if approx != approximations[-1]:
			approximations.append(approx)

	# Performs the union of all approximations in a linear pass:
	merged_approximations = [approximations[0]]
	for i in range(1, len(approximations)):
		if approximations[i][0] <= merged_approximations[-1][1]:
			merged_approximations[-1] = (merged_approximations[-1][0], approximations[i][1])
		else:
			merged_approximations.append(approximations[i])

	return merged_approximations


"""Computes the minimum and maximum filesize from the blocksize of a ssdeep hash.

From the implementation of ssdeep we know that:
blocksize = min_blocksize * 2 ^ bi.
bi is the smallest integer such that SPAMSUM_LENGTH * blocksize > filesize.
From this we can deduce that:
SPAMSUM_LENGTH * blocksize/2 < filesize <= SPAMSUM_LENGTH * blocksize.

Args:
	blocksize: The ssdeep blocksize.

Returns:
	The minimum and maximum filesize as a tuple.
"""
def compute_filesize_approximation(blocksize):
	max_filesize = SPAMSUM_LENGTH * blocksize
	min_filesize = int(math.ceil(max_filesize / 2))
	return (min_filesize, max_filesize)


"""Checks if a filesize matches a set of approximation.

Each approximation is a tuple with a minimum and a maximum filesize.
The filesize matches the set of approximations if it's in one of the intervals.

Args:
	filesize: The filesize of the currently verified file.
	filesize_approximations: The list of filesize approximations.

Returns:
	True if the filesize matches one of the approximations.
"""
def matches_approximations(filesize, filesize_approximations):
	for (min_filesize, max_filesize) in filesize_approximations:
		if filesize >= min_filesize and filesize < max_filesize:
			return True
	return False


"""Matches all files in a directory against a set of ssdeep hashes.

Doesn't search for partial matches.
Thanks to this limitation, we can use the filesize approximation.
See compute_filesize_approximation and compute_filesize_approximations.

Args:
	directory: The directory where to search.
	hashes: A Python array containing the hashes, the filenames and the blocksizes.

Returns:
	The matches as a Python array.
	The array contains the filepath and the ssdeep score.
"""
def match_against_hashes(directory, hashes):
	matches = []

	filesize_approximations = compute_filesize_approximations(hashes)
	
	for root, dirs, filenames in os.walk(directory):
		for filename in filenames:
			filepath = os.path.join(root, filename)
			if os.path.isfile(filepath):
				filesize = os.path.getsize(filepath)
				if matches_approximations(filesize, filesize_approximations):
					piecewise_hash = ssdeep.hash_from_file(filepath.decode('utf-8'))
					for ref_hash in hashes:
						ssdeep_score = ssdeep.compare(ref_hash['hash'], piecewise_hash)
						if ssdeep_score > 0:
							matches.append((filepath, ssdeep_score))
	return matches


"""Matches all files in a directory against a set of ssdeep hashes.

Includes the partial matches (no optimization on the filesize).

Args:
	directory: The directory where to search.
	hashes: A Python array containing the hashes, the filenames and the blocksizes.

Returns:
	The matches as a Python array.
	The array contains the filepath and the ssdeep score.
"""
def match_against_hashes_partial_matches(directory, hashes):
	matches = []
	for root, dirs, filenames in os.walk(directory):
		for filename in filenames:
			filepath = os.path.join(root, filename)
			if os.path.isfile(filepath):
				piecewise_hash = ssdeep.hash_from_file(filepath.decode('utf-8'))
				for ref_hash in hashes:
					ssdeep_score = ssdeep.compare(ref_hash['hash'], piecewise_hash)
					if ssdeep_score > 0:
						matches.append((filepath, ssdeep_score))
	return matches


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


"""Searches for a file by its ssdeep hash.

Includes the partial matches (no optimization on the filesize).

Args:
	directory: The directory where to search.
	ref_hash: The ssdeep hash to search for.

Returns:
	The matches as a Python array.
	The array contains the filepath and the ssdeep score.
"""
def search_by_hash_partial_matches(directory, ref_hash):
	matches = []
	for root, dirs, filenames in os.walk(directory):
		for filename in filenames:
			filepath = os.path.join(root, filename)
			if os.path.isfile(filepath):
				piecewise_hash = ssdeep.hash_from_file(filepath.decode('utf-8'))
				ssdeep_score = ssdeep.compare(ref_hash, piecewise_hash)
				if ssdeep_score > 0:
					matches.append((filepath, ssdeep_score))
	return matches


"""Find files using ssdeep piecewise hashes.
usage: find_by_hash.py [-h] [--hash HASH] [--hashes_file HASHES_FILE] [-p] directory

positional arguments:
	directory					The directory to search in.

optional arguments:
	-h, --help					show this help message and exit
	--hash HASH					Piecewise hash from ssdeep.
	--hashes-file HASHES_FILE	File containing piecewise hashes from ssdeep.
	-p, --partial-matches		Include partial matches in the results.
"""
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Find files using ssdeep piecewise hashes.")
	parser.add_argument("directory", help="The directory to search in.", type=str)
	parser.add_argument("--hash", help="Piecewise hash from ssdeep.", type=str)
	parser.add_argument("-f", "--hashes-file", help="File containing piecewise hashes from ssdeep.", type=str)
	parser.add_argument("-p", "--partial-matches", dest="partial_matches", action="store_true",
						help="Include partial matches in the results.")
	args = parser.parse_args()

	if not (args.hash or args.hashes_file):
		parser.error('No source for hashes given, add hash or hashes_file.')
	if args.hash and args.hashes_file:
		parser.error("You can't have both hash and hashes_file as sources.")
	if args.hashes_file and not os.path.isfile(args.hashes_file):
		parser.error('File for hashes not found.')

	matches = []
	if args.hash:
		if args.partial_matches:
			matches = search_by_hash_partial_matches(args.directory, args.hash)
		else:
			matches = search_by_hash(args.directory, args.hash)
	else:
		hashes = read_hashlist(args.hashes_file)
		if args.partial_matches:
			matches = match_against_hashes_partial_matches(args.directory, hashes)
		else:
			matches = match_against_hashes(args.directory, hashes)

	for match in matches:
		print("%d - %s" % (match[1], match[0]))
