#!/usr/bin/env python
"""
Rewritten in Python from a C implementation in ssdeep.

Copyright (C) 2014 Jesse Kornblum <research@jessekornblum.com>
Copyright (C) 2014 Paul Chaignon <paul.chaignon@gmail.com>
"""
import copy
import subprocess
import re
import os
import sys
from edit_dist import edit_distn

SPAMSUM_LENGTH = 64
ROLLING_WINDOW = 7
MIN_BLOCKSIZE = 3

"""Hashes a file using ssdeep.

Calls ssdeep as a command line process.
This should only be used as a replacement if libfuzzy can't be used.
Using the libfuzzy is much faster.
An other solution for the future would be to rewrite the rest of ssdeep in Python.

Args:
	filepath: Path to the file to hash.

Returns:
	The piecewise hash of a file.
"""
def hash_from_file(filepath):
	FNULL = open(os.devnull, 'w')
	process = subprocess.Popen(('ssdeep', filepath), stderr=FNULL, stdout=subprocess.PIPE)
	output = process.stdout.read().decode('utf-8')
	piecewise_hash = output.split("\n")[1].split(',')[0]
	return piecewise_hash


"""Compares two ssdeep hashes.

This function is only an alias to fuzzy_compare.
Given two spamsum strings return a value indicating the degree to which they match.

Args:
	hash1: The first hash.
	hash2: The second hash.

Returns:
	A score from 0 to 100 indicating the degree to which the hashes match.
"""
def compare(hash1, hash2):
	return fuzzy_compare(hash1, hash2)


"""State for the rolling hash algorithm.

Python class in replacement of the C roll_state structure.
"""
class RollState:

	"""Constructor.
	"""
	def __init__(self):
		self.window = [0] * ROLLING_WINDOW
		self.h1 = 0
		self.h2 = 0
		self.h3 = 0
		self.n = 0


	"""Resets the state.

	All values are set to zero.
	"""
	def init(self):
		self.window = [0] * ROLLING_WINDOW
		self.h1 = 0
		self.h2 = 0
		self.h3 = 0
		self.n = 0


	"""Computes the rolling hash.

	A rolling hash, based on the Adler checksum. By using a rolling hash
	we can perform auto resynchronisation after inserts/deletes

	Internally, h1 is the sum of the bytes in the window and h2
	is the sum of the bytes times the index

	h3 is a shift/xor based rolling hash, and is mostly needed to ensure that
	we can cope with large blocksize values

	Args:
		c: The next character to hash.
	"""
	def hash(self, c):
		self.h2 -= self.h1
		self.h2 += ROLLING_WINDOW * ord(c)

		self.h1 += ord(c)
		self.h1 -= self.window[self.n % ROLLING_WINDOW]

		self.window[self.n % ROLLING_WINDOW] = ord(c)
		self.n += 1

		# The original spamsum AND'ed this value with 0xFFFFFFFF which
		# in theory should have no effect.
		# This AND has been removed for performance (jk)
		self.h3 <<= 5
		self.h3 ^= ord(c)


	"""Sums the three rolling hash values.

	Values are summed modulo UINT32_MAX + 1 to be identical to the C values.

	Returns:
		The current output of the rolling hash algorithm.
	"""
	def sum(self):
		# 4294967295 is UINT32_MAX.
		return (self.h1 + self.h2 + self.h3) % 4294967296


"""Checks if two strings have common values using the rolling hash algorithm.

We only accept a match if we have at least one common substring in
the signature of length ROLLING_WINDOW.
This dramatically drops the false positive rate for low score thresholds while having
negligable affect on the rate of spam detection.

There are many possible algorithms for common substring detection.
In this case we are re-using the rolling hash code to act
as a filter for possible substring matches

Args:
	s1: The first string.
	s2: The second string.

Returns:
	1 if the two strings do have a common substring, 0 otherwise
"""
def has_common_substring(s1, s2):

	hashes = [0] * SPAMSUM_LENGTH

	# First compute the windowed rolling hash at each offset in the first string:
	state = RollState()
	len1 = len(s1)
	for i in range(0, len1):
		state.hash(s1[i])
		hashes[i] = state.sum()
	num_hashes = i + 1

	state.init()

	# Now for each offset in the second string compute the rolling hash and
	# compare it to all of the rolling hashes for the first string.
	# If one matches then we have a candidate substring match.
	# We then confirm that match with a direct string comparison:
	len2 = len(s2)
	for i in range(0, len2):
		state.hash(s2[i])
		h = state.sum()
		if i < ROLLING_WINDOW - 1:
			continue
		for j in range(ROLLING_WINDOW - 1, num_hashes):
			if hashes[j] != 0 and hashes[j] == h:
				# We have a potential match - confirm it:
				if len(s2[i - (ROLLING_WINDOW - 1):]) >= ROLLING_WINDOW:
					# Strings to compare:
					string1 = s2[i - (ROLLING_WINDOW - 1):]
					string2 = s1[j - (ROLLING_WINDOW - 1):]
					if string1[0: ROLLING_WINDOW] == string2[0: ROLLING_WINDOW]:
						return 1

	return 0


"""Eliminate sequences of longer than 3 identical characters.

These sequences contain very little information so they tend to just bias the result unfairly.

Args:
	string: The string to process.

Returns:
	The same string with all sequence of more than 3 characters reduced to 3 characters.
"""
def eliminate_sequences(string):
	length = len(string)
	if length < 3:
		return copy.copy(string)

	j = 3
	ret = string[0:3]
	for i in range(3, length):
		if string[i] != string[i-1] or string[i] != string[i-2] or string[i] != string[i-3]:
			ret += string[i]
			j += 1

	return ret


"""Computes the score between two piecewise hashes.

This is the low level string scoring algorithm.
It takes two strings and scores them on a scale of 0-100
where 0 is a terrible match and 100 is a great match.
The block_size is used to cope with very small messages.

Args:
	s1: The first piecewise hash.
	s2: The second piecewise hash.
	block_size: The blocksize for the two hashes.

Returns:
	A score from 0 to 100 indicating the degree to which the hashes match.
"""
def score_strings(s1, s2, block_size):
	len1 = len(s1)
	len2 = len(s2)

	if len1 > SPAMSUM_LENGTH or len2 > SPAMSUM_LENGTH:
	# Not a real spamsum signature.
		return 0

	# The two strings must have a common substring of length ROLLING_WINDOW to be candidates.
	if has_common_substring(s1, s2) == 0:
		return 0

	# Computes the edit distance between the two strings.
	# The edit distance gives us a pretty good idea of how closely related the two strings are.
	score = edit_distn(s1, len1, s2, len2)

	# Scales the edit distance by the lengths of the two strings.
	# This changes the score to be a measure of the proportion of the message
	# that has changed rather than an absolute quantity..
	# It also copes with the variability of the string lengths.
	score = (score * SPAMSUM_LENGTH) / (len1 + len2)

	# At this stage the score occurs roughly on a 0-64 scale,
	# with 0 being a good match and 64 being a complete mismatch.

	# Rescales to a 0-100 scale (friendlier to humans).
	score = (100 * score) / 64

	# It is possible to get a score above 100 here, but it is a really terrible match.
	if score >= 100:
		return 0

	# Now re-scales on a 0-100 scale with 0 being a poor match and 100 being a excellent match.
	score = 100 - score

	# When the blocksize is small we don't want to exaggerate the match size:
	if score > block_size / MIN_BLOCKSIZE * min(len1, len2):
		score = block_size / MIN_BLOCKSIZE * min(len1, len2)
	return score


"""Compares two ssdeep hashes.

Given two spamsum strings return a value indicating the degree to which they match.

Args:
	hash1: The first hash.
	hash2: The second hash.

Returns:
	A score from 0 to 100 indicating the degree to which the hashes match.
"""
def fuzzy_compare(str1, str2):
	if None == str1 or None == str2:
		return -1

	# Each spamsum is prefixed by its block size:
	match1 = re.match(r'^(\d+):([^:]+):([^,]+)(,.+)?$', str1)
	if not match1:
		return -2
	block_size1 = int(match1.group(1))
	s1_1 = match1.group(2)
	s1_2 = match1.group(3)
	match2 = re.match(r'^(\d+):([^:]+):([^,]+)(,.+)?$', str2)
	if not match2:
		return -3
	block_size2 = int(match2.group(1))
	s2_1 = match2.group(2)
	s2_2 = match2.group(3)

	# If the blocksizes don't match then we are comparing apples to oranges.
	# This isn't an 'error' per se.
	# We could have two valid signatures, but they can't be compared.
	if block_size1 != block_size2 and block_size1 != block_size2 * 2 and block_size2 != block_size1 * 2:
		return 0

	# There is very little information content is sequences of the same character like 'LLLLL'.
	# Eliminates any sequences longer than 3.
	# This is especially important when combined with the has_common_substring() test below.
	# NOTE: This function duplciates str1 and str2.
	s1_1 = eliminate_sequences(s1_1)
	s2_1 = eliminate_sequences(s2_1)
	s1_2 = eliminate_sequences(s1_2)
	s2_2 = eliminate_sequences(s2_2)

	# Now that we know the strings are both well formed, are the identical?
	# We could save ourselves some work here.
	if block_size1 == block_size2 and s1_1 == s2_1 and s1_2 == s2_2:
		return 100

	# Each signature has a string for two block sizes.
	# We now choose how to combine the two block sizes.
	# We checked above that they have at least one block size in common.
	if block_size1 == block_size2:
		score1 = score_strings(s1_1, s2_1, block_size1)
		score2 = score_strings(s1_2, s2_2, block_size1 * 2)
		score = max(score1, score2)
	elif block_size1 == block_size2 * 2:
		score = score_strings(s1_1, s2_2, block_size1)
	else:
		score = score_strings(s1_2, s2_1, block_size2)

	return score


if __name__ == "__main__":
	"""
	string = "p2f3tmXCK0wAxQ/2222P2e+4OlOP1Q/UPiRgC9O+:p2f3tmyKDAxQ/21hw2w9cUPiRgC9H"
	result = eliminate_sequences(string)
	print(string)
	print(result)
	sys.exit()
	"""

	hash1 = hash_from_file('test2.jpg')
	hash2 = "24576:9dR6xbt+XUgTu2YL/ZtT8052UJNZyCWbGNLsw5opPm0Off225NP02Rf:9Ox56dFYr/j8CWaJopu0On22fs2Rf"
	print(hash1)
	print(hash2)
	score0 = compare(hash1, hash1)
	print(score0)
	score = compare(hash1, hash2)
	print(score)
