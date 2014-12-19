#!/usr/bin/env python
"""
Modified levenshtein distance calculation
Rewritten in Python from a C implementation in ssdeep.

This program can be used, redistributed or modified under any of
Boost Software License 1.0, GPL v2 or GPL v3
See the file COPYING for details.

$Id$

Copyright (C) 2014 kikairoya <kikairoya@gmail.com>
Copyright (C) 2014 Jesse Kornblum <research@jessekornblum.com>
Copyright (C) 2014 Paul Chaignon <paul.chaignon@gmail.com>
"""

EDIT_DISTN_MAXLEN = 64 # MAX_SPAMSUM
EDIT_DISTN_INSERT_COST = 1
EDIT_DISTN_REMOVE_COST = 1
EDIT_DISTN_REPLACE_COST = 2

def edit_distn(s1, s1len, s2, s2len):
	t = [[0] * (EDIT_DISTN_MAXLEN + 1), [0] * (EDIT_DISTN_MAXLEN + 1)]
	for i2 in range(0, s2len + 1):
		t[0][i2] = i2
	for i1 in range(0, s1len):
		t[1][0] = i1 + 1
		for i2 in range(0, s2len):
			cost_a = t[0][i2 + 1] + EDIT_DISTN_INSERT_COST
			cost_d = t[1][i2] + EDIT_DISTN_REMOVE_COST
			cost_r = t[0][i2]
			if s1[i1] != s2[i2]:
				cost_r += EDIT_DISTN_REPLACE_COST
			t[1][i2 + 1] = min(cost_a, cost_d, cost_r)
		temp = t[0]
		t[0] = t[1]
		t[1] = temp
	return t[0][s2len]



"""

HELLOWORLD = "Hello World!"

# Convenience method for getting the edit distance of two strings
def edit_dist(a, b):
	a_len = 0
	b_len = 0
	if a:
		a_len = len(a)
	if b:
		b_len = len(b)

	return edit_distn(a, a_len, b, b_len)


# Exercises edit_dist on a and b. If the result matches the expected value,
# returns 0. If not, displays the message and returns 1.
def run_test(a, b, expected, msg):
	actual = edit_dist(a, b)
	if actual == expected:
		return 0

	print("FAIL: Expected %d, got %d for %s:%s, %s" % (expected, actual, a, b, msg))
	return 1


if __name__ == "__main__":
	failures = 0
	failures += run_test(None, HELLOWORLD, 12, "Null source")
	failures += run_test(HELLOWORLD, None, 12, "Null dest")
	failures += run_test("", HELLOWORLD, 12, "Empty source")
	failures += run_test(HELLOWORLD, "", 12, "Empty destination")
	failures += run_test(HELLOWORLD, HELLOWORLD, 0, "Equal strings")
	failures += run_test("Hello world", "Hell world", 1, "Delete")
	failures += run_test("Hell world", "Hello world", 1, "Insert")
	failures += run_test("Hello world", "Hello owrld", 2, "Swap")
	failures += run_test("Hello world", "HellX world", 2, "Change")

	if failures > 0:
		print("\n%u tests failed." % failures)
		sys.exit(1)

	print("All tests passed.")
	sys.exit(0)
"""
