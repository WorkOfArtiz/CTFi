#!/usr/bin/env python
# -*- coding: utf-8 -*-
from collections import defaultdict
import argparse,re,sys

# Globals (this is a script, those are kind of impossible to avoid)
rules = defaultdict(list)

parser = argparse.ArgumentParser(prog="CFLI", 
description="The Context-free language interpreter by Arthur de Fluiter.")

parser.add_argument("-i", "--iterations", type=int, default=3,
help="the amount of substitutions (infinite languages spawn infinite datasets, which your computer won't like)")

parser.add_argument("-r", "--rule", type=str, default=[], action='append',
help="a rule in the form of S->a or S -> lambda | aS")

parser.add_argument("-u", "--unicode", action="store_true", 
help="displays lambda as unicode lambda (some terminals can't handle this)")

parser.add_argument("-s", "--start", type=str, default="S",
help="the start variable (default=S)")

parser.add_argument("-l", "--len", action="store_true", 
help="normally the raw set is outputted, this orders it in terms of string size")

parser.add_argument("-f", "--file", type=str, default=[], action="append",
help="rule file, every line may contain at most one rule")

parser.add_argument("-v", "--verbose", action='store_true',
help="give verbose output")

parser.add_argument('--version', action='version', version='%(prog)s 2.8')

args = parser.parse_args()

def parse_rules(args):
	for fn in args.file:
		with open(fn) as f:
			for rule in f:
				parse_rule(rule)
	for rule in args.rule:
		parse_rule(rule)
	if len(rules) == 0:
		print("Error: No rules were given")
		parser.print_help()
		exit(-1)

def parse_rule(rule):
	rule = re.sub(r'\s*', '', rule)
	rule = rule.split("#")[0]
	if rule == "":
		return
	
	var, to = rule.split("->")
	# clean the variable to only contain capitals
	var = re.sub("[^A-Z]+", "", var)
	to = to.split("|")
	for res in to:
		res = re.sub(r'(?i)lambda|λ', "", res)
		rules[var].append(res)

def rm_var_expr(expressions):
	return set(expr for expr in expressions if not has_var(expr))

def has_var(expr):
	return any(l.isupper() for l in expr)

def extend(expr="S"):
	if not has_var(expr):
		return [expr]
	
	res = []
	for l in expr:
		# if l is not var
		if l.islower():
			if not res:
				res.append(l)
			else:
				res = [p+l for p in res]
		else:
			if not res:
				res = [f for f in rules[l]]
			else:
				res = [p + f for p in res for f in rules[l]]
	return res

def generate(args):
	old = [args.start]
	for i in range(args.iterations):
		if args.verbose:
			print("Iteration %d" % i)
			set_print(args, old)
		new = []
		for expr in old:
			new.extend(extend(expr))
		old = new
	old = rm_var_expr(old)
	return old

def set_print(args, result):
	empty = u"\u03BB".encode("utf-8") if args.unicode else 'lambda'
	if not args.len:
		print("{" + ",".join(empty if s == '' else s for s in result) + "}")
	else:
		sorted_d = defaultdict(list)
		for x in result:
			sorted_d[len(x)].append(x)
		for k in sorted(sorted_d.keys()):
			print("Words with len %d:" % k)
			print("{" + ",".join(empty if x == "" else x for x in sorted(sorted_d[k])) + "}")

parse_rules(args)
set_print(args, generate(args))
