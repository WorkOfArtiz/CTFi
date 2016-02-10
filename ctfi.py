#!/usr/bin/env python
# -*- coding: utf-8 -*-
from collections import defaultdict
import argparse,re,sys

# Globals (this is a script, those are kind of impossible to avoid)
rules = defaultdict(list)

parser = argparse.ArgumentParser(prog="CFLI", 
description="The Context-free language interpreter by Arthur de Fluiter.")

parser.add_argument("-l", "--len", action="store_true", 
help="(gen only) normally the raw set is outputted, this orders it in terms of string size")

parser.add_argument("-r","--rule", type=str, default=[], action='append',
help="a rule in the form of S->a or S -> lambda | aS")

parser.add_argument("-f", "--file", type=str, default=[], action="append",
help="rule file, every line may contain at most one rule")

parser.add_argument("-a", "--action", choices=['gen','rl2ll', 'll2rl', 'mini'], default='gen',
help="gen will generate n iterations\nrl2ll will transform a right linear rule set to left linear, ll2rl the other way around\nmini will attempt to minify your ruleset (not very intelligent)")

parser.add_argument("-i","--iterations", type=int, default=3,
help="the amount of substitutions when generating (infinite languages spawn infinite datasets, which your computer won't like)")

parser.add_argument("-u", "--unicode", action="store_true", 
help="displays lambda as unicode lambda (some terminals can't handle this)")

parser.add_argument("-s", "--start", type=str, default="S",
help="the start variable (default=S)")

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
    
    if args.verbose:
        print("Interpreted Rules:")
        print_rules(rules, args.start)

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

def print_rules(rules, initial):
    empty = u"\u03BB".encode("utf-8") if args.unicode else 'lambda'
    if initial not in rules.keys():
        print("your rules reduced to nothing, maybe you didn't start at %s see --start" % args.start)
        return
    
    print("initial node: %s" % initial) 
    print("%s -> %s" % (initial, " | ".join(empty if v == "" else v for v in rules[initial])))
    for k in rules.keys():
        if k == initial:
            continue
        print("%s -> %s" % (k, " | ".join(empty if v == "" else v for v in rules[k])))
        
def rm_var_expr(expressions):
    return set(expr for expr in expressions if not has_var(expr))

def has_var(expr):
    return any(l.isupper() for l in expr)

def has_term(expr):
    return any(l.islower() for l in expr)

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

def validate_linear(right, strict):
    if right:
        if strict:
            regex = re.compile(r'^[a-z]?[A-Z]?$')
            error = "The expression %s -> %s is not in strict right linear form"
        else:
            regex = re.compile(r'^[a-z]*[A-Z]?$')
            error = "The expression %s -> %s is not in right linear form"
    else:
        if strict:
            regex = re.compile(r'^[A-Z]?[a-z]?$')
            error = "The expression %s -> %s is not in strict left linear form"
        else:
            regex = re.compile(r'^[A-Z]?[a-z]*$')
            error = "The expression %s -> %s is not in left linear form"
    
    for key in rules.keys():
        for expr in rules[key]:
            if not regex.match(expr):
                raise Exception(error % (key, "lambda" if expr == "" else expr))
    
def right_linear2left_linear(args):
    validate_linear(True, False)
    generated = defaultdict(set)
    visited = defaultdict(bool)
    todo = [args.start]
    final = get_unused_var()
    
    generated[args.start].add("")
    
    while len(todo) > 0:
        s = todo.pop()
        if visited[s]:
            continue
        visited[s] = True
        
        for t in rules[s]:
            if not has_var(t):
                generated[final].add("%s%s" % (s,t))
            else:
                if has_term(t):
                    u, V = re.findall("[a-z]+|[A-Z]", t)
                    generated[V].add(s+u)
                    todo.append(V)
                else:
                    V = t
                    generated[V].add(s)
                    todo.append(V)
    print("Generated ruleset:")
    final = minify(generated, final)
    print_rules(generated, final)

def left_linear2left_right_linear(args):
    validate_linear(False, False)
    generated = defaultdict(set)
    visited = defaultdict(bool)
    todo = [args.start]
    final = get_unused_var(final=False)
    
    generated[args.start].add("")
    
    while len(todo) > 0:
        s = todo.pop()
        if visited[s]:
            continue
        visited[s] = True
        
        for t in rules[s]:
            if not has_var(t):
                generated[final].add("%s%s" % (t,s))
            else:
                if has_term(t):
                    V,u = re.findall("[a-z]+|[A-Z]", t)
                    generated[V].add(u+s)
                    todo.append(V)
                else:
                    V = t
                    generated[V].add(s)
                    todo.append(V)
    print("Generated ruleset:")
    final = minify(generated, final)
    print_rules(generated, final)

def minify(rules,initial):
    if len(rules) < 2:
        return initial
    
    todo = [initial]
    visited = defaultdict(bool)

    while todo:
        s = todo.pop()
        if visited[s]:
            continue
        visited[s] = True
        
        rules_s = rules[s]
        if len(rules_s) == 0:
            raise Exception("variable %s can be reached but not replaced by anything" % s)
        elif len(rules_s) == 1:
            one_rule, = rules_s
            
            if one_rule == "" and s != initial:
                replace(rules, s, one_rule)
            elif not has_term(one_rule):
                if s == initial:
                    initial = one_rule
                replace(rules, s, one_rule) 
            elif s != initial:
                replace(rules, s, one_rule)
        for expr in rules_s:
            todo.extend(re.findall("[A-Z]", expr))
    
    for k in rules.keys():
        if not visited[k]:
            del rules[k]
    return initial

def replace(rules, s, t):
    fill_in = rules[s]
    if len(fill_in) != 1:
        raise Exception("replacing complex expressions isn't supported yet")
    
    for k in rules.keys():
        rules[k] = [x.replace(s,t) for x in rules[k] ]
    
    del(rules[s])
    
def get_unused_var(final=True):
    vars = rules.keys()
    for l in "FSTZXYQPABCDEGHIJKLMNORUVW" if final else "SQTABCDEGHIJKLMNORUVWFZXYP":
        if l not in vars:
            return l
    raise Exception("There aren't any remaining variables that can be used")
    
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
if args.action == 'gen':
    set_print(args, generate(args))
elif args.action == 'rl2ll':
    right_linear2left_linear(args)
elif args.action == 'll2rl':
    left_linear2left_right_linear(args)
elif args.action == 'mini':
    args.start = minify(rules, args.start)
    print_rules(rules, args.start)
else:
    raise Exception("Unknown Action")