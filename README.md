# CTFi

This is the context free language interpreter. A rule set like `palindrome.rule` can be interpreted up until a certain iteration (your computer wouldn't like solving infinite languages I think)

## Program 

So I'm too lazy to list all options here, some trial and error will be required. The program itself has a '-h' and '--help' option like any normal unix-like program. So goodluck with that.

## Rule syntax

Variables are written in capitals like in most mathematical representations, non-terminatal symbols are written in lowercase.

In addition to the strict mathematical notation it is ok to seperate rules with '|'

Demonstration

```
S -> a
S -> bc
S -> TT
T -> aa
```

Note that rules can be entered via commandline or file
