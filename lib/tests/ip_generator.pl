#!/usr/bin/perl
use strict;

srand(time() ^ ($$ + ($$ << 15)));

for (1..100000){
print join ('.', (int(rand(255))
	,int(rand(255))
	,int(rand(255))
	,int(rand(255))))
	, " "; }

