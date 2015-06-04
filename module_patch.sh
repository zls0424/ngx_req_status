#!/bin/bash

v=$(echo ${1:-1.7.0} | awk -F'.' '{print $1*1000000+$2*1000+$3}')
p=

if [ $v -lt 1007011 ]; then
  p="$p write_filter.patch"
else
  p="$p write_filter-1.7.11.patch"
fi

echo $p
