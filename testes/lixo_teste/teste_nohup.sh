#!/bin/bash

sudo perf record -F 99 -a -g -- sleep 30 -p 19196 -o saida_1.data  &
