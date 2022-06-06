find $PWD -name \*.h > cscope.files
find $PWD -name \*.c >> cscope.files
cscope -b -k -q
