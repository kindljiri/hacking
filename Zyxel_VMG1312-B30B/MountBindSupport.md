
```
/var/tmp # cat /tmp/test
hello 01
/var/tmp # cat /tmp/test02 
hello test02

/var/tmp # mount --bind /tmp/test /tmp/test02 
/var/tmp # cat /tmp/test
hello 01
/var/tmp # cat /tmp/test02 
hello 01
/var/tmp # 
```
