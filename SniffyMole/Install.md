## Flash micropython

```
esptool.py erase_flash
esptool.py --baud 460800 write_flash 0x1000 ESP32_GENERIC-SPIRAM-20260406-v1.28.0.bin
```

## Upload the code

mpremote connect /dev/ttyUSB0
mpremote fs cp smble.py :smble.py
mpremote fs cp main.py :main.py
mpremote fs cp netscan.py :netscan.py

## Connect to device 

and enjoy

picocom -b 115200 /dev/ttyUSB0