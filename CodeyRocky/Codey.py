import codey
import event
import rocky
import time
import random
#import codey_broadcast

# #Codey Rocky G33kOS
# The system after start is controled by EMOS Ir Remote control 
# Have 3 modes based on 3 buttons 
# - A - Main Menu controlled by EMOS Ir Remote
# - B - NEC Ir Decoder
# - C 
#
# ##EMOS Ir codes 
# EMOS is NEC coded remote below is mapping of codes(DEC) to buttons on remote
#|Button|Address|Command|
#|Power|1|25|
#|Mute|1|5|
#|Red|1|82|
#|Green|1|87|
#|Yellow|1|30|
#|Blue|1|17|
#|Rew(<<)|1|74|
#|Fwd(>>)|1|8|
#|Prew(|<<)|1|85|
#|Next(>>|)|1|67|
#|Play|1|91|
#|Pause|1|7|
#|Stop|1|68|
#|USB|1|79|
#|Sub|1|12|
#|Text|1|94|
#|Goto|1|66|
#|Audio|1|64|
#|EPG|1|88|
#|Info|1|20|
#|Menu|1|73|
#|Exit|1|86|
#|Up|1|80|
#|Down|1|18|
#|Right|1|23|
#|Left|1|22|
#|OK|1|19|
#|Vol+|1|16|
#|Vol-|1|116|
#|Ch+|1|216|
#|Ch-|1|316|
#|1|1|1|
#|2|1|9|
#|3|1|13|
#|4|1|2|
#|5|1|10|
#|6|1|14|
#|7|1|3|
#|8|1|11|
#|9|1|15|
#|0|1|65|
#|Recall|1|27|
#|TV/Radio|1|81|

def NECCommandName(cmd):
    if cmd == 25:  return "Power"
    elif cmd == 5:  return "Mute"
    elif cmd == 82: return "Red"
    elif cmd == 87: return "Green"
    elif cmd == 30: return "Yellow"
    elif cmd == 17: return "Blue"
    elif cmd == 74: return "Rew"
    elif cmd == 8:  return "Fwd"
    elif cmd == 85: return "Prev"
    elif cmd == 67: return "Next"
    elif cmd == 91: return "Play"
    elif cmd == 7:  return "Pause"
    elif cmd == 68: return "Stop"
    elif cmd == 79: return "USB"
    elif cmd == 12: return "Sub"
    elif cmd == 94: return "Text"
    elif cmd == 66: return "Goto"
    elif cmd == 64: return "Audio"
    elif cmd == 88: return "EPG"
    elif cmd == 20: return "Info"
    elif cmd == 73: return "Menu"
    elif cmd == 86: return "Exit"
    elif cmd == 80: return "Up"
    elif cmd == 18: return "Down"
    elif cmd == 23: return "Right"
    elif cmd == 22: return "Left"
    elif cmd == 19: return "OK"
    elif cmd == 16: return "Vol+"
    elif cmd == 116: return "Vol-"
    elif cmd == 216: return "Ch+"
    elif cmd == 316: return "Ch-"
    elif cmd == 1:  return "1"
    elif cmd == 9:  return "2"
    elif cmd == 13: return "3"
    elif cmd == 2:  return "4"
    elif cmd == 10: return "5"
    elif cmd == 14: return "6"
    elif cmd == 3:  return "7"
    elif cmd == 11: return "8"
    elif cmd == 15: return "9"
    elif cmd == 65: return "0"
    elif cmd == 27: return "Recall"
    elif cmd == 81: return "TV/Radio"

    return "Unknown"


def Battery():
    # Read battery percentage
    p = codey.battery.get_percentage()
    v = codey.battery.get_voltage()
    v = codey.battery.get_voltage()
    vs = str(v)
    v = vs[0:4]

    # Convert percentage to index 0–10
    idx = p // 10
    if idx > 10:
        idx = 10

    # Build battery image dynamically
    filled = "7e" * (1 + idx)
    empty = "42" * (10 - idx)
    img = "0000" + filled + empty + "7e3c00"

    # Modes: 0 = image, 1 = text
    show_mode = 0
    last_mode = -1   # force initial draw

    while True:
        # Read IR
        nec_address, nec_command = codey.ir.receive_remote_code()
        nec_cmd_name = NECCommandName(nec_command)

        if nec_address == 1 and nec_command != 0:

            # INFO (20) - toggle mode
            if nec_cmd_name == "Info":
                if show_mode == 0:
                    show_mode = 1
                elif show_mode == 1:
                    show_mode = 2
                else:
                    show_mode = 0

            # EXIT (86)
            elif nec_cmd_name == "Exit":
                codey.led.off()
                codey.display.show("Menu:") #Because return to MainMenu will not redraw display
                return
            
        # Draw only when mode changes
        if show_mode != last_mode:
            if show_mode == 0:
                codey.display.show_image(img, 0, 0)
            elif show_mode == 1: 
                codey.display.show(str(p) + "%")
            else:
                codey.display.show(v + "V")
            last_mode = show_mode

        time.sleep(0.03)

def Dice():
    codey.display.show("Shake")
    shaken = False
    
    while True:
        # Read IR
        nec_address, nec_command = codey.ir.receive_remote_code()
        nec_cmd_name = NECCommandName(nec_command)

        if nec_address == 1 and nec_command != 0:
            # EXIT (86)
            if nec_cmd_name == "Exit":
                codey.led.off()
                codey.display.show("Menu:") #Because return to MainMenu will not redraw display
                return
        
        if codey.motion_sensor.get_shake_strength() > 50:
            shaken = True
            rnd_number = str(random.randint(1, 6))
            
        if shaken:
            codey.display.show("  " + rnd_number)
            shaken = False
            time.sleep(2)

def IRDrive():
    speed = 10
    obstacle_detection = True
    obstacle_detection_until = 0

    sun_glasses = "207c7e7e7e7e7c20207c7e7e7e7e7c20"
    codey.display.show_image(sun_glasses, 0, 0)

    while True:

        # --- AUTO RE-ENABLE OBSTACLE DETECTION AFTER TIMEOUT ---
        if not obstacle_detection and time.time() > obstacle_detection_until:
            obstacle_detection = True
            codey.led.show(0, 0, 255)  # optional visual feedback
            codey.display.show("OD ON")
            time.sleep(0.3)
            codey.display.show_image(sun_glasses, 0, 0)

        nec_address, nec_command = codey.ir.receive_remote_code()
        nec_cmd_name = NECCommandName(nec_command)

        if nec_address == 1 and nec_command != 0:

            # Power
            if nec_cmd_name == "Power":
                rocky.stop()

            # Red (-1)
            elif nec_cmd_name == "Red":
                speed = speed - 1
                if speed < 0:
                    speed = 0
                codey.display.show(speed)

            # Green (+1)
            elif nec_cmd_name == "Green":
                speed = speed + 1
                if speed > 100:
                    speed = 100
                codey.display.show(speed)

            # Yellow (90° left)
            elif nec_cmd_name == "Yellow":
                rocky.turn_left_by_degree(90, speed)

            # Blue (180° left)
            elif nec_cmd_name == "Blue":
                rocky.turn_left_by_degree(180, speed)

            # Rew (<<) -1
            elif nec_cmd_name == "Rew":
                speed = speed - 1
                if speed < 0:
                    speed = 0
                codey.display.show(speed)

            # Fwd (>>) +1
            elif nec_cmd_name == "Fwd":
                speed = speed + 1
                if speed > 100:
                    speed = 100
                codey.display.show(speed)

            # Prev (|<<) -10
            elif nec_cmd_name == "Prev":
                speed = speed - 10
                if speed < 0:
                    speed = 0
                codey.display.show(speed)

            # Next (>>|) +10
            elif nec_cmd_name == "Next":
                speed = speed + 10
                if speed > 100:
                    speed = 100
                codey.display.show(speed)

            # Info
            elif nec_cmd_name == "Info":
                codey.display.show(speed)
                #codey.broadcast("Speed:" + str(speed))

            # Menu
            elif nec_cmd_name == "Menu":
                codey.led.off()
                codey.display.show("Menu:")
                return

            # Exit
            elif nec_cmd_name == "Exit":
                codey.led.off()
                codey.display.show("Menu:")
                return

            # Up (forward)
            elif nec_cmd_name == "Up":
                if rocky.color_ir_sensor.is_obstacle_ahead() and obstacle_detection:
                    rocky.stop()
                    codey.led.show(255, 0, 0)
                    codey.display.show("Obstacle")
                else:
                    rocky.forward(speed)
                    codey.led.show(0, 255, 0)
                    codey.display.show_image(sun_glasses, 0, 0)

            # Down (backward)
            elif nec_cmd_name == "Down":
                rocky.backward(speed)
                codey.display.show_image(sun_glasses, 0, 0)
                codey.led.show(0, 255, 0)

            # Right
            elif nec_cmd_name == "Right":
                rocky.turn_right(speed)
                codey.display.show_image(sun_glasses, 0, 0)
                codey.led.show(0, 255, 0)

            # Left
            elif nec_cmd_name == "Left": 
                rocky.turn_left(speed)
                codey.display.show_image(sun_glasses, 0, 0)
                codey.led.show(0, 255, 0)

            # Play - disable obstacle detection for 60 seconds
            elif nec_cmd_name == "Play":
                obstacle_detection = False
                obstacle_detection_until = time.time() + 60
                codey.display.show("OD OFF")
                time.sleep(0.3)
                codey.display.show_image(sun_glasses, 0, 0)

            # Stop - enable obstacle detection immediately
            elif nec_cmd_name == "Stop": 
                obstacle_detection = True
                obstacle_detection_until = 0
                codey.display.show("OD ON")
                time.sleep(0.3)
                codey.display.show_image(sun_glasses, 0, 0)

        else:
            rocky.stop()

            
def MainMenu():
    menu = ["Menu:", "IRDrive", "Battery", " Dice"]
    menu_index = 0
    last_index = -1   # force initial refresh
     
    # show first item
    codey.display.show(menu[menu_index])
    codey.broadcast("Menu")

    while True:
        nec_address, nec_command = codey.ir.receive_remote_code()
        nec_cmd_name = NECCommandName(nec_command)

        if nec_address == 1 and nec_command != 0:

            # UP (80)
            if nec_cmd_name == "Up":
                menu_index = menu_index - 1
                if menu_index < 0:
                    menu_index = len(menu) - 1

            # DOWN (18)
            elif nec_cmd_name == "Down":
                menu_index = menu_index + 1
                if menu_index >= len(menu):
                    menu_index = 0

            # OK 
            elif nec_cmd_name == "OK":
                if menu[menu_index] == "IRDrive":
                    IRDrive()
                elif menu[menu_index] == "Battery":
                    Battery()
                elif menu[menu_index] == " Dice":
                    Dice()

        # Only refresh display if index changed
        if menu_index != last_index:
            codey.display.show(menu[menu_index])
            last_index = menu_index

@event.start
def start_cb():
    simple_eyes="00003c7e7e3c000000003c7e7e3c0000"
    codey.display.show_image(simple_eyes,0,0)
    codey.speaker.play_melody("hello")
    codey.broadcast("hello")
    #codey.display.show_image(image, pos_x = 3, pos_y = 4)
    #last_time = time.time()
    #showing = False
    time.sleep(1.00)
    MainMenu()

@event.button_b_pressed
def button_b_cb():
    codey.stop_other_scripts()
    codey.led.off()
    codey.display.show("NEC Ir Decoder")
    codey.broadcast("NEC Ir Decoder")
    last = None

    while True:
        nec_address, nec_command = codey.ir.receive_remote_code()

        if nec_command != 0 and nec_command != last:
            text = "{}:{}".format(nec_address, nec_command)
            codey.display.show(text)
            last = nec_command

        time.sleep(0.05)

@event.button_a_pressed
def button_a_cb():
    codey.stop_other_scripts()
    MainMenu()
        
