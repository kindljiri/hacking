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
#|Button|Proto|Value|
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

        if nec_command != 0:

            # INFO (20) → toggle mode
            if nec_address == 1 and nec_command == 20:
                if show_mode == 0:
                    show_mode = 1
                elif show_mode == 1:
                    show_mode = 2
                else:
                    show_mode = 0

            # EXIT (86)
            elif nec_address == 1 and nec_command == 86:
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
        
        if nec_command != 0:
            # EXIT (86)
            if nec_address == 1 and nec_command == 86:
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

        if nec_command != 0:

            # Power
            if nec_address == 1 and nec_command == 25:
                rocky.stop()

            # Red (-1)
            elif nec_address == 1 and nec_command == 82:
                speed = speed - 1
                if speed < 0:
                    speed = 0
                codey.display.show(speed)

            # Green (+1)
            elif nec_address == 1 and nec_command == 87:
                speed = speed + 1
                if speed > 100:
                    speed = 100
                codey.display.show(speed)

            # Yellow (90° left)
            elif nec_address == 1 and nec_command == 30:
                rocky.turn_left_by_degree(90, speed)

            # Blue (180° left)
            elif nec_address == 1 and nec_command == 17:
                rocky.turn_left_by_degree(180, speed)

            # Rew (<<) -1
            elif nec_address == 1 and nec_command == 74:
                speed = speed - 1
                if speed < 0:
                    speed = 0
                codey.display.show(speed)

            # Fwd (>>) +1
            elif nec_address == 1 and nec_command == 8:
                speed = speed + 1
                if speed > 100:
                    speed = 100
                codey.display.show(speed)

            # Prew (|<<) -10
            elif nec_address == 1 and nec_command == 85:
                speed = speed - 10
                if speed < 0:
                    speed = 0
                codey.display.show(speed)

            # Next (>>|) +10
            elif nec_address == 1 and nec_command == 67:
                speed = speed + 10
                if speed > 100:
                    speed = 100
                codey.display.show(speed)

            # Info
            elif nec_address == 1 and nec_command == 20:
                codey.display.show(speed)
                #codey.broadcast("Speed:" + str(speed))

            # Menu
            elif nec_address == 1 and nec_command == 73:
                codey.led.off()
                codey.display.show("Menu:")
                return

            # Exit
            elif nec_address == 1 and nec_command == 86:
                codey.led.off()
                codey.display.show("Menu:")
                return

            # Up (forward)
            elif nec_address == 1 and nec_command == 80:
                if rocky.color_ir_sensor.is_obstacle_ahead() and obstacle_detection:
                    rocky.stop()
                    codey.led.show(255, 0, 0)
                    codey.display.show("Obstacle")
                else:
                    rocky.forward(speed)
                    codey.led.show(0, 255, 0)
                    codey.display.show_image(sun_glasses, 0, 0)

            # Down (backward)
            elif nec_address == 1 and nec_command == 18:
                rocky.backward(speed)
                codey.display.show_image(sun_glasses, 0, 0)
                codey.led.show(0, 255, 0)

            # Right
            elif nec_address == 1 and nec_command == 23:
                rocky.turn_right(speed)
                codey.display.show_image(sun_glasses, 0, 0)
                codey.led.show(0, 255, 0)

            # Left
            elif nec_address == 1 and nec_command == 22:
                rocky.turn_left(speed)
                codey.display.show_image(sun_glasses, 0, 0)
                codey.led.show(0, 255, 0)

            # Play → disable obstacle detection for 60 seconds
            elif nec_address == 1 and nec_command == 91:
                obstacle_detection = False
                obstacle_detection_until = time.time() + 60
                codey.display.show("OD OFF")
                time.sleep(0.3)
                codey.display.show_image(sun_glasses, 0, 0)

            # Stop → enable obstacle detection immediately
            elif nec_address == 1 and nec_command == 68:
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

        if nec_command != 0:

            # UP (80)
            if nec_address == 1 and nec_command == 80:
                menu_index = menu_index - 1
                if menu_index < 0:
                    menu_index = len(menu) - 1

            # DOWN (18)
            elif nec_address == 1 and nec_command == 18:
                menu_index = menu_index + 1
                if menu_index >= len(menu):
                    menu_index = 0

            # OK 
            elif nec_address == 1 and nec_command == 19:
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
        
