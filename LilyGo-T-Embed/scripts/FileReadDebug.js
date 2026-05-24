var serial = require('serial');
var storage = require('storage');
var dialog = require('dialog');

var serialPrintln = serial.println;
var passwords_file = dialog.pickFile("/");
var data = storage.read(passwords_file)

var binary = storage.read(passwords_file,true);
serialPrintln("Binary data lenght:" + binary.length);

//var text = storage.read(passwords_file);
//serialPrintln("Text data lenght:" + text.length);


