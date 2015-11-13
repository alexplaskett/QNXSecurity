# ppsparse() testers
while true
do
   ./radamsa pps_base.txt > fuzzed.txt
   value=`cat fuzzed.txt`
   ./PPS "$value"
   test $? -gt 127 && break
done


while true
do
	FILES="$(find /pps -type f)"
	for f in ${FILES[@]}
	do
		[ -w $f ] && echo $f && ./radamsa pps_base.txt > fuzzed.txt && cat fuzzed.txt > $f
	done
done

value=`cat fuzzed.txt` && ./PPSJSON "$value"



value=`cat fuzzed.txt` && ./ntox86-gdb --args ./PPS "$value"


while true
do
   ./radamsa base.txt > fuzzed_json.txt
   value=`cat fuzzed_json.txt`
   ./PPSJSON "$value"
   test $? -gt 127 && break
done


value=`cat fuzzed_json.txt` && ./ntox86-gdb --args ./PPSJSON "$value"


while true
do
	./radamsa base.txt > fuzzed_json.txt
	./PPSJSON fuzzed_json.txt
	test $? -gt 127 && break
done


while true
do
	./radamsa pps_base.txt > fuzzed_pps.txt
	./PPSJSON fuzzed_pps.txt
	test $? -gt 127 && break
done



while true
do
	./radamsa test4.txt > fuzzed.txt && cat fuzzed.txt > /pps/services/navigator/control
done

value=`cat fuzzed.txt` && ./PPS "$value"


while true
do
	FILES="$(find /pps -type f)"
	for f in ${FILES[@]}
	do
		[ -w $f ] && echo $f && ./radamsa json_base.txt > fuzzed.txt && cat fuzzed.txt > $f
	done
done



while true
do
	./radamsa base_nav.txt > fuzzed.txt && cat fuzzed.txt > /pps/system/navigator/background
done





/pps/services/bluetooth/public/control
/pps/services/bluetooth/public/btgatt
/pps/services/bluetooth/public/btgattsrv
/pps/services/bluetooth/public/service
/pps/services/bluetooth/public/btle

$ cat /pps/services/bluetooth/.all
@settings
a2dp:b:false
a2dp_snk_disabled:n:1
a2dp_src_disabled:n:1
accessibility:n:3
active_connections:b:false
avrcp_disabled:n:0
bt_disabled:n:0
btaddr::02:C0:0F:73:C2:81
cod:n:131344
connect_on_power_up:b:true
enabled:b:false
hfp_disabled:n:1
hfpg_disabled:n:1
hid_clnt_disabled:n:1
hid_srvr_disabled:n:0
it_policy_allow_work_files:n:1
low_energy_disabled:n:1
map_disabled:n:0
map_download_timeout:n:20
map_html_mode::auto
name::BLACKBERRY-C280
nfc_prompt_to_receive:b:true
opp_clnt_disabled:n:0
opp_srvr_disabled:n:0
pan_disabled:n:1
pbap_disabled:n:0
pwrup_en:b:false
sap_disabled:n:5
spp_disabled:n:0
user_trust_static_nfc_initiated_bluetooth_pairing:b:false

/pps/services/notify/control
/pps/services/bbid/control
/pps/services/audio/control


msg::set_output_level\nid::1\ndat:json:{"name":"headset", "level":75}

toggle_output_mute

msg::toggle_output_mute\nid::1\ndat:json:{'name','headset'}

$ cat /pps/services/audio/.all
@stats
@status
audio.mode::audio
audio.status::normal
hpboostlevel:n:92
hpoutput.regulated:b:false
hpoutput.unregulatedlevel:n:0.000000
hpoverride:b:false
hpoverride.supported:b:false
hpunsafelevel:n:75
hpunsafezone:b:false
hpunsafezone.supported:b:true
input.btsco.gain:n:100.000000
input.btsco.muted:b:false
input.gain:n:100.000000
input.handset.gain:n:100.000000
input.handset.muted:b:false
input.headset.gain:n:100.000000
input.headset.muted:b:false
input.mirrorlink.gain:n:100.000000
input.mirrorlink.muted:b:false
input.muted:b:false
input.tty.gain:n:100.000000
input.tty.muted:b:false
input.usb.gain:n:100.000000
input.usb.muted:b:false
input.voice.gain:n:100.000000
input.voice.muted:b:false
output.a2dp.muted:b:false
output.a2dp.volume:n:100.000000
output.audioshare.muted:b:false
output.audioshare.volume:n:100.000000
output.available::speaker
output.btsco.muted:b:false
output.btsco.volume:n:100.000000
output.hac.muted:b:false
output.hac.volume:n:60.000000
output.handset.muted:b:false
output.handset.volume:n:60.000000
output.hdmi.muted:b:false
output.hdmi.volume:n:100.000000
output.headphone.muted:b:false
output.headphone.volume:n:60.000000
output.headset.muted:b:false
output.headset.volume:n:60.000000
output.lineout.muted:b:false
output.lineout.volume:n:60.000000
output.miracast.muted:b:false
output.miracast.volume:n:100.000000
output.mirrorlink.muted:b:false
output.mirrorlink.volume:n:100.000000
output.speaker.muted:b:false
output.speaker.volume:n:60.000000
output.tones.muted:b:false
output.tones.volume:n:100.000000
output.toslink.muted:b:false
output.toslink.volume:n:100.000000
output.tty.muted:b:false
output.tty.volume:n:100.000000
output.usb.muted:b:false
output.usb.volume:n:100.000000
output.voice.muted:b:false
output.voice.volume:n:60.000000
@voice_status
input.muted:b:false
voice.mode::Off
voice.output.a2dp.muted:b:false
voice.output.a2dp.volume:n:100.000000
voice.output.audioshare.muted:b:false
voice.output.audioshare.volume:n:100.000000
voice.output.btsco.muted:b:false
voice.output.btsco.volume:n:100.000000
voice.output.hac.muted:b:false
voice.output.hac.volume:n:60.000000
voice.output.handset.muted:b:false
voice.output.handset.volume:n:60.000000
voice.output.hdmi.muted:b:false
voice.output.hdmi.volume:n:100.000000
voice.output.headphone.muted:b:false
voice.output.headphone.volume:n:60.000000
voice.output.headset.muted:b:false
voice.output.headset.volume:n:60.000000
voice.output.lineout.muted:b:false
voice.output.lineout.volume:n:60.000000
voice.output.miracast.muted:b:false
voice.output.miracast.volume:n:100.000000
voice.output.mirrorlink.muted:b:false
voice.output.mirrorlink.volume:n:100.000000
voice.output.speaker.muted:b:false
voice.output.speaker.volume:n:60.000000
voice.output.tones.muted:b:false
voice.output.tones.volume:n:100.000000
voice.output.toslink.muted:b:false
voice.output.toslink.volume:n:100.000000
voice.output.tty.muted:b:false
voice.output.tty.volume:n:100.000000
voice.output.usb.muted:b:false
voice.output.usb.volume:n:100.000000
voice.output.voice.muted:b:false
voice.output.voice.volume:n:100.000000
@audio_router_status
voiceservices.cellular.codec::default
voiceservices.cellular.handset.eq::normal
voiceservices.cellular.headphone.eq::normal
voiceservices.cellular.headset.eq::normal
voiceservices.cellular.rate:n:0
voiceservices.cellular.speaker.eq::normal
voiceservices.cellular.status::off
voiceservices.naturalsound.codec::default
voiceservices.naturalsound.rate:n:0
voiceservices.naturalsound.status::off
voiceservices.voip.codec::default
voiceservices.voip.rate:n:0
voiceservices.voip.status::off


/pps/services/audio/audio_router_control

/pps/services/input/control
/pps/services/dialog/control
/pps/services/credmgr/control


/pps/services/launcher/appmon                                                                                                  
/pps/services/progress/control                                                                                                 
/pps/services/vibrator        
/pps/services/wifi_p2p/send/control    


/pps/services/navigator/control                                                                                                
/pps/services/navigator/assets                                                                                                 
/pps/services/navigator/resource                                                                                               

$ cat /pps/services/navigator/.all
@state
bedsideMode:b:false
[n]isDeviceLocked::screenLocked
@control
@assets
@resource

/pps/services/automation/navigator/output                                                                                      
/pps/services/automation/navigator/control                                                                                     
/pps/services/automation/navigator/notify                                                                                      

/pps/services/multimedia/sound/control                                                                                         
/pps/services/multimedia/renderer/control                                                                                      
/pps/services/multimedia/mediaplayer/control
/pps/services/multimedia/mediacontroller/control                                                                               

echo "msg::register\ndat:json:{\"name":\"aaa\",\"notificationService\":"bbbb\",\"prio\":\"pem\"}" > /pps/services/multimedia/mediaplayer/control


.rodata:000B6DB6 aMsgButtonDatJs DCB "msg::button",0xA   ; DATA XREF: .data:000E9180o
.rodata:000B6DB6                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_vdown_short",0x22,",",0x22,"action",0x22,":",0x22,"f"
.rodata:000B6DB6                 DCB "orward",0x22,"}",0
.rodata:000B6DF7 aMsgButtonDat_0 DCB "msg::button",0xA   ; DATA XREF: .data:000E9184o
.rodata:000B6DF7                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_vdown_med",0x22,",",0x22,"action",0x22,":",0x22,"fo"
.rodata:000B6DF7                 DCB "rward",0x22,"}",0
.rodata:000B6E36 aMsgButtonDat_1 DCB "msg::button",0xA   ; DATA XREF: .data:000E9188o
.rodata:000B6E36                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_vdown_long",0x22,",",0x22,"action",0x22,":",0x22,"f"
.rodata:000B6E36                 DCB "orward",0x22,"}",0
.rodata:000B6E76 aMsgButtonDat_2 DCB "msg::button",0xA   ; DATA XREF: .data:000E918Co
.rodata:000B6E76                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_vup_short",0x22,",",0x22,"action",0x22,":",0x22,"fo"
.rodata:000B6E76                 DCB "rward",0x22,"}",0
.rodata:000B6EB5 aMsgButtonDat_3 DCB "msg::button",0xA   ; DATA XREF: .data:000E9190o
.rodata:000B6EB5                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_vup_med",0x22,",",0x22,"action",0x22,":",0x22,"forw"
.rodata:000B6EB5                 DCB "ard",0x22,"}",0
.rodata:000B6EF2 aMsgButtonDat_4 DCB "msg::button",0xA   ; DATA XREF: .data:000E9194o
.rodata:000B6EF2                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_vup_long",0x22,",",0x22,"action",0x22,":",0x22,"for"
.rodata:000B6EF2                 DCB "ward",0x22,"}",0
.rodata:000B6F30 aMsgButtonDat_5 DCB "msg::button",0xA   ; DATA XREF: .data:000E9198o
.rodata:000B6F30                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_playpause_short",0x22,",",0x22,"action",0x22,":"
.rodata:000B6F30                 DCB 0x22,"forward",0x22,"}",0
.rodata:000B6F75 aMsgButtonDat_6 DCB "msg::button",0xA   ; DATA XREF: .data:000E919Co
.rodata:000B6F75                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_playpause_med",0x22,",",0x22,"action",0x22,":",0x22
.rodata:000B6F75                 DCB "forward",0x22,"}",0
.rodata:000B6FB8 aMsgButtonDat_7 DCB "msg::button",0xA   ; DATA XREF: .data:000E91A0o
.rodata:000B6FB8                 DCB "dat:json:{",0x22,"key",0x22,":",0x22,"bn_playpause_long",0x22,",",0x22,"action",0x22,":",0x22
.rodata:000B6FB8                 DCB "forward",0x22,"}",0



echo "msg::register\ndat:json:{\"name":\"aaa\",\"notificationService\":"bbbb\",\"prio\":\"pem\"}" > /pps/services/multimedia/mediaplayer/control
echo "msg::button\ndat:json:{\"key":\"aaa\",\"bn_playpause_long\":"bbbb\"}" > /pps/services/multimedia/mediaplayer/control


/pps/services/networking/proxyserver                                                                                           
/pps/services/credmgr.entr/control                                                                                             
/pps/services/certmgr_server/control_public                                                                                    
/pps/services/tztrans/control                                                                                                  
/pps/services/bbm/meetings/service_control                                                                                     
/pps/services/paymentsystem/control     
/pps/system/navigator/background                                                                                               
/pps/system/splash  





"json:{ \"entry\" : \"sys.service.a11y\", \"cmd\" : \"/services/sys.service.a11y/service.sh start &\", \"flags\" : \"\", \"path\" : [ \"(cg660)a11y/at.bb_a11y_registry/default\",\"(cg666)a11y/rt.bb_a11y_registry/default\"], \"caps\" : \"\" }"




Sep 22 09:58:48.435             bslauncher.1826867        bsl-intercept      0  Request for /pps/services/wifi_p2p/send/control, starting sys.service.wifi-direct-send..default
Sep 22 09:58:48.435             bslauncher.1826867        bsl-intercept      0  Authman defapp ext default personal single 232 230 sys.service.wifi-direct-send sys sys 0 access_impostor_control use_notify_system access_personal_shared returned 7
Sep 22 09:58:48.435             bslauncher.1826867        bsl-intercept      0  Start _SERVICEPATH=/pps/services/wifi_p2p/send/control /services/sys.service.wifi-direct-send/service.sh start &
Sep 22 09:58:53.436             bslauncher.1826867        bsl-intercept      0  Timeout waiting for sys.service.wifi-direct-send to attach to its service paths
Sep 22 09:58:53.436             bslauncher.1826867        bsl-intercept      0  return timeout ENXIO to client waitlisted on services/wifi_p2p/send/control


.rodata:0004C349 0000001E C msg::check\nid::wifi_p2p_send\n                                          
.rodata:0004C2BB 0000001D C msg::copy\nid::wifi_p2p_send\n                                           
.rodata:00051114 0000002F C msg::wifi_p2p_start_session\nid::wifi_p2p_send\n                         
.rodata:000511BE 00000046 C msg::wifi_p2p_stop_session\nid::wifi_p2p_send\ndat:json:{\"session_key\":

echo "msg::check\nid::wifi_p2p_send\n" >  /pps/services/wifi_p2p/send/control

echo "msg::wifi_p2p_stop_session\nid::wifi_p2p_send\ndat:json:{\"session_key\":" > /pps/services/wifi_p2p/send/control





$ cat /pps/services/automation/navigator/.all
@output
_dest::
_id::
_src::
dat::enableCSNotification
msg::watch\ndat:json:{\"object\":\"/pps/system/installer/upd/current/.all\",\"exec\":\"/tmp/test.sh\","timeout\":1}\
response::cs_notifcation=1;
@control
@notify


echo "msg::watch\ndat:json:{\"object\":\"/pps/system/installer/upd/current/.all\",\"exec\":\"aaaaaaaa\",\"timeout\":1}" > /pps/services/automation/navigator/control



echo "AAAAA" > /pps/services/automation/navigator/control



echo "msg::watch\ndat:json:{\"object\":\"aaaaa\",\"exec\":\"aaaaaaaa\",\"timeout\":1}" > /pps/services/automation/navigator/notify



"json:{ \"entry\" : \"sys.service.a11y\", \"cmd\" : \"/services/sys.service.a11y/service.sh start &\", \"flags\" : \"\", \"path\" : [ \"(cg660)a11y/at.bb_a11y_registry/default\",\"(cg666)a11y/rt.bb_a11y_registry/default\"], \"caps\" : \"\" }"

echo "msg::launchService\ndat:json:{ \"entrypoint\" : \"sys.service.a11y\", \"cmd\" : \"/services/sys.service.a11y/service.sh start &\", \"flags\" : \"\", \"path\" : [ \"(cg660)a11y/at.bb_a11y_registry/default\",\"(cg666)a11y/rt.bb_a11y_registry/default\"], \"caps\" : \"\" }" > /pps/system/bslauncher



# echo "msg::getForegroundAppInfo\n" > /pps/services/automation/navigator/control && cat /pps/services/automation/navigator/output
@output
_dest::
_id::
_src::
dat::getForegroundAppInfo
msg::watch\ndat:json:{\"object\":\"/pps/system/installer/upd/current/.all\",\"exec\":\"/tmp/test.sh\","timeout\":1}\
response::name=sys.settings.gYABgFXZghhSmuJ6oBTACT1DwpQ;label=Settings;pid=0;uriname=NULL;urilabel=NULL;orientation=portrait;layout_orientation=0;active=0;landscape=0;angle=0;visible=1;fullscreen=0;cover=1;preloaded=0;perimeter=0;splat=0;x=0;y=0;height=396;width=334;total-cards=0;


openAutomationInterface
closeAutomationInterface
getForegroundAppInfo
getAllRunningApps
enableAppNotification
disableAppNotification
enableCSNotification
disableCSNotification


echo "msg::disableCSNotification\n" > /pps/services/automation/navigator/control && cat /pps/services/automation/navigator/output



echo "msg::invoke\nid::1\ndat:json:{'name','headset'}" > /pps/services/navigator/control

/pps/services/navigator/control


while true
do
	./radamsa test.txt > fuzzed.txt && cat fuzzed.txt > /pps/services/bluetooth/public/control
done



shell echo set \$x=\"$(cat fuzzed_json.txt)\"





while true
do
	./radamsa base.txt > fuzzed_json.txt
	./PPSJSON fuzzed_json.txt
	test $? -gt 127 && break
done


while true
do
	./radamsa pps_base.txt > fuzzed_pps.txt
	./PPSJSON fuzzed_pps.txt
	test $? -gt 127 && break
done
