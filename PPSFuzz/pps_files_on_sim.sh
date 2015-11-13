

# Script to test writable files:

$ cat test.sh
FILES="$(find /pps -type f)"

for f in ${FILES[@]}
do

#echo "test" >> $f

[ -w $f ] && echo $f
#if [ $? -eq 0 ]; then
#       #echo "test"
#fi

done



bbid in this list:

on the sim:
/pps/services/bluetooth/public/control
/pps/services/bluetooth/public/btgatt
/pps/services/bluetooth/public/btgattsrv
/pps/services/bluetooth/public/service
/pps/services/bluetooth/public/btle
/pps/services/notify/control
/pps/services/bbid/control
/pps/services/audio/control
/pps/services/audio/audio_router_control
/pps/services/input/control
/pps/services/dialog/control
/pps/services/launcher/appmon
/pps/services/progress/control
/pps/services/vibrator
/pps/services/wifi_p2p/send/control
/pps/services/navigator/control
/pps/services/navigator/assets
/pps/services/navigator/resource
/pps/services/automation/navigator/output
/pps/services/automation/navigator/control
/pps/services/automation/navigator/notify
/pps/services/multimedia/sound/control
/pps/services/multimedia/renderer/control
/pps/services/multimedia/mediaplayer/control
/pps/services/multimedia/mediacontroller/control
/pps/services/networking/proxyserver
/pps/services/certmgr_server/control_public
/pps/services/tztrans/control
/pps/services/paymentsystem/control
/pps/system/navigator/background
/pps/system/splash

On the device:
/pps/services/bluetooth/public/control
/pps/services/bluetooth/public/btgatt
/pps/services/bluetooth/public/btgattsrv
/pps/services/bluetooth/public/service
/pps/services/bluetooth/public/btle
/pps/services/notify/control
/pps/services/bbid/control
/pps/services/audio/control
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
/pps/services/automation/navigator/output                                                                                      
/pps/services/automation/navigator/control                                                                                     
/pps/services/automation/navigator/notify                                                                                      
/pps/services/multimedia/sound/control                                                                                         
/pps/services/multimedia/renderer/control                                                                                      
/pps/services/multimedia/mediaplayer/control
/pps/services/multimedia/mediacontroller/control                                                                               
/pps/services/networking/proxyserver                                                                                           
/pps/services/credmgr.entr/control                                                                                             
/pps/services/certmgr_server/control_public                                                                                    
/pps/services/tztrans/control                                                                                                  
/pps/services/bbm/meetings/service_control                                                                                     
/pps/services/paymentsystem/control     
/pps/system/navigator/background                                                                                               
/pps/system/splash  

//////////////////////////////////////////////////////////////////////////////////////////////////////////

-rw-rw-rw-  1 blueman   bluetooth         9 Apr 27 07:53 /pps/services/bluetooth/public/control


-rw-rw-rw-  1 root      nto              11 Apr 27 07:35 /pps/services/bluetooth/public/btgatt


-rw-rw-rw-  1 root      nto              14 Apr 27 07:35 /pps/services/bluetooth/public/btgattsrv


-rw-rw-rw-  1 root      nto              12 Apr 27 07:35 /pps/services/bluetooth/public/service



-rw-rw-rw-  1 root      nto               9 Apr 27 07:57 /pps/services/bluetooth/public/btle



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

-rw-rw-rw-  1 notifications notifications         9 Apr 27 07:31 /pps/services/notify/control

-rw-rw-rw-  1 media     media            12 Apr 27 07:35 /pps/services/audio/control

-rw-rw-rw-  1 media     media            25 Apr 27 07:35 /pps/services/audio/audio_router_control

-rw-rw-rw-  1 root      nto              12 Apr 27 08:00 /pps/services/input/control

-rw-rw-rw-  1 apps      dialog_service        12 Apr 27 07:31 /pps/services/dialog/control

-rw-rw-rw-  1 root      nto              11 Apr 27 07:31 /pps/services/launcher/appmon

-rw-rw-rw-  1 progress  progress         12 Apr 27 07:31 /pps/services/progress/control

-rw-rw-rw-  1 wfdsend   wfdirect         12 Apr 27 07:31 /pps/services/wifi_p2p/send/control

-rw-rw-rw-  1 root      nto              12 Apr 27 07:32 /pps/services/navigator/control
-rw-rw-rw-  1 root      nto              11 Apr 27 07:35 /pps/services/navigator/assets
-rw-rw-rw-  1 root      nto              13 Apr 27 07:31 /pps/services/navigator/resource

-rw-rw-rw-  1 root      nto              83 Apr 27 07:35 /pps/services/automation/navigator/output
-rw-rw-rw-  1 root      nto               9 Apr 27 07:32 /pps/services/automation/navigator/control
-rw-rw-rw-  1 root      nto           26833 Apr 27 08:00 /pps/services/automation/navigator/notify

-rw-rw-rw-  1 root      soundplayerd        12 Apr 27 07:35 /pps/services/multimedia/sound/control
-rw-rw-rw-  1 context   nobody           12 Apr 27 07:31 /pps/services/multimedia/renderer/control
-rw-rw-rw-  1 nowplaying now_playing         9 Apr 27 07:31 /pps/services/multimedia/mediaplayer/control
-rw-rw-rw-  1 nowplaying now_playing         9 Apr 27 08:00 /pps/services/multimedia/mediacontroller/control
-rw-rw-rw-  1 root      nto              16 Apr 27 07:35 /pps/services/networking/proxyserver
-rw-rw-rw-  1 certmgr   certmgr          16 Apr 27 07:31 /pps/services/certmgr_server/control_public



dat:json:{"store":"/var/certmgr/%s/%s"}


-rw-rw-rw-  1 root      nto              12 Apr 27 07:31 /pps/services/tztrans/control
-rw-rw-rw-  1 100171000 10017            12 Apr 27 07:31 /pps/services/paymentsystem/control
-rw-rw-rw-  1 bb10_boot bb10_boot         8 Apr 27 07:32 /pps/system/splash

echo "dat:json:{\"store\":\"/var/certmgr/aaa\"}" > /pps/services/certmgr_server/control_public



/////////////////////////////

msg::command_string\nid::ID_number\ndat:json:{JSON_data}

