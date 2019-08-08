# lab3_TELE4642

USAGE: 
topo.py:
        $sudo python topo.py
 
ryuapp.py:
        $ryu-manager ryuapp1.py
DET tool:

CLient-side: 
           $sudo python det.py -L -c ./config-server.json -p dns
Server-side: 
           $sudo python det.py -L -c ./config-client.json -p dns
