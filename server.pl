#!/usr/bin/perl
#
##########################################
#     Spoofing Auditing Server           #
#                                        #
# This server is part of the Spoofing    #
# audit toolbox by Ghede, it can be      #
# used freely for auditing purposes.     #
# No warranty whatsoever is given about  #
# this software, use at your own risk.   #
#                                        #
##########################################
use Socket;
use English;
use Net::RawIP;
$version="0.1.2";
if ($uid!=0)
{
  print "I'm a verry dangerous tool and need to run as root.\n";
  print "And NO, There is no proof I'm actualy save, so do so at your own risk\n";
  print "Don't keep me running for to long\n";
  exit;
}
$port=8989;
$proto = getprotobyname('tcp');
socket(Server, PF_INET, SOCK_STREAM, $proto)  || die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR, pack("l", 1))|| die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_ANY))        || die "bind: $!";
listen(Server,SOMAXCONN)                            || die "listen: $!";
print "Spoofrules Audit server waiting for connection\n";
while ($paddr = accept(Client,Server))
{
   my($port,$iaddr) = sockaddr_in($paddr);
   @ip=unpack('C4',$iaddr);
   $clientip=$ip[0].".".$ip[1].".".$ip[2].".".$ip[3];
   print "Forking handler for $clientip\n";
   $pid = fork;
   if ($pid == 0)
   {
      select(Client);
      $|=1;
      select(STDOUT);
      print Client "SAS $version\n";
      $line=<Client>;
      if ($line =~ /PASV/i)
      {
        $udp=getprotobyname('udp');
	unless (socket(UDPH, PF_INET, SOCK_DGRAM, $udp))
        {
           print Client "502 Unable to create udp socket\n";
	   close(Client);
	   exit;
        }  
        unless (setsockopt(UDPH, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)))
        {
           print Client "503 Unable to set reuse option on socket\n";
	   close(Client);
	   exit;         
        }
        $port=1200;
        while (($port < 2000)&&
                (!bind(UDPH, sockaddr_in($port, INADDR_ANY)))) 
        {
          print "Couldn't bind to $port triing next one\n";
          $port++;
        }
        if ($port >= 2000) 
        {
           print Client "504 Unable to bind to ussable udp port\n";
	   close(Client);
	   exit;         
        }
        alarm(8);
        print Client "200 $port UDP waiting (16 seconds)\n";
        while (1)
        {
          $sender=recv(UDPH,$data,4,0);
          if ($sender && $data)
          {
            $id=unpack("N",$data);
	    ($rport, $raddr) = sockaddr_in($sender);
	    $peer_addr = inet_ntoa($raddr); 
            print Client "204 $id $peer_addr $rport OK\n";
          }
        }
      }
      elsif ($line =~ /ACTV/i)
      {
        $raw = new Net::RawIP;
        $uraw = new Net::RawIP({udp =>{}});
        print Client "202 Please send spoof commands\n";
        while (<Client>)
        {
          if (/^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)/)
          {
             $ips=$1; $psp=$2; $id=$3;
             print Client "203 OK, sending spoofed UDP packet Source IP=$ips to Dest IP $clientip PRT $psp (ID=$id)\n";
             $sourceip=unpack("N",inet_aton($ips));
             $destip=unpack("N",inet_aton($clientip));
             if (($sourceip==0)||($destip==0)||($psp==0))
             {
               print Client "402 Invalid parameters\n";
               close(Client);
	       exit;
             }
             $idp=pack("N",$id);
             #Try different ranges in order to bypass potential filters
             #remember we're testing anti spoofing and not any firewalling
             #rules that may be pressent.
             foreach $sport (53,530,1080,5300)
             {
               $uraw->set({ip => {saddr => $sourceip ,daddr => $destip},
		         udp => {source => $sport,
			 dest => $psp,
			 data => $idp}});
               foreach $try (1 .. 4)
               { 
                 $uraw->send;
               }
             }
          }
          else
          {
             print Client "401 Unknown command \"$_\"\n";
             close(Client);
             exit;
          }
        }
      }
      else
      {
        print Client "Unknown command\n";
      }
      exit;
   }
} 
                 
