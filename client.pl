#!/usr/bin/perl
#
##########################################
#     Spoofingrules Auditing Client      #
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
sub timeout {
  foreach $count (1 .. 6)
  {
     $ip=$RESULT{$count};
     if ($count < 4 ) {$spoofer="Client";}
     else {$spoofer="Server";}
     if ($ip)
     {
       print "$spoofer was able to spoof $ip\n";
     }
  }
  print "\n\nResults for the clients network:\n";
  if ($RESULT{6}) 
  {
         print "* The server was able to spoof clientnet adresses to the client, \n";
         print "  this means that the clients border router has no incomming\n"; 
         print "  spoofing filters\n";
  }
  elsif (! $RESULT{4})
  {
         print "* The test for incomming spoofing filters could not be done,\n";
         print "  the servers network has outgoing spoofing filters that\n"; 
         print "  prohibit this test\n";
  }
  if ($RESULT{1}) 
  {
         print "* The client was able to spoof 3th party adresses to the server,\n"; 
         print "  this means that the clients border router has no outgoing\n"; 
         print "  spoofing filters\n";
  }
  elsif ($RESULT{2}) 
  {
         print "* The client was able to spoof client network adresses to the server,\n"; 
         print "  this means that the clients terminal server have no internal \n";
         print "  spoofing filters\n";
  }
  print "\nResults for the server network:\n";
  if ($RESULT{3}) 
  {
         print "* The client was able to spoof servernet adresses to the server, \n";
         print "  this means that the server border router has no incomming\n"; 
         print "  spoofing filters`\n";
  }
  elsif (! $RESULT{1})
  {
         print "* The test for incomming spoofing filters could not be done,\n";
         print "  the client network has outgoing spoofing filters that\n"; 
         print "  prohibit this test\n";
  }
  if ($RESULT{4}) 
  {
         print "* The server was able to spoof 3th party adresses to the client,\n"; 
         print "  this means that the server border router has no outgoing\n"; 
         print "  spoofing filters\n";
  }
  elsif ($RESULT{5}) 
  {
         print "* The server was able to spoof client network adresses to the client,\n"; 
         print "  this means that the servernet terminal server have no internal \n";
         print "  spoofing filters\n";
  }
  print "\n";
  exit;
}
$version="0.1.3";
if ($uid!=0)
{
  print "I'm a verry dangerous alpha version of a tool and need to run as root.\n";
  print "And NO, There is no proof I'm actualy save, so do so at your own risk\n";
  exit;
}
$server=$ARGV[0];
$localspoof=$ARGV[1];
$remotespoof=$ARGV[2];
unless($remotespoof)
{
  print "Usage: ./client.pl <server IP> <localnet spoof IP> <servernet spoof IP>\n";  
  exit;
}
print "Spoofingrules Auditing Client $version\n";
print " This will take aprox 16 seconds\n\n";
$port=8989;
$proto = getprotobyname('tcp');
socket(Client, PF_INET, SOCK_STREAM, $proto)  || die "socket: $!";
setsockopt(Client, SOL_SOCKET, SO_REUSEADDR, pack("l", 1))|| die "setsockopt: $!";
bind(Client, sockaddr_in(0, INADDR_ANY))        || die "bind: $!";
($name,$aliases,$type,$len,$thataddr)=gethostbyname($server);
connect(Client,sockaddr_in($port, $thataddr)) || die "Connect: $!";
select(Client);$|=1;select(STDOUT);
$line=<Client>;
unless($line =~ /^SAS\s/) {print "Invalid server reply"; exit;}
print Client "PASV\n";
$line=<Client>;
unless($line =~ /^200\s+(\d+)\s+/) {print "Invalid server reply"; exit;}
$serverudp=$1;
$raw = new Net::RawIP;
$uraw = new Net::RawIP({udp =>{}});
$id=0;
foreach $ip ("198.41.0.4",$localspoof,$remotespoof)
{
  $id++;
  $idp=pack("N",$id);   
  foreach $sport (53,530,1080,5300) 
  {
    $uraw->set({ip => {saddr => $ip ,daddr => $server},
		       udp => {source => $sport,
                       dest => $serverudp,
		       data => $idp}});
    #udp is unreliable, so lets send four to be sure.
    foreach $try (1 .. 4) 
    {
      $uraw->send;
    }
  }
}
while (<Client>)
{
  if (/204\s+(\d)\s+(\d+\.\d+\.\d+\.\d+)\s+/)
  {
    $code=$1;
    $ip=$2;
    $RESULT{$code}=$ip;
  }
}
close(Client);

$port=8989;
$proto = getprotobyname('tcp');
socket(Client, PF_INET, SOCK_STREAM, $proto)  || die "socket: $!";
setsockopt(Client, SOL_SOCKET, SO_REUSEADDR, pack("l", 1))|| die "setsockopt: $!";
bind(Client, sockaddr_in(0, INADDR_ANY))        || die "bind: $!";
($name,$aliases,$type,$len,$thataddr)=gethostbyname($server);
connect(Client,sockaddr_in($port, $thataddr)) || die "Connect: $!";
select(Client);$|=1;select(STDOUT);
$line=<Client>;
unless($line =~ /^SAS\s/) {print "Invalid server reply"; exit;}
print Client "ACTV\n";
$line=<Client>;
unless($line =~ /^202/) {print "Invalid server reply"; exit;}
$udp=getprotobyname('udp');
unless (socket(UDPH, PF_INET, SOCK_DGRAM, $udp))
{ 
   print "Unable to create udp socket\n";
   exit;
}
unless (setsockopt(UDPH, SOL_SOCKET, SO_REUSEADDR, pack("l", 1))) 
{
  print "Unable to set reuse option on socket\n";
  exit;
}
$port=2200;
while (($port < 3000)&&
        (!bind(UDPH, sockaddr_in($port, INADDR_ANY)))) {$port++;} 
if ($port >= 3000)
{
  print "Unable to bind to ussable udp port\n";
  exit;
}
$commands="";
foreach $ip ("198.41.0.4",$remotespoof,$localspoof)
{
  $id++;
  $commands .= "$ip $port $id\n";
}
$SIG{'ALRM'}='timeout';
alarm(8);
print Client "$commands";
# Need to make a decent timeout handler here!!\n";
while (1)
{
  $sender=recv(UDPH,$data,4,0);
  if ($sender && $data)
  {
    $id=unpack("N",$data); 
    ($rport, $raddr) = sockaddr_in($sender);
    $peer_addr = inet_ntoa($raddr);
    $RESULT{$id}=$peer_addr;
  }
}
