NAME

CRAPPS - Cisco Router Action Performing Perl Script
Author:  Michael J. Vincent


DESCRIPTION

Script will interface with Cisco router via SNMP, Telnet or SSH supporting
regular login or username, and perform actions. SNMP supports a get
config, put config and a save config ("wr mem" for IOS). SNMP mode also
supports get and clear VTY line function and a get interface list and
monitor interface utilization function, including CPU, memory and proxy
ping.

Telnet and SSH mode supports the issuing of commands from a file. The only
default command issued in is "terminal length 0" for IOS or
"set length 0" for CatOS. Therefore, show commands can be in the
commands file along with config commands (on IOS, as long as preceded by
a "config term" and followed by an "end" and "wr mem" if save is
desired). Also supports log file of session transcript.

Password decrypt and encrypt mode is provided for Cisco passwords. Type
7 (not "enable secret") are decrypted or encrypted to all possible
combinations. Type 5 ("enable secret") are encrypted or cracked by
dictionary brute force.

Default execution with no options provides simple Ping.


DEPENDENCIES
 
  The following will most likely be standard with a Perl install:

    strict
    warnings
    Getopt::Long
    Pod::Usage
    Sys::Hostname
    IO::Socket           (requires version >1.94 for IPv6 support)
    Net::Ping
    Digest::MD5        ? (required by Crypt::PasswdMD5)
    Term::ReadKey      ? (required for password masking)

  The following will probably require extra download:

    Net::SNMP            (required by Cisco::SNMP)
    Cisco::SNMP        *
    Net::Telnet        # (required by Net::Telnet::Cisco)
    Net::Telnet::Cisco
    Net::SSH2          ?# (required by Net::SSH2::Cisco)
    Net::SSH2::Cisco   ?*
    Crypt::PasswdMD5   ? (required for MD5 -P modes)

    ? Modules for optional features
    + Not core modules - these are required by other modules.
    # Not core modules, but supplied with Strawberry in vendor/lib

  All above Perl modules are NOT written or maintained by Michael 
  Vincent (except *).  For info on the required Perl modules, see 
  http://CPAN.org.


USAGE

The following steps are geared toward a Windows installation of 
Perl and the use of CRAPPS on Windows.  However, CRAPPS is written 
in Perl and thus is platform independent.  You can run it on any OS 
that supports Perl and has the required modules.  It has been tested 
successfully on Windows (2K, XP, 2K3, 7) 32-bit and 64-bit with 
Strawberry versions 5.14 to 5.20 32-bit and 64-bit, Linux (various 
flavors) and Mac OSX.

  1)  Install Perl
  2)  Install Perl Modules (if required)
  3)  Test CRAPPS.PL
  4)  Additional Uses


1)  Install Perl

You'll need Perl.  If you already have it, skip to step 2.

Some options for Perl on Windows are:

    Strawberry
    Activestate

Grab the latest version.  Install with all the default options.  Once 
installed, you may find it useful to add the ".PL" extension to your 
PATHEXT environment variable so you can run the Perl scripts that 
you'll no doubt write simply by typing their name rather than prefacing 
them with the "perl" command.

This can be done by (example on Windows):

  1)  Control Panel --> System --> "Advanced" tab --> 
      "Environment Variables" button.

  2)  In the "System variables" section, locate the "PATHEXT" variable.

  3)  Press "Edit" button.

  4)  In the "Variable value:" text box that pops up, go to the end and 
      add the text ";.PL" without the double quotes.  (That's semicolon
      period capital P capital L.)

  5)  Press the "OK" button.

  6)  Press the "OK" button ("Environment Variables" window).

  7)  Press the "OK" button ("System Properties" window).

  8)  Close any open cmd.exe windows and open a new one.

  9)  Check your work by Start -> Run "cmd.exe".  Type the command:

           set | find "PATHEXT"

      output should be something like:

        {C} > set | find "PATHEXT"
        PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.PL

      Note the ;.PL added at the end.


2)  Install Perl Modules

Next, you'll need the modules detailed in the above DEPENDENCIES 
section.  If you already have them installed, skip to step 3.

If you are behind a proxy to access the Internet, you'll need to add an 
environment variable (similar to editing the PATHEXT environment 
variable in Step 1 above) called "http_proxy" (without the double 
quotes) and the value should be your proxy server.  For example:

      http://myproxy.mycompany.com:8080

a) If you're using Strawberry, use the 'cpan' client once you can 
access the Internet.  You can simply install the required modules by:

      cpan <module>

For CRAPPS, you will (most likely only - in addition to the default 
Perl install) need:

      cpan Net-Telnet
      cpan Net-Telnet-Cisco
      cpan Net-SNMP
      cpan Cisco-SNMP

For optional features and full functionality, you will also need:

      cpan Crypt-PasswdMD5
      cpan Net::SSH2::Cisco
      cpan Crypt::PasswdMD5

b) You can also download each module directly from CPAN 
(http://search.cpan.org) and follow the installation procedures 
included with each modules.  Usually:

      perl Makefile.PL
      make
      make test
      make install

      NOTE:  'make' should be 'dmake' on Windows Strawberry Perl

3)  Test CRAPPS.PL

Once you've done ALL the above, you can run the CRAPPS.PL script simply 
by typing:

  crapps

at the cmd.exe prompt.

If you get something like:

  {C} > crapps
  Can't locate Net/Telnet/Cisco.pm in @INC (@INC contains: C:/Perl/lib 
  C:/Perl/site/lib .) at C:\crapps.pl line 41.
  BEGIN failed--compilation aborted at C:\crapps.pl line 41.

You have a problem.  In the above example, Perl can't find the 
Net::Telnet::Cisco module.  Are you sure you installed the modules 
correctly in step 2 above?

If you get the following output, you're good to go!

  {C} > crapps
  C:\usr\bin\crapps.pl: host required

  Usage:
       crapps [options] [SNMP options] | [Telnet options] host ...
       crapps -P encrypt
       crapps -S svc

To get the 411, use:

  {C} > crapps --man


4)  Additional Uses

Once you start using CRAPPS.PL to automate some tasks to Cisco routers/
switches, you'll start to realize that running it several times with 
some "feedback" and parsing of output can lead to automation of more 
complicated tasks.  To illustrate this, I've created some Batch file 
"wrappers" that call CRAPPS.PL in various configurations with various 
input commands to complete complex tasks.

  getcall.bat    Acts like a call tracing application to find the 
                 port on a Cisco CMM blade that a Cisco VoIP phone 
                 is using when accessing the PSTN.  This narrows 
                 the call down to the specific channel on the T1.  
                 We use this script at my current client when doing 
                 testing to/from the PSTN.  We can fail PSTN trunks 
                 and verify which new T1 the calls are routed over 
                 in the failure scenario.  This script eliminates 
                 the need to have Telnet sessions open to each of 
                 the 4 CMM blades and having to issue two commands 
                 to each and parse through the returned information 
                 looking for the test phone I'm testing with.

  getuser.bat    You have an IP address - where is it on the network?  
                 You traceroute, then telnet to the router.  You do 
                 an ARP lookup, you do a CAM lookup based on the 
                 IP to MAC mapping.  You've found the trunk port to 
                 The access switch.  You convert the MAC address 
                 from IOS format to CatOS format.  Now you telnet to 
                 the access switch and do the final CAM lookup to 
                 get the final port and MAC address where the IP 
                 device is.  Alternatively, you run this script and 
                 it does it all for you!

Not included is a batch file that I wrote to use CRAPPS.PL to backup 
all IOS and CatOS devices in the network via TFTP, save them in a 
folder by date, rotate the folders to keep 10 versions of back configs, 
run the batch file as a Scheduled Task every other night (to maintain 
20 days worth of back configs) and use two simple files - 1 for IOS and 
1 for CatOS - that contain the names/IP's of the devices to backup for 
easy editing by those who are Perl/Batch disabled.
