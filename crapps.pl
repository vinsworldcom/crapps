#!/usr/bin/perl

##################################################
# AUTHOR = Michael Vincent
# www.VinsWorld.com
##################################################

use vars qw($VERSION);

$VERSION = "3.02 - 09 JUL 2015";

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case); #bundling
use Pod::Usage;

##################################################
# Start Additional USE
##################################################
use Sys::Hostname;
use Socket qw(inet_ntoa AF_INET IPPROTO_TCP);

my $AF_INET6 = eval { Socket::AF_INET6() };
my $AF_UNSPEC = eval { Socket::AF_UNSPEC() };
my $AI_NUMERICHOST = eval { Socket::AI_NUMERICHOST() };
my $NI_NUMERICHOST = eval { Socket::NI_NUMERICHOST() };

use Cisco::SNMP::Config 1.01;
use Cisco::SNMP::CPU 1.01;
use Cisco::SNMP::Entity 1.01;
use Cisco::SNMP::Interface 1.01;
use Cisco::SNMP::IP 1.01;
use Cisco::SNMP::Line 1.01;
use Cisco::SNMP::Memory 1.01;
use Cisco::SNMP::Password 1.01;
use Cisco::SNMP::ProxyPing 1.01;
use Cisco::SNMP::System 1.01;
use Net::Ping 2.31;
use Net::Telnet::Cisco 1.10;
my $HAVE_Net_SSH2_Cisco = 0;
eval "use Net::SSH2::Cisco";
if(!$@) {
    $HAVE_Net_SSH2_Cisco = 1
}
my $HAVE_IO_Socket_IP = 0;
eval "use IO::Socket::IP -register";
if(!$@) {
    $HAVE_IO_Socket_IP = 1
} else {
    eval "use IO::Socket::INET"
}
my $HAVE_Crypt_PasswdMD5 = 0;
eval "use Crypt::PasswdMD5";
if(!$@) {
    $HAVE_Crypt_PasswdMD5 = 1
}
my $HAVE_Term_ReadKey = 0;
eval "use Term::ReadKey";
if(!$@) {
    $HAVE_Term_ReadKey = 1
}
##################################################
# End Additional USE
##################################################

my @commands;
my $FAILED       = "FAILED!";
my $SUCCESS      = "SUCCESS!";
my $CMD_FILE_EXT = ".confg";
my $UNIQUE       = 0;
my $FORMAT       = "%-19s > ";
# REGEX to match lines in a Cisco config that contain passwords
my $PASSWORD5 = qr/ secret 5 \$1/;
my $PASSWORD7 = qr/( password 7 )|(-server key 7 )|( key-string 7 )/;
my $PROMPT    = '/(?m:^(?:[\w.\/]+\:)?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$#>]\s?(?:\(enable\))?\s*$)/';

my %opt;
my ($opt_help, $opt_man, $opt_versions);

GetOptions(
  '4!'                     => sub { $opt{family} = AF_INET},
  '6!'                     => sub { $opt{family} = $AF_INET6},
  'beep+'                  => \$opt{beep},
  'c|command=s'            => \$opt{command},
  'C|catos!'               => \$opt{Catos},
  'directory|dictionary=s' => \$opt{dir},
  'encrypt|enable:s'       => \$opt{enable},
  'f|force!'               => \$opt{force},
  'F|format=s'             => \$opt{format},
  'h|header!'              => \$opt{header},
  'i|interface:s'          => \$opt{interface},
  'I|inventory+'           => \$opt{inventory},
  'lines:s'                => \$opt{lines},
  'm|metric|message|mib=s' => \$opt{metric},
  'password:s'             => \$opt{pass},
  'Password=s'             => \$opt{Pass},
  'r|repeat=i'             => \$opt{repeat},
  'R|replay=i'             => \$opt{replay},
  'snmp|salt=s'            => \$opt{snmp},
  'S|ssh!'                 => \$opt{ssh},
  't|tftp:s'               => \$opt{tftp},
  'T|terminal+'            => \$opt{term},
  'username=s'             => \$opt{user},
  'w|write+'               => \$opt{write},
  'W|wait=i'               => \$opt{Wait},
  'help!'                  => \$opt_help,
  'man!'                   => \$opt_man,
  'versions!'              => \$opt_versions
) or pod2usage(-verbose => 0);

if (defined $opt_help) {
    pod2usage(-verbose => 99, -sections => "OPTIONS/PASSWORD MODE") if defined $opt{Pass};
    pod2usage(-verbose => 99, -sections => "OPTIONS/SNMP MODE") if defined $opt{snmp};
    pod2usage(-verbose => 99, -sections => "OPTIONS/TELNET SSH MODE") if (defined $opt{user} or defined $opt{pass})
}

pod2usage(-verbose => 1) if defined $opt_help;
pod2usage(-verbose => 2) if defined $opt_man;

if (defined $opt_versions) {
    print
      "\nModules, Perl, OS, Program info:\n",
      "  $0\n",
      "  Version               $VERSION\n",
      "    strict              $strict::VERSION\n",
      "    warnings            $warnings::VERSION\n",
      "    Getopt::Long        $Getopt::Long::VERSION\n",
      "    Pod::Usage          $Pod::Usage::VERSION\n",
##################################################
# Start Additional USE
##################################################
      "    Sys::Hostname       $Sys::Hostname::VERSION\n",
      "    Socket              $Socket::VERSION\n",
      "    Cisco::SNMP         $Cisco::SNMP::VERSION\n",
      "    Net::Ping           $Net::Ping::VERSION\n",
      "    Net::Telnet::Cisco  $Net::Telnet::Cisco::VERSION\n";
if ($HAVE_Net_SSH2_Cisco) {
    print
      "    Net::SSH2::Cisco    $Net::SSH2::Cisco::VERSION\n"
} else {
    print
      "    Net::SSH2::Cisco    [NOT INSTALLED]\n"
}
if ($HAVE_Crypt_PasswdMD5) {
    print
      "    Crypt::PasswdMD5    $Crypt::PasswdMD5::VERSION\n"
} else {
    print
      "    Crypt::PasswdMD5    [NOT INSTALLED]\n"
}
if ($HAVE_Term_ReadKey) {
    print
      "    Term::ReadKey       $Term::ReadKey::VERSION\n"
} else {
    print
      "    Term::ReadKey       [NOT INSTALLED]\n"
}
##################################################
# End Additional USE
##################################################
    print
      "    Perl version        $]\n",
      "    Perl executable     $^X\n",
      "    OS                  $^O\n",
      "\n\n";
    exit
}

##################################################
# Start Program
##################################################

$opt{beep} = $opt{beep} || 0;
if (!defined $opt{header}) {
    $opt{header} = 1
}

# Password mode
if (defined $opt{Pass}) {
    if ((my $ret = PASSWORD_Mode()) eq $FAILED) {
        print "$0: Password MODE Error! -> $ret\n"
    } 
    print "\a" if ($opt{beep} >= 1);
    exit 0
}

if (!$HAVE_IO_Socket_IP and defined $opt{family} and ($opt{family} == $AF_INET6)) {
    print "IO::Socket::IP required for IPv6 (-6)\n";
    exit 1
}
if (!$HAVE_Net_SSH2_Cisco and defined $opt{ssh}) {
    print "Net::SSH2::Cisco required for SSH (-S)\n";
    exit 1
}

# Default to IPv4 for backward compatiblity
# THIS MAY CHANGE IN THE FUTURE!!!
if (!defined $opt{family}) {
    $opt{family} = AF_INET
}

# -d directory
if (defined $opt{dir}) {
    # replace \ with / for compatibility with UNIX/Windows
    $opt{dir} =~ s/\\/\//g;
    # remove trailing / so we're sure it does NOT exist and we CAN put it in later
    $opt{dir} =~ s/\/$//
}

# Make sure at least one host provided
if (!@ARGV) {
    pod2usage(-verbose => 0, -message => "$0: host required\n")
}

# Don't allow TELNET and SNMP options together
# v3 UPDATE:  Need --username / --password for SNMPv3
#if (($opt{user} || $opt{pass} || $opt{enable}) && ($opt{snmp} || $opt{tftp} || $opt{lines} || $opt{interface} || $opt{inventory} || $opt{metric})) {
#    print "$0: SNMP and TELNET options mutually exclusive\n";
#    exit 1
#}

$opt{repeat} = Rr($opt{repeat});
$opt{replay} = Rr($opt{replay});

    sub Rr {
        my $opt = shift;
        if (defined $opt) {
            if ($opt < 0) {
                print "$0: -r or -R must be integer >= 0\n";
                exit 1
            } elsif ($opt == 0) {
                return -1
            } else {
                return $opt
            }
        } else {
            return 1
        }
    }

$opt{Catos} = $opt{Catos} || 0;
$opt{write} = $opt{write} || 0;
$opt{Wait}  = $opt{Wait}  || 0;
if (defined $opt{format}) {
    # Format needs some form of printf % format to accommodate $host
    if (($opt{format} eq "") || ($opt{format} !~ /%/)) {
        # %.0s = no size (sink variable, don't display)
        $FORMAT = "%.0s" . $opt{format}
    } else {
        $FORMAT = $opt{format}
    }
}

# -c file or directory
if (defined $opt{command}) {
    # replace \ with / for compatibility with UNIX/Windows
    $opt{command} =~ s/\\/\//g;
    # Trailing / = directory of unique files
    $UNIQUE = 1 if ($opt{command} =~ /\/$/)
}

# -s SNMP mode
if (defined $opt{snmp}) {
    getSNMPOpts()
# -p Telnet mode
} elsif (defined $opt{pass}) {
    getTelnetOpts()
}

my @hosts = getHosts();

##################################################
# START LOOPING ON HOSTS #
##########################
my $run = 1;
for my $host (0..$#hosts) {

    # clear response variable to be used for subroutine returns
    my $response = "";

    ########
    # SNMP #
    ########
    if (defined $opt{snmp}) {
        if (defined $opt{tftp}) {
            # SNMP TFTP PUT
            if (defined $opt{command}) {
                my $u_file = "";
                # Unique file per device or 1 file for all
                if ($UNIQUE) {
                    $u_file = $opt{command} . $hosts[$host]->{host} . $CMD_FILE_EXT
                } else {
                    $u_file = $opt{command}
                }
                $response = SNMP_Config($hosts[$host], $u_file)

            # SNMP TFTP GET
            } else {
                my $output_file = "";
                if (defined $opt{dir}) {
                    $output_file = $opt{dir} . "/" . $hosts[$host]->{host} . $CMD_FILE_EXT
                } else {
                    $output_file = $hosts[$host]->{host} . $CMD_FILE_EXT
                }
                $response = SNMP_Config($hosts[$host], $output_file)
            }
        }

        # SNMP WR MEM
        # if config failed, skip write.
        if ($opt{write} && ($response =~ $FAILED)) {
            printf "$0: Skipping SNMP 'wr mem' > %s\n", $hosts[$host]->{host};
            next
        } else {
            if ($opt{write} && !(defined $opt{interface} || defined $opt{inventory} || defined $opt{lines})) {
                $response = SNMP_Config($hosts[$host], undef, 1);
                next
            }
        }

        # SNMP Line Ops
        if (defined $opt{lines}) {
            # Send message
            if (defined $opt{metric}) {
                $response = SNMP_LineMessage($hosts[$host])
            # Line query or clear
            } else {
                # Lone flag = query
                if ($opt{lines} eq "") {
                    $response = SNMP_LineInfo($hosts[$host])
                # has args = determine lines and clear
                } else {
                    $response = SNMP_LineClear($hosts[$host])
                }
            }
            next
        }

        # SNMP Interface
        if (defined $opt{interface}) {

            # Lone flag = query
            if ($opt{interface} eq "") {
                # logging?
                my $log = "";
                if ($opt{write}) {
                    $log = get_log_file($hosts[$host]->{host}, $opt{dir}, "if" . $opt{interface})
                }
                $response = SNMP_IntfInfo($hosts[$host], $log);

            # has args = determine what to do
            } else {
                # If Wait is <0 we need to adjust to minimum sample window (1)
                $opt{Wait} = 1 if ($opt{Wait} < 1);

                # admin up/down
                if (defined $opt{command} && ((uc($opt{command}) eq "UP") || (uc($opt{command}) eq "DOWN"))) {
                    $response = SNMP_IntfUpDown($hosts[$host])
                } else {
                    # logging?
                    my $log = "";
                    if ($opt{write} && ($opt{interface} =~ /^[0-9]+$/)) {
                        $log = get_log_file($hosts[$host]->{host}, $opt{dir}, "if" . $opt{interface})
                    }
                    if ($opt{interface} eq "0") {
                        $response = SNMP_CPUUtil($hosts[$host], $log)
                    } elsif ($opt{interface} eq "00") {
                        $response = SNMP_MemUtil($hosts[$host], $log)
                    } elsif ($opt{interface} =~ /^\d+$/) {
                        $response = SNMP_IntfUtil($hosts[$host], $log)
                    } else {
                        $response = SNMP_ProxyPing($hosts[$host])
                    }
                }
            }
            next
        }

        # SNMP Inventory
        if (defined $opt{inventory}) {
            my $log = "";
            if ($opt{write}) {
                $log = get_log_file($hosts[$host]->{host}, $opt{dir}, "inventory")
            }
            $response = SNMP_Inventory($hosts[$host], $log);
            next
        }

        # SNMP Info
        if (!defined $opt{tftp}) {
            $response = SNMP_GetInfo($hosts[$host])
        }

    ##########
    # Telnet #
    ##########
    } elsif (defined $opt{pass}) {

        if ($UNIQUE) {
            # Deferred -c file read until now.  Read each file in -c (path) + $hosts[$host] + .confg
            my $u_file = $opt{command} . $hosts[$host]->{host} . $CMD_FILE_EXT;
            printf $FORMAT . "Reading file: $u_file ", $hosts[$host]->{host};
            if (-e $u_file) {
                open(my $CMDFILE, '<', $u_file);
                @commands = <$CMDFILE>;
                close($CMDFILE);
                print "$SUCCESS\n"
            } else {
                print "$FAILED\n";
                next
            }
        }

        # no commands = interactive
        # send all hosts at once - let TELNET_Mode loop
        # exit on return
        if (!defined $opt{command}) {
            $response = TELNET_Mode(\@hosts, \@commands);
            last
        # one by one, but TELNET_Mode expects host as an array due to previous comment
        } else {
            my @th;
            push @th, $hosts[$host];
            $response = TELNET_Mode(\@th, \@commands)
        }

    ########
    # Ping #
    ########
    } else {
        if ($hosts[$host]->{family} == $AF_INET6) {
            print "Net::Ping does not support IPv6\n";
            next
        }
        $response = PING_Mode($hosts[$host])
    }

} continue {
    print "\n";
    print "\a" if ($opt{beep} > 1);

    # wait between host if provided
    sleep $opt{Wait} unless ($run++ == @hosts)
}

print "\a" if ($opt{beep} == 1);
exit 0;

##################################################
# End Program
##################################################

##################################################
# Begin Subroutines
##################################################
sub getSNMPOpts {
    # CATOS and WRITE not allowed for SNMP mode
    if (($opt{Catos}) && ($opt{write})) {
        print "$0: WR MEM not allowed with CatOS in SNMP mode\n";
        exit 1
    }

    # TFTP: keep or assign localhost
    if (defined $opt{tftp}) {
        if ($opt{tftp} eq "") {
            $opt{tftp} = hostname
        }            
        if (defined(my $r = Cisco::SNMP::_resolv($opt{tftp}, $opt{family}))) {
            $opt{tftp} = $r
        } else {
            print Cisco::SNMP->error . "\n";
            exit 1
        }
        # startup-config / running-config
        if (defined $opt{metric}) {
            if (($opt{metric} !~ /^start(?:up)?(?:-config)?$/i) && ($opt{metric} !~ /^run(?:ning)?(?:-config)?$/i)) {
                print "$0: Unknown file - $opt{metric}\n";
                exit 1
            }
        } else {
            $opt{metric} = 'running-config'
        }
    }

    # Interface Info
    if (defined $opt{interface} && ($opt{interface} ne "")) {
        # Admin up/down
        if (defined $opt{command}) {
            if ((uc($opt{command}) eq "UP") || (uc($opt{command}) eq "DOWN")) {
                # DO NOTHING (Admin up/down)
            # Ping packet size for proxy ping
            } elsif ($opt{command} =~ /^\d+$/) {
                if (defined(my $r = Cisco::SNMP::_resolv($opt{interface}, $opt{family}))) {
                    $opt{interface} = $r
                } else {
                    print Cisco::SNMP->error . "\n";
                    exit 1
                }
            } else {
                print "$0: not valid command - $opt{command}\n";
                exit 1
            }
        # or IP address for proxy ping
        } elsif ($opt{interface} !~ /^\d+$/) {
            if (defined(my $r = Cisco::SNMP::_resolv($opt{interface}, $opt{family}))) {
                $opt{interface} = $r
            } else {
                print Cisco::SNMP->error . "\n";
                exit 1
            }
        }
        # fall through
    }

    # default: system MIB
    if (($opt{write} == 0) && !(defined $opt{tftp} || defined $opt{lines} || defined $opt{interface} || defined $opt{inventory})) {
        $opt{metric} = read_mib_file()
    }
}

##################################################
sub getTelnetOpts {
    if ($opt{pass} eq "") {
        print "Password: ";
        $opt{pass} = GetPass()
    }

    if (defined $opt{enable}) {
        if ($opt{enable} eq "") {
            print "Enable Password: ";
            $opt{enable} = GetPass()
        }
    }

    sub GetPass {
        # No echo password
        if ($HAVE_Term_ReadKey) { ReadMode(2) }
        chomp(my $opt = <STDIN>);
        if ($HAVE_Term_ReadKey) { ReadMode(0) }
        print "\n";
        return $opt
    }

    # Telnet requires command file read to the @commands array.
    # We can only read command file now if it isn't unique per device.
    if (!$UNIQUE) {
        # -c not provided - interactive mode
        if (!defined $opt{command}) {
            $commands[0] = "--STDIN--"
        # -c file
        } elsif (-e $opt{command}) {
            open(my $CMDFILE, '<', $opt{command});
            @commands = <$CMDFILE>;
            close($CMDFILE)
        # -c command
        } else {
            $commands[0] = $opt{command}
        }
    }
}

##################################################
sub getHosts {
    for my $host (@ARGV) {

        # try to open as file first
        if (-e $host) {
            open(my $IN, '<', $host);
            my @tHosts;
            while (<$IN>) {
                # skip blank lines and #comments
                next if (($_ =~ /^[\n\r]+$/) || ($_ =~ /^#/));
                chomp $_;
                # only get first 'arg' on each line (hostnames can't contain whitespace)
                my ($h) = split /\s+/, $_;
                # lookup host and skip if not found
                if (defined(my $ret = Cisco::SNMP::_resolv($h, $opt{family}))) {
                    push @tHosts, $ret
                } else {
                    print Cisco::SNMP->error . "\n";
                    next
                }
            }
            # clean up - add temp hosts to final host array
            close($IN);
            push @hosts, @tHosts
        # not a file, push hostname to array
        } else {
            # lookup host and skip if not found
            if (defined(my $ret = Cisco::SNMP::_resolv($host, $opt{family}))) {
                push @hosts, $ret
            } else {
                print Cisco::SNMP->error . "\n";
                next
            }
        }
    }
    return @hosts
}

##################################################
sub read_mib_file {

# (for /f %i in ('awk "/^[A-Za-z]/ {print $1}" \usr\share\snmp\mibs\*') 
#  do @eecho -n "%i " && snmptranslate -mALL -IR -On %i) 2>&1 | 
#  grep -v Unknown >> out.txt

    my %MIB;

    if (!defined $opt{force}) {
        %MIB = (
            '1.3.6.1.2.1.1'     => "System MIB",
            '1.3.6.1.2.1.1.1.0' => "sysDescr",
            '1.3.6.1.2.1.1.2.0' => "sysObjectID",
            '1.3.6.1.2.1.1.3.0' => "sysUpTimeInstance",
            '1.3.6.1.2.1.1.4.0' => "sysContact",
            '1.3.6.1.2.1.1.5.0' => "sysName",
            '1.3.6.1.2.1.1.6.0' => "sysLocation",
            '1.3.6.1.2.1.1.7.0' => "sysServices",
            '1.3.6.1.2.1.1.8.0' => "sysORLastChange",
            '1.3.6.1.6.3.1.1.4.1.0' => "snmpTrapOID"
        )
    }

    # MIB file
    if (defined $opt{metric}) {
        if (-e $opt{metric}) {
            open(my $IN, '<', $opt{metric});
            while (<$IN>) {
                # skip blank lines and comments (starting with #)
                next if (($_ =~ /^[\n\r]+$/) || ($_ =~ /^#/));
                chomp $_;
                my ($o, $m) = split /\t/, $_;
                $MIB{$o} = $m
            }
            close($IN)
        } else {
            print "$0: error reading MIB file - $opt{metric}\n"
        }
    }
    return \%MIB
}

##################################################
sub getCMSession {
    my ($t, $h) = @_;

    my %params = (
        hostname => $h->{addr},
        family   => $h->{family},
    );

    if ((defined $opt{user}) and (defined $opt{pass})) {
        $params{version} = 3;
        $params{username} = $opt{user};
        $params{authpassword} = $opt{pass};

        my ($auth, $priv) = split /,/, $opt{snmp};
        $params{authprotocol} = $auth;

        if (defined $opt{enable}) {
            $params{privpassword} = $opt{enable};
            if (defined $priv) {
                $params{privprotocol} = $priv
            } else {
                $params{privprotocol} = 'des'
            }
        }
    } else {
        $params{community} = $opt{snmp}
    }

    my $s = ('Cisco::SNMP::' . $t)->new(
        hostname  => $h->{addr},
        family    => $h->{family},
        %params
    );

    if (!defined $s) {
        printf $FORMAT . "$FAILED (" . Cisco::SNMP->error . ")", $h->{host};
        return
    }
    return $s
}

##################################################
sub SNMP_Config {

    my ($host, $file, $COPY) = @_;

    my $session;
    if (!defined($session = getCMSession('Config', $host))) {
        return
    }

    # wr mem
    if (defined $COPY) {
        printf $FORMAT . "%s/running-config > %s/startup-config ", $host->{host}, $host->{host}, $host->{host};
        if (defined(my $conf = $session->config_copy())) {
            print "$SUCCESS\n"
        } else {
            print "$FAILED (" . Cisco::SNMP->error . ")\n"
        }
    } else {
        # TFTP PUT (to device)
        if (defined $opt{command}) {
            printf $FORMAT . "tftp://%s/$file > %s/$opt{metric} ", $host->{host}, $opt{tftp}->{addr}, $host->{host};

            # CatOS
            if ($opt{Catos}) {
                if (defined(my $conf = $session->config_copy(
                               -tftp   => $opt{tftp}->{addr},
                               -source => $file,
                               -dest   => $opt{metric}
                               -catos  => 1
                           ))) {
                    print "$SUCCESS\n"
                } else {
                    print "$FAILED (" . Cisco::SNMP->error . ")\n"
                }

            # IOS
            } else {
                if (defined(my $conf = $session->config_copy(
                               -tftp   => $opt{tftp}->{addr},
                               -family => $opt{tftp}->{family},
                               -source => $file,
                               -dest   => $opt{metric}
                           ))) {
                    print "$SUCCESS\n"
                } else {
                    print "$FAILED (" . Cisco::SNMP->error . ")\n"
                }
            }

        # TFTP GET (from device)
        } else {
            printf $FORMAT . "%s/$opt{metric} > tftp://%s/$file ", $host->{host}, $host->{host}, $opt{tftp}->{addr};

            # CatOS
            if ($opt{Catos}) {
                if (defined(my $conf = $session->config_copy(
                               -tftp   => $opt{tftp}->{addr},
                               -source => $opt{metric},
                               -dest   => $file,
                               -catos  => 1
                           ))) {
                    print "$SUCCESS\n"
                } else {
                    print "$FAILED (" . Cisco::SNMP->error . ")\n"
                }

            # IOS
            } else {
                if (defined(my $conf = $session->config_copy(
                               -tftp   => $opt{tftp}->{addr},
                               -family => $opt{tftp}->{family},
                               -source => $opt{metric},
                               -dest   => $file
                           ))) {
                    print "$SUCCESS\n"
                } else {
                    print "$FAILED (" . Cisco::SNMP->error . ")\n"
                }
            }
        }
    }

    $session->close()
}

##################################################
sub SNMP_LineMessage {

    my ($host) = @_;

    my $session;
    if (!defined($session = getCMSession('Line', $host))) {
        return
    }

    my %params = (
        message => $opt{metric}
    );

    if ($opt{lines} ne '') { 
        $params{lines} = $opt{lines}
    }

    printf $FORMAT, $host->{host};
    if (defined(my $response = $session->line_message(%params))) {
        print "Messaged lines = @{$response} $SUCCESS\n"
    } else {
        print "$FAILED (" . Cisco::SNMP->error . ")\n"
    }

    $session->close()
}

##################################################
sub SNMP_LineInfo {

    my ($host) = @_;

    my $session;
    if (!defined($session = getCMSession('Line', $host))) {
        return
    }

    my $response = $session->line_numberof();
    printf $FORMAT . "(%3s) TYPE ACT  SECS SESS\n" .
           $FORMAT . "-------------------------\n", $host->{host}, (defined($response) ? $response : '#'), $host->{host} if ($opt{header});

    if (defined($response = $session->line_info())) {
        my $sessions = $session->line_sessions();
        for my $line (sort {$a <=> $b} (keys(%{$response}))) {
            printf $FORMAT . "%5i %-5s", $host->{host}, $line, $response->lineType($line);
            if ($response->lineActive($line) == 1) {
                print "Y "
            } else {
                print "N "
            }
            printf "%7i", $response->lineTimeActive($line);
            if ($response->lineActive($line) == 1) {
                for (0..$response->lineNses($line)-1) {
                    printf " [%.1s]%s://%s%s", 
                        $sessions->sessDirection($line, $_), 
                        $sessions->sessType($line, $_), 
                        ($response->lineUser($line) ne '') ? $response->lineUser($line) . '@' : '',
                        $sessions->sessAddress($line, $_)
                }
            }
            print "\n"
        }
    } else {
        printf $FORMAT . "$FAILED (" . Cisco::SNMP->error . ")\n", $host->{host}
    }

    $session->close()
}

##################################################
sub SNMP_LineClear {

    my ($host) = @_;

    my $session;
    if (!defined($session = getCMSession('Line', $host))) {
        return
    }

    printf $FORMAT, $host->{host};
    if (defined(my $response = $session->line_clear($opt{lines}))) {        
        print "Cleared lines = @{$response} $SUCCESS\n"
    } else {
        print "$FAILED (" . Cisco::SNMP->error . ")\n"
    }

    $session->close()
}

##################################################
sub SNMP_IntfInfo {

    my ($host, $log) = @_;

    my $sessip;
    my $sessif;
    if (!defined($sessif = getCMSession('Interface', $host))) {
        return
    }
    if (!defined($sessip = getCMSession('IP', $host))) {
        return
    }

    my @mets;
    if (defined $opt{metric}) {
        @mets = split /,/, $opt{metric}
    } else {
        push @mets, "Index", "Description", "AdminStatus", "OperStatus"
    }

    my (%OIDS, %ifOIDS, %ipOIDS);
    $ifOIDS{lc($_)} = $_ for ($sessif->ifOIDs());
    $ipOIDS{lc($_)} = $_ for ($sessip->addrOIDs());
    %OIDS = (%ifOIDS, %ipOIDS);

    if (!defined(my $r = verifyMetrics(\@mets, \%OIDS))) {
        return
    }

    my $OUT;
    if ($log ne "") {
        $OUT = open_log_file_keys($log, \@mets, \%OIDS)
    }

    # header
    if ($opt{header}) {
        printf $FORMAT, $host->{host};
        for (@mets) {
            if ($_ =~ /^(?:if)?index$/) {
                printf "%-6s", $OIDS{$_}
            } elsif ($_ eq "description") {
                printf "%-20s", $OIDS{$_}
            } elsif (exists $ipOIDS{$_}) {
                printf "%-16s", $OIDS{$_}
            } else {
                printf "%-12s", $OIDS{$_}
            }
        }
        printf "\n" . $FORMAT, $host->{host};
        for (@mets) {
            if ($_ =~ /^(?:if)?index$/) {
                print "-"x6
            } elsif ($_ eq "description") {
                print "-"x20
            } elsif (exists $ipOIDS{$_}) {
                print "-"x16
            } else {
                print "-"x12
            }
        }
        print "\n"
    }

    if (defined(my $response = $sessif->interface_info())) {
        my $ips = $sessip->addr_info();
        for my $int (sort {$a <=> $b} (keys(%{$response}))) {
            printf $FORMAT, $host->{host};
            printf $OUT "%s\t", $host->{host} if ($OUT);
            for my $m (@mets) {
                if ($m =~ /^(?:if)?index$/) {
                    printf "%-6i", $response->{$int}->{$OIDS{$m}};
                    printf $OUT "%i\t", $response->{$int}->{$OIDS{$m}} if ($OUT)
                } elsif ($m eq "description") {
                    printf "%-20s", $response->{$int}->{$OIDS{$m}};
                    printf $OUT "%s\t", $response->{$int}->{$OIDS{$m}} if ($OUT)
                } elsif (exists $ipOIDS{$m}) {
                    if (exists($ips->{$int})) {
                        for (0..$#{$ips->{$int}}) {
                            printf "%-16s", $ips->{$int}->[$_]->{$OIDS{$m}};
                            printf $OUT "%s\t", $ips->{$int}->[$_]->{$OIDS{$m}} if ($OUT)
                        }
                    } else {
                        print " " x 16;
                        print $OUT "\t" if ($OUT)
                    }
                } else {
                    printf "%-12s", $response->{$int}->{$OIDS{$m}};
                    printf $OUT "%s\t", $response->{$int}->{$OIDS{$m}} if ($OUT)
                }
            }
            print "\n";
            print $OUT "\n" if ($OUT)
        }
    } else {
        printf $FORMAT . "$FAILED (" . Cisco::SNMP->error . ")\n", $host->{host}
    }

    close($OUT) if ($OUT);
    $sessif->close();
    $sessip->close()
}

##################################################
sub SNMP_IntfUpDown {

    my ($host) = @_;

    my $session;
    if (!defined($session = getCMSession('Interface', $host))) {
        return
    }

    printf $FORMAT, $host->{host};
    if (defined(my $response = $session->interface_updown(
                   interface => $opt{interface},
                   operation => $opt{command}
               ))) {
        $opt{command} = uc($opt{command});
        print "Admin $opt{command} interfaces = @{$response} $SUCCESS\n"
    } else {
        print "$FAILED (" . Cisco::SNMP->error . ")\n"
    }

    $session->close()
}

##################################################
sub SNMP_CPUUtil {

    my ($host, $log) = @_;

    my $session;
    if (!defined($session = getCMSession('CPU', $host))) {
        return
    }

    my $response;
    if (!defined($response = $session->cpu_info())) {        
        return $FAILED . " (" . Cisco::SNMP->error . ")"
    }

    # outfile if requested
    my $OUT;
    if ($log ne "") {
        if (defined($OUT = open_log_file($log))) {
            if (defined $response->cpuName(0)) {
                print $OUT "CPU Name:\t";
                for (0..$#{$response}) {
                    printf $OUT "%s\t\t\t", $response->cpuName($_)
                }
                print $OUT "\nTimestamp";
                for (0..$#{$response}) {
                    print $OUT "\t5s%\t1m%\t5m%"
                }
                print $OUT "\n"
            } else {
                print $OUT "Timestamp\t5s%\t1m%\t5m%\n"
            }
        }
    }

    # header
    if ($opt{header}) {
        printf $FORMAT . "CPU Utilization\n", $host->{host};
        if (defined $response->cpuName(0)) {
            printf $FORMAT . "CPU Name:      ", $host->{host};
            for (0..$#{$response}) {
                printf "%-11s ", $response->cpuName($_)
            }
            print "\n"
        }
        printf $FORMAT . "Timestamp      5s%% 1m%% 5m%%", $host->{host};
        if (defined $response->cpuName(0)) {
            for (0..($#{$response} - 1)) {
                print " 5s% 1m% 5m%"
            }
        }
        printf "\n" . $FORMAT . "-"x56 . "\n", $host->{host}
    }

    # Ctrl-C handler to stop replay/repeat
    my $stopRepeat = 0;
    $SIG{INT} = sub {
        print "SIGINT! - Stop\n";
        $stopRepeat = 1
    };

    my $j = 0;
    while ($j != $opt{repeat}) {

        # Wait sample interval
        sleep $opt{Wait};

        # CTRL-C?
        last if ($stopRepeat);

        if (defined($response = $session->cpu_info())) {
            printf $FORMAT . "%s", $host->{host}, yyyymmddhhmmss();
            printf $OUT "%s", yyyymmddhhmmss() if ($OUT);
            for (0..$#{$response}) {
                printf      " %3i %3i %3i", (defined($response->cpu5sec($_)) ? $response->cpu5sec($_) : 0) , (defined($response->cpu1min($_)) ? $response->cpu1min($_) : 0), $response->cpu5min($_);
                printf $OUT "\t%i\t%i\t%i", (defined($response->cpu5sec($_)) ? $response->cpu5sec($_) : 0) , (defined($response->cpu1min($_)) ? $response->cpu1min($_) : 0), $response->cpu5min($_) if ($OUT)
            }
            print "\n";
            print $OUT "\n" if ($OUT);
            $j++
        } else {
            printf $FORMAT . "%s %s\n", $host->{host}, yyyymmddhhmmss(), Cisco::SNMP->error;
            printf $OUT "%s\t%s\n", yyyymmddhhmmss(), Cisco::SNMP->error if ($OUT)
        }
    }

    close($OUT) if ($OUT);
    $session->close()
}

##################################################
sub SNMP_MemUtil {

    my ($host, $log) = @_;

    my $session;
    if (!defined($session = getCMSession('Memory', $host))) {
        return
    }

    my $response;
    if (!defined($response = $session->memory_info())) {        
        return $FAILED . " (" . Cisco::SNMP->error . ")"
    }

    # outfile if requested
    my $OUT;
    if ($log ne "") {
        if (defined($OUT = open_log_file($log))) {
            print $OUT "Mem Pool Name:\t";
            for (0..$#{$response}) {
                printf $OUT "%s\t\t", $response->memName($_)
            }
            print $OUT "\nTotal:\t";
            for (0..$#{$response}) {
                printf $OUT "%i K\t\t", $response->memTotal($_)/1000
            }
            print $OUT "\nTimestamp\t";
            for (0..$#{$response}) {
                print $OUT "Used(K)\tUsed(%)\t"
            }
            print $OUT "\n"
        }
    }

    # header
    if ($opt{header}) {
        printf $FORMAT . "Mem Pool Name: ", $host->{host}, $host->{host};
        for (0..$#{$response}) {
            printf "%-12s ", $response->memName($_)
        }
        printf "\n" . $FORMAT . "Total:         ", $host->{host};
        for (0..$#{$response}) {
            printf "%8i K   ", $response->memTotal($_)/1000
        }
        printf "\n" . $FORMAT . "Timestamp      Used(K)    %%", $host->{host};
        for (0..($#{$response} - 1)) {
            print " Used(K)    %"
        }
        printf "\n" . $FORMAT . "-"x56 . "\n", $host->{host}
    }

    # Ctrl-C handler to stop replay/repeat
    my $stopRepeat = 0;
    $SIG{INT} = sub {
        print "SIGINT! - Stop\n";
        $stopRepeat = 1
    };

    my $j = 0;
    while ($j != $opt{repeat}) {

        # Wait sample interval
        sleep $opt{Wait};

        # CTRL-C?
        last if ($stopRepeat);

        if (defined($response = $session->memory_info())) {
            printf $FORMAT . "%s", $host->{host}, yyyymmddhhmmss();
            printf $OUT "%s", yyyymmddhhmmss() if ($OUT);
            for (0..$#{$response}) {
                printf      " %7i %4.1f",  ($response->memUsed($_) / 1000), ((($response->memUsed($_))/$response->memTotal($_)) * 100);
                printf $OUT "\t%i\t%1.1f", ($response->memUsed($_) / 1000), ((($response->memUsed($_))/$response->memTotal($_)) * 100) if ($OUT)
            }
            print "\n";
            print $OUT "\n" if ($OUT);
            $j++
        } else {
            printf $FORMAT . "%s %s\n", $host->{host}, yyyymmddhhmmss(), Cisco::SNMP->error;
            printf $OUT "%s\t%s\n", yyyymmddhhmmss(), Cisco::SNMP->error if ($OUT)
        }
    }

    close($OUT) if ($OUT);
    $session->close()
}

##################################################
sub SNMP_IntfUtil {

    my ($host, $log) = @_;

    my $session;
    if (!defined($session = getCMSession('Interface', $host))) {
        return
    }

    my @mets;
    if (defined $opt{metric}) {
        @mets = split /,/, $opt{metric}
    } else {
        $mets[0] = "Octets"
    }
    my %OIDS;
    $OIDS{lc($_)} = $_ for ($session->ifMetricUserOIDs);

    if (!defined(my $r = verifyMetrics(\@mets, \%OIDS))) {
        return
    }
    
    my $response;
    if (!defined($response = $session->interface_info($opt{interface}))) {
        return $FAILED . " (" . Cisco::SNMP->error . ")"
    }
    my $ifSpeed = $response->ifSpeed($opt{interface});

    # outfile if requested
    my $OUT;
    if ($log ne "") {
        if (defined($OUT = open_log_file($log))) {
            printf $OUT "%s - %s (bits/sec)\n\t", $response->ifDescription($opt{interface}), $ifSpeed;
            for (@mets) {
                print $OUT $OIDS{$_} . (($_ eq 'octets') ? " (bits/sec)" : " (pkts/sec)") . "\t\t\t\t"
            }
            print $OUT "\nTimestamp";
            for (0..$#mets) {
                print $OUT "\tIn\tIn %\tOut\tOut %"
            }
            print $OUT "\n"
        }
    }

    # header
    if ($opt{header}) {
        printf $FORMAT . "%s - %s (bits/sec)\n" .
               $FORMAT . "               ", 
                   $host->{host},
                   $response->ifDescription($opt{interface}),
                   $ifSpeed,
                   $host->{host};
        for (@mets) {
            printf "%-42s", $OIDS{$_} . (($_ eq 'octets') ? " (bits/sec)" : " (pkts/sec)")
        }
        print "\n";
        printf $FORMAT . "Timestamp      ", $host->{host};
        for (0..$#mets) {
            print "            In  In %            Out Out % "
        }
        print "\n";
        printf $FORMAT . "---------------", $host->{host};
        for (0..$#mets) {
            print "-"x42
        }
        print "\n"
    }

    # Ctrl-C handler to stop replay/repeat
    my $stopRepeat = 0;
    $SIG{INT} = sub {
        print "SIGINT! - Stop\n";
        $stopRepeat = 1
    };

    my $j = 0;
    my $recur;
    my %params = (
        interface => $opt{interface},
        polling   => $opt{Wait}
    );

    while ($j != $opt{repeat}) {

        # CTRL-C?
        last if ($stopRepeat);

        $params{recursive} = $recur;
        $params{metrics}   = \@mets;
        ($response, $recur) = $session->interface_utilization(%params);
        if (defined $response) {
            printf $FORMAT . "%s", $host->{host}, yyyymmddhhmmss();
            printf $OUT "%s\t", yyyymmddhhmmss() if ($OUT);
            for my $metric (@mets) {
                if ($metric eq 'octets') {
                    my $inPer  = $response->{$opt{interface}}->{InOctets}  * 100 / $ifSpeed;
                    my $outPer = $response->{$opt{interface}}->{OutOctets} * 100 / $ifSpeed;
                    printf " %14.2f %5.2f %14.2f %5.2f", $response->{$opt{interface}}->{InOctets}, $inPer, $response->{$opt{interface}}->{OutOctets}, $outPer;
                    printf $OUT "%1.2f\t%1.2f\t%1.2f\t%1.2f\t", $response->{$opt{interface}}->{InOctets}, $inPer, $response->{$opt{interface}}->{OutOctets}, $outPer if ($OUT)
                } else {
                    printf " %14.2f  --   %14.2f  --  ", $response->{$opt{interface}}->{'In' . $OIDS{$metric}}, ($metric eq 'unknowns') ? 0 : $response->{$opt{interface}}->{'Out' . $OIDS{$metric}};
                    printf $OUT "%1.2f\t\t%1.2f\t\t", $response->{$opt{interface}}->{'In' . $OIDS{$metric}}, ($metric eq 'unknowns') ? 0 : $response->{$opt{interface}}->{'Out' . $OIDS{$metric}} if ($OUT)
                }
            }
            print "\n";
            print $OUT "\n" if ($OUT)
        } else {
            printf $FORMAT . "%s %s\n", $host->{host}, yyyymmddhhmmss(), Cisco::SNMP->error;
            printf $OUT "%s\t%s\n", yyyymmddhhmmss(), Cisco::SNMP->error if ($OUT)
        }
        $j++
    }

    close($OUT) if ($OUT);
    $session->close()
}

##################################################
sub SNMP_ProxyPing {

    my ($host) = @_;

    my $session;
    if (!defined($session = getCMSession('ProxyPing', $host))) {
        return
    }

    my $count = 1;
    if (defined $opt{repeat}) {
        if (($opt{repeat} > 0) && ($opt{repeat} < 11)) { $count = $opt{repeat} }
    }

    my $size  = 64;
    if (defined $opt{command}) {
        if ($opt{command} =~ /^\d+$/) {
            if (($opt{command} > 0) && ($opt{command} < 65536)) { $size  = $opt{command} }
        }
    }

    # header
    printf $FORMAT . "ping://$opt{interface}->{addr} ($size byte packets)\n" .
           $FORMAT . "Timestamp      Tx Rx Av-RT(ms) Min(ms) Max(ms)\n" . 
           $FORMAT . "----------------------------------------------\n", $host->{host}, $host->{host}, $host->{host} if ($opt{header});

    # Ctrl-C handler to stop replay/repeat
    my $stopReplay = 0;
    $SIG{INT} = sub {
        print "SIGINT! - Stop\n";
        $stopReplay = 1
    };

    my $j = 0;
    my $min = 10000; # use outrageous numbers so actual
    my $max = 1;     # values will overwrite them
    my $received = 0;
    my %params = (
        host   => $opt{interface}->{addr},
        family => $opt{interface}->{family},
        count  => $count,
        size   => $size,
        wait   => $opt{Wait}
    );
    if (defined $opt{metric}) {
        $params{vrf} = $opt{metric}
    }

    while ($j != $opt{replay}) {

        if (defined(my $pings = $session->proxy_ping(%params))) {

            # CTRL-C?
            last if ($stopReplay);

            printf $FORMAT . "%s %2i %2i %5i", $host->{host}, yyyymmddhhmmss(), $pings->ppSent(), $pings->ppReceived(), $pings->ppAverage();

            # assign new min/max if the current ping time is a better choice
            if ($pings->ppMinimum() < $min) {
                $min = $pings->ppMinimum();
                printf "   %5i", $min
            } else { print "        " }
            if ($pings->ppMaximum() > $max) {
                $max = $pings->ppMaximum();
                printf "   %5i", $max
            }
            print "\n";

            # Increment total received to use with $j (total times) to calculate success percentage 
            $received += $pings->ppReceived()
        } else {
            printf $FORMAT . "%s\n", $host->{host}, Cisco::SNMP->error;
            if (Cisco::SNMP->error eq "NOT SUPPORTED") {
                last
            }
        }
        $j++
    }

    $session->close();
    # Summary stats
    if ($opt{header}) {
        printf $FORMAT . "----------------------------------------------\n", $host->{host};
        printf $FORMAT . "Success Rate: %i%% ($received/%i)\n", $host->{host}, $received/(($j == 0) ? 1 : $j*$count)*100, $j*$count;
        printf $FORMAT . "Min: %s ms, Max: $max ms\n", $host->{host}, (($min == 0) ? "<1" : $min) if ($received > 0)
    }
}

##################################################
sub SNMP_Inventory {

    my ($host, $log) = @_;

    my $session;
    if (!defined($session = getCMSession('Entity', $host))) {
        return
    }

    my @mets;
    if (defined $opt{metric}) {
        @mets = split /,/, $opt{metric}
    } else {
        push @mets, "ModelName", "Descr", "SerialNum", "FirmwareRev", "SoftwareRev"
    }

    my %OIDS;
    $OIDS{lc($_)} = $_ for ($session->entityOIDs);

    if (!defined(my $r = verifyMetrics(\@mets, \%OIDS))) {
        return
    }

    my $OUT;
    if ($log ne "") {
        $OUT = open_log_file_keys($log, \@mets, \%OIDS)
    }

    # header
    if ($opt{header}) {
        printf $FORMAT, $host->{host};
        for (@mets) {
            if ($_ eq "descr") {
                printf "%-30s", $OIDS{$_}
            } else {
                printf "%-20s", $OIDS{$_}
            }
        }
        printf "\n" . $FORMAT, $host->{host};
        for (@mets) {
            if ($_ eq "descr") {
                print "-"x30
            } else {
                print "-"x20
            }
        }
        print "\n"
    }

    if (defined(my $inventory = $session->entity_info())) {
        for my $part (0..$#{$inventory}) {
            next if (($inventory->entitySerialNum($part) eq '') && ($opt{inventory} <= 1));

            printf $FORMAT, $host->{host};
            printf $OUT "%s\t", $host->{host} if ($OUT);
            for (@mets) {
                if ($_ eq "descr") {
                    printf "%-30s", $inventory->[$part]->{$OIDS{$_}};
                    printf $OUT "%s\t", $inventory->[$part]->{$OIDS{$_}} if ($OUT)
                } else {
                    printf "%-20s", $inventory->[$part]->{$OIDS{$_}};
                    printf $OUT "%s\t", $inventory->[$part]->{$OIDS{$_}} if ($OUT)
                }
            }
            print "\n";
            print $OUT "\n" if ($OUT)
        }
    } else {
        printf $FORMAT . "$FAILED (" . Cisco::SNMP->error . ")\n", $host->{host}
    }

    close($OUT) if ($OUT);
    $session->close()
}

##################################################
sub SNMP_GetInfo {

    my ($host) = @_;

    my $session;
    if (!defined($session = getCMSession('System', $host))) {
        return
    }

    if (defined(my $sysinfo = $session->system_info())) {
        printf $FORMAT . "sysDescr        = %s\n", $host->{host}, $sysinfo->sysDescr;
        printf $FORMAT . "sysObjectID     = %s\n", $host->{host}, $sysinfo->sysObjectID;
        printf $FORMAT . "sysUpTime       = %s\n", $host->{host}, $sysinfo->sysUpTime;
        printf $FORMAT . "sysConctact     = %s\n", $host->{host}, $sysinfo->sysContact;
        printf $FORMAT . "sysName         = %s\n", $host->{host}, $sysinfo->sysName;
        printf $FORMAT . "sysLocation     = %s\n", $host->{host}, $sysinfo->sysLocation;
        printf $FORMAT . "sysORLastChange = %s\n", $host->{host}, $sysinfo->sysORLastChange;
        printf $FORMAT . "sysOSVersion    = %s\n", $host->{host}, $sysinfo->sysOSVersion;
        printf $FORMAT . "sysServices     = ", $host->{host};
        print "$_ " for (@{$sysinfo->sysServices});
        print "\n"
    } else {
        printf $FORMAT . "$FAILED (" . Cisco::SNMP->error . ")\n", $host->{host}
    }
}

##################################################
sub TELNET_Mode {

    my ($host, $cmds) = @_;

    my $result = 0;
    my %sessions;

    for my $h (0..$#{$host}) {
        # Make sure port is acceptable
        if (!defined $host->[$h]->{port}) {
            if (defined $opt{ssh}) {
                $host->[$h]->{port} = 22
            } else {
                $host->[$h]->{port} = 23
            }
        }

        my $socket;
        if ($HAVE_IO_Socket_IP) {
            $socket = IO::Socket::IP->new(
                PeerHost => $host->[$h]->{addr},
                PeerPort => $host->[$h]->{port},
                Family   => $host->[$h]->{family}
            )
        } else {
            $socket = IO::Socket::INET->new(
                PeerHost => $host->[$h]->{addr},
                PeerPort => $host->[$h]->{port}
            )
        }

        if (!$socket) {
            printf $FORMAT. "$FAILED (No connect)\n", $host->[$h]->{host};
            if (defined $opt{force}) {
                next
            } else {
                return
            }
        }

        my $session;
        if (defined $opt{ssh}) {
            $session = Net::SSH2::Cisco->new(
                fhopen  => $socket,
                binmode => 1,
                Errmode => 'return',
                Prompt  => $PROMPT
            )
        } else {
            $session = Net::Telnet::Cisco->new(
                fhopen  => $socket,
                binmode => 1,
                Errmode => 'return',
                Prompt  => $PROMPT
            )
        }

        if (!$session) {
            printf $FORMAT. "$FAILED (No session)\n", $host->[$h]->{host};
            if (!defined $opt{force}) {
                return
            }
        }
        $sessions{$host->[$h]->{host}} = $session
    }

    my @hosts;
    for my $h (0..$#{$host}) {
        # keep new array of successfully connected hosts (required for -f (force))
        if (defined $sessions{$host->[$h]->{host}}) {
            push @hosts, $host->[$h]->{host}
        } else {
            next
        }

        my $log = "";
        if ($opt{write}) {
            $sessions{$host->[$h]->{host}}->max_buffer_length(5 * 1024 * 1024);

            if (($opt{write} == 1) || ($opt{write} == 3)){
                $log = get_log_file($host->[$h]->{host}, $opt{dir}, undef);
                $sessions{$host->[$h]->{host}}->input_log($log);
                printf $FORMAT . "Writing log $log $SUCCESS\n", $host->[$h]->{host}
            }

            # start TAIL if requested
            if ($opt{write} == 3) {
                # Windows
                my @pathDirs = split /;/, $ENV{PATH};
                for (@pathDirs) {
                    $_ =~ s/\\$//;
                    if (-e ($_ . "\\tail.exe")) {
                        system ("start \"CRAPPS - $log\" tail -f $log");
                        last
                    }
                }
                # *nix
                system ("tail -f $log &") if (-e "/usr/bin/tail")
            }

            # dump log
            if ($opt{write} == 4) {
                $log = get_log_file($host->[$h]->{host}, $opt{dir}, 'dump');
                $sessions{$host->[$h]->{host}}->dump_log($log);
                printf $FORMAT . "Writing log $log $SUCCESS\n", $host->[$h]->{host}
            }
        }

        # Terminal Server?
        if ($opt{term} and !defined $opt{ssh}) {
            $result = $sessions{$host->[$h]->{host}}->cmd("\n") for (1..$opt{term})
        }

        # login
        if ((defined $opt{user}) or (defined $opt{ssh})) {
            # with Username
            if (!($sessions{$host->[$h]->{host}}->login(Name => $opt{user}, Password => $opt{pass}))) {
                printf $FORMAT. "$FAILED (Username login)\n", $host->[$h]->{host};
                if (defined $opt{force}) {
                    $sessions{$host->[$h]->{host}}->close;
                    $sessions{$host->[$h]->{host}} = undef
                } else {
                    $sessions{$_}->close for (keys(%sessions));
                    return
                }
            }
        } else {
            # without Username
            if (!($sessions{$host->[$h]->{host}}->login(Password => $opt{pass}))) {
                printf $FORMAT. "$FAILED (login)\n", $host->[$h]->{host};
                if (defined $opt{force}) {
                    $sessions{$host->[$h]->{host}}->close;
                    $sessions{$host->[$h]->{host}} = undef
                } else {
                    $sessions{$_}->close for (keys(%sessions));
                    return
                }
            }
        }

        # enable if provided
        if (defined $opt{enable}) {
            if (!($sessions{$host->[$h]->{host}}->enable($opt{enable}))) {
                printf $FORMAT. "$FAILED (enable)\n", $host->[$h]->{host};
                if (defined $opt{force}) {
                    $sessions{$host->[$h]->{host}}->close;
                    $sessions{$host->[$h]->{host}} = undef
                } else {
                    $sessions{$_}->close for (keys(%sessions));
                    return
                }
            }
        }

        # turn off paging by default for CatOS or IOS
        if (defined $sessions{$host->[$h]->{host}}) {
            if ($opt{Catos}) {
                $result = $sessions{$host->[$h]->{host}}->cmd('set length 0')
            } else {
                $result = $sessions{$host->[$h]->{host}}->cmd('terminal length 0')
            }
        }
    }

    # create final array of successfully connected and logged on hosts (required for -f (force))
    my @temp;
    for my $h (0..$#{$host}) {
        if (defined $sessions{$host->[$h]->{host}}) {
            push @temp, $host->[$h]
        }
    }

    # return if no hosts opened (required for -f (force))
    if ($#temp == -1) {
        print "$FAILED (No connections opened)\n";
        return
    } else {
        $host = \@temp
    }

    # apply commands
    # interactive mode
    if (defined $cmds->[0] && ($cmds->[0] eq "--STDIN--")) {

        my $cmdPrompt = ($#{$host} == 0) ? $host->[0]->{host} . ":" . $host->[0]->{port} : $#{$host} + 1  . " hosts";
        printf $FORMAT . "CONNECTED! - Enter commands, 'logout' to end\n", $cmdPrompt;
        my $cmd = "";
        $SIG{INT} = sub {
            print "SIGINT! - Stop\n";
            $cmd = 'logout';
        };

        # get command
        while (lc($cmd) ne "logout") {

            printf $FORMAT, $cmdPrompt;
            $cmd = <STDIN>;
            chomp $cmd if defined $cmd ;

            my $DONE = 0;
# Sort by hostname
#           for my $h (sort(keys(%sessions))) {
# Sort by order entered on command line
            for my $h (0..$#{$host}) {
                $sessions{$host->[$h]->{host}}->errmode(
                    sub { 
                        if (!$sessions{$host->[$h]->{host}}->eof()) {
                            printf $FORMAT . $FAILED . " ($cmd)\n", $host->[$h]->{host}
                        }
                    }
                );
                my @output = $sessions{$host->[$h]->{host}}->cmd($cmd);
                if ($opt{write} == 2) {
                    printf $FORMAT . "$cmd\n", $host->[$h]->{host};
                    print $_ for (@output)
                }
                # detect session end
                if ($sessions{$host->[$h]->{host}}->eof()) {
                    $DONE = 1
                }
            }
            last if ($DONE)
        }

    # not interactive
    } else {
        my $session = $sessions{$host->[0]->{host}};
        # Ctrl-C handler to stop replay/repeat
        my $stopReplay = 0;
        my $stopRepeat = 0;
        my $stopQuit   = 0;
        $SIG{INT} = sub {
            print "\n";
            while (1) {
                printf $FORMAT . "SIGINT! - Stop (R)eplay (r)epeat (Q)uit: ", $host->[0]->{host};
                chomp(my $uInput = <STDIN>);
                if ($uInput eq "r") { $stopRepeat = 1; return }
                if ($uInput eq "R") { $stopReplay = 1; return }
                if (lc($uInput) eq "q") { $stopRepeat = 1; $stopReplay = 1; $stopQuit = 1; return }
            }
        };

        my $i = 0;
        $stopReplay = 0; # Reset Replay for next host
        while ($i != $opt{replay}) {

            # Loop up commands
            for my $cmd (@{$cmds}) {

                my $j = 0;
                $stopRepeat = 0; # Reset Repeat for next host
                while ($j != $opt{repeat}) {

                    chomp $cmd;
                    printf $FORMAT, $host->[0]->{host};

                    # Print replay/repeat numbers if we're looping
                    if (($opt{repeat} != 1) || ($opt{replay} != 1)) {
                        printf "[%s%s] ", ((!$stopReplay) && ($opt{replay} != 1)) ? "R" . ($i + 1) : "", ((!$stopRepeat) && ($opt{repeat} != 1)) ? "r" . ($j + 1) : ""
                    }
                    print "$cmd ";

                    my $ERROR = 0;
                    $session->errmode(
                        sub { 
                            if (!$session->eof()) {
                                if (defined $opt{force}) {
                                    print $FAILED
                                } else {
                                    $ERROR = 1
                                }
                            }
                        }
                    );
                    my @output = $session->cmd($cmd);
                    if ($ERROR) {
                        $session->close;
                        print "$FAILED ABORTING";
                        return
                    }
                    if ($opt{write} == 2) {
                        print "\n";
                        print $_ for (@output)
                    }
                    print "\n";
                    sleep $opt{Wait};
                    last if ($stopRepeat);
                    $j++ # increment repeat
                }
                last if ($stopQuit)
            }
            last if ($stopReplay);
            $i++ # increment replay
        }
    }

    for my $h (0..$#{$host}) {
        $sessions{$host->[$h]->{host}}->close
    }
}

##################################################
sub PING_Mode {

    my ($host) = @_;

    # Create Ping object
    my $p;
    if (defined $opt{metric}) {
        if    ($opt{metric} =~ /^icmp$/i) { $p = Net::Ping->new('icmp') }
        elsif ($opt{metric} =~ /^tcp$/i)  { $p = Net::Ping->new('tcp')  }
        elsif ($opt{metric} =~ /^udp$/i)  { $p = Net::Ping->new('udp')  }
        elsif ($opt{metric} =~ /^syn$/i)  { $p = Net::Ping->new('syn')  }
        else {
            return $FAILED . " (Undefined protocol: $opt{metric})"
        }
    } else {
        $opt{metric} = "TCP";
        $p = Net::Ping->new()
    }

    $p->hires(1);
    $opt{metric} = uc($opt{metric});

    my $interfaces = [0];
    if (defined $opt{interface} && ($opt{interface} ne "") && ($opt{metric} !~ /^icmp$/i)) {
        if (!defined($interfaces = Cisco::SNMP::_get_range($opt{interface}))) {
            return $FAILED . " (" . Cisco::SNMP->error . ")"
        }
    }

    # Ctrl-C handler to stop replay/repeat
    my $stopReplay = 0;
    my $stopRepeat = 0;
    my $stopQuit   = 0;
    $SIG{INT} = sub {
        print "\n";
        while (1) {
            print "SIGINT! - Stop (R)eplay (r)epeat (Q)uit: ";
            chomp(my $uInput = <STDIN>);
            if ($uInput eq "r") { $stopRepeat = 1; return }
            if ($uInput eq "R") { $stopReplay = 1; return }
            if (lc($uInput) eq "q") { $stopRepeat = 1; $stopReplay = 1; $stopQuit = 1; return }
        }
    };

    my $i = 0;
    $stopReplay = 0; # Reset Replay for next host
    while ($i != $opt{replay}) {
        for (@{$interfaces}) {
            my $port = 7;
            if ($_ == 0) {
                if ($opt{metric} =~ /^icmp$/i) { $port = 0 }
            } else {
                 # Right way
                 #$p->port_number($port = $_)
                 # This will support older versions of Net::Ping
                 $p->{port_num} = $port = $_
            }

            my $j = 0;
            $stopRepeat = 0; # Reset Repeat for next host
            while ($j != $opt{repeat}) {
                printf $FORMAT, $host->{host};

                # Print replay/repeat numbers if looping
                if (($opt{repeat} != 1) || ($opt{replay} != 1)) {
                    printf "[%s%s] ", ((!$stopReplay) && ($opt{replay} != 1)) ? "R" . ($i + 1) : "", ((!$stopRepeat) && ($opt{repeat} != 1)) ? "r" . ($j + 1) : ""
                }
                printf "%s[:%5i] ", $opt{metric}, $port;

                # Execute Ping
                my ($response, $rtt, $ip) = $p->ping($host->{addr});
                if ($response) {
                    printf $SUCCESS . " %2.3f sec\n", $rtt
                } else {
                    print "$FAILED\n"
                }
                sleep $opt{Wait};
                last if ($stopRepeat);
                $j++ # increment repeat
            }
            last if ($stopQuit)
        }
        last if ($stopReplay);
        $i++ # increment replay
    }

    $p->close()
}

##################################################
sub verifyMetrics {
    my ($mets, $OIDS) = @_;

    my @tMets;
    for (@{$mets}) {
        if (!defined $OIDS->{lc($_)}) {
            if (!defined $opt{force}) {
                print "$0: Unknown field `$_'";
                return undef
            }
        } else {
            push @tMets, lc($_)
        }
    }
    undef @{$mets};
    push @{$mets}, @tMets;
    return 1
}

##################################################
sub get_log_file {

    my ($host, $dir, $option) = @_;

    my $log = $host . (defined($option) ? ("-" . $option) : "") . ".log";

    # append directory path to log file name
    if (defined $dir) {
        $log = $dir . "/" . $log
    }

    # File exists
    if (-e ($log)) {
        $log =~ s/\.log$//;
        # Get unique filename by appending date
        $log = $log . "-" . yyyymmddhhmmss() . ".log"
    }
    return $log
}

##################################################
sub open_log_file {
    my ($log) = @_;

    my $OUT;
    print "Writing log $log ";
    if (open($OUT, '>', $log)) {
        # autoflush (in case tail -f)
        select $OUT;
        $| = 1;
        select STDOUT;

        print "$SUCCESS\n"
    } else {
        print "$FAILED\n";
        undef $OUT
    }
    return $OUT
}

##################################################
sub open_log_file_keys {
    my ($log, $mets, $OIDS) = @_;

    my $OUT;
    print "Writing log $log ";
    if (open($OUT, '>', $log)) {
        # autoflush (in case tail -f)
        select $OUT;
        $| = 1;
        select STDOUT;

        print "$SUCCESS\n";

        print $OUT "HOST\t";
        for (@{$mets}) {
            print $OUT $OIDS->{$_} . "\t"
        }
        print $OUT "\n"
    } else {
        print "$FAILED\n";
        undef $OUT
    }
    return $OUT
}

##################################################
sub yyyymmddhhmmss {
    my @time = localtime();
    return (($time[5] + 1900) . ((($time[4] + 1) < 10)?("0" . ($time[4] + 1)):($time[4] + 1)) . (($time[3] < 10)?("0" . $time[3]):$time[3]) . (($time[2] < 10)?("0" . $time[2]):$time[2]) . (($time[1] < 10)?("0" . $time[1]):$time[1]) . (($time[0] < 10)?("0" . $time[0]):$time[0]))
}

##################################################
sub PASSWORD_Mode {

    my $result = 0;

    # Encrypt
    if (defined $opt{enable}) {
        # MD5
        if (defined $opt{snmp}) {
            if ($HAVE_Crypt_PasswdMD5) {
                # Standard Cisco salt length is 4, but testing shows it accepts from 1 to 7 inclusive
                if ((length($opt{snmp}) > 7) || (length($opt{snmp}) < 1)) {
                    $opt{snmp} = 'crap'
                }
                printf "%s\n", unix_md5_crypt($opt{Pass}, $opt{snmp});
                return $SUCCESS
            } else {
                print "$0: Requires Crypt::PasswdMD5\n";
                exit
            }
        # Type 7
        } else {
            if (($result = Cisco::SNMP::Password->password_encrypt($opt{Pass}, $opt{enable})) == 0) {
                printf "$0: %s\n", Cisco::SNMP->error
            } else {
                for my $p (@{$result}) {
                    print "$p\n"
                }
            }
            return $SUCCESS
        }
    # Decrypt
    } else {
        my @passwords;

        # -P file
        if (open(my $IN, '<', $opt{Pass})) {
            my $linecnt = 1;
            while (<$IN>) {
                chomp $_;
                if (defined $opt{dir}) {
                    if ($_ =~ $PASSWORD5) { push @passwords, "($linecnt) " . $_ }
                } else {
                    if ($_ =~ $PASSWORD7) { push @passwords, "($linecnt) " . $_ }
                }
                $linecnt++
            }
            close($IN);

        # -P password
        } else {
            push @passwords, $opt{Pass}
        }

        for my $pass (@passwords) {

            # $pass is a password if it was a password originally.
            # $pass is a line from a router config if password was a file so we 
            # need to split $pass into array at spaces, last of which is password.
            my @parts = split / /, $pass;

            # MD5
            if (defined $opt{dir}) {
                if ($HAVE_Crypt_PasswdMD5) {
                    my $DONE = 0;
                    my $salt = $parts[$#parts];
                    $salt =~ s/^\$1\$//;
                    $salt =~ s/^(.*)\$.*$/$1/;
                    $salt = substr($salt, 0, 8);

                    # -d File
                    my @dictionary;
                    if (-e $opt{dir}) {
                        open(my $DICT, '<', $opt{dir});
                        @dictionary = <$DICT>;
                        close($DICT)
                    # -d word
                    } else {
                        push @dictionary, $opt{dir}
                    }

                    if (-e $opt{Pass}) {
                        print "$opt{Pass}:$pass\n"
                    }

                    for my $word (@dictionary) {
                        chomp $word;
                        print "Trying: $word\n" if (defined $opt{write});
                        if (unix_md5_crypt($word, $salt) eq $parts[$#parts]) {
                            print "$word\n";
                            $DONE = 1;
                            last
                        }
                    }
                    if (!$DONE) {
                        print "$FAILED\n"
                    }
                    print "\n"
                } else {
                    print "$0: Requires Crypt::PasswdMD5\n";
                    exit
                }
            # Type 7
            } else {
                if (-e $opt{Pass}) {
                    print "$opt{Pass}:$pass\n"
                }
                if (($result = Cisco::SNMP::Password->password_decrypt($parts[$#parts])) eq 0) {
                    print $FAILED . " (" . Cisco::SNMP->error . ")"
                } else {
                    print "$result\n"
                }
                print "\n"
            }
        }
        return $SUCCESS
    }
}

##################################################
# End Subroutines
##################################################

__END__

##################################################
# Start POD
##################################################

=head1 NAME

CRAPPS - Cisco Router Action Performing Perl Script

=head1 SYNOPSIS

 crapps -P password [options]
 crapps -S svc [options]
 crapps [[SNMP options] | [Telnet options]] [options] host ...

=head1 DESCRIPTION

Script will interface with Cisco router via SNMP or Telnet, supporting 
regular login or username, and perform actions.  SNMP supports a get 
config, put config and a save config (C<wr mem> for IOS).  SNMP mode also
supports get and clear VTY line function and a get interface list and 
monitor interface utilization function, including CPU, memory and proxy 
ping.

Telnet mode supports the issuing of commands from a file.  The only
default command issued in TELNET mode is C<terminal length 0> for IOS 
or C<set length 0> for CatOS.  Therefore, show commands can be in the 
commands file along with config commands (on IOS, as long as preceded 
by a C<config term> and followed by an C<end> and C<wr mem> if save is 
desired).  Telnet mode supports log file of session transcript.

Password decrypt and encrypt mode is provided for Cisco passwords.  
Type 7 (not C<enable secret>) are decrypted or encrypted to all 
possible encryptions.  Type 5 (C<enable secret>) are encrypted or 
decrypted by dictionary brute force.

Server mode is provided for service listening.  Default execution 
with no options provides Ping.

=head1 CAVEATS

=head2 Net::Telnet::Cisco

The latest B<Net::Telnet::Cisco> at the time of this script (1.10) has an 
issue with prompt discovery on new Cisco IOS-XR routers.  These routers 
have a prompt like:

  RP/0/RP1/CPU0:routername#

The current B<Net::Telnet::Cisco> prompt matching will not catch this and 
cause timeouts on Telnet connects to these types of routers.

This script sends a new prompt that should match existing prompts and the 
new IOS-XR prompts.  If you are having failed connect issues when in 
Telnet mode, but logging shows that you are connecting, the custom prompt 
is the first place to look.

B<Net::Telnet::Cisco> supplied prompt:

  '/(?m:^[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$#>]\s?(?:\(enable\))?\s*$)/'

Updated by this program:

  (?:[\w.\/]+\:)?

inserted after the C<'/(?m:^>  The rest of the line is left as is.

=head1 ARGUMENTS

 host                 Device hostname or IP address.  Can be a file, 
                      with optional path containing hostnames or 
                      IP's of devices, 1 per line.  Blank lines and
                      lines starting with hash (#) are ignored.

                      NOTE:  Not required and ignored for Password 
                             and/or Server Mode.

=head1 OPTIONS

 -4                   Force IPv4 for name resolution. [Default]
 -6                   Force IPv6 for name resolution.

 -b [-b]              Beep on completion.
 --beep               -b    = Beep on completion.
                      -b -b = Beep after each host is completed.
                      DEFAULT:  (or not specified) No beep.

 -C                   CatOS - device specified by 'host' is running 
 --catos              Catalyst OS.  Note this applies to all hosts 
                      during a single run so do not mix and match IOS
                      and CatOS hosts on a single command line or input 
                      host file.  Effects terminal length setting in 
                      Telnet mode and OID in SNMP mode (TFTP).

 -F #                 Output line header format.  Can use 'printf' 
 --format             formatting commands.
                      DEFAULT:  (or not specified) "%-19s > ", $host.

 -h #                 Print header in output.  Use --noheader to omit.
 --header             DEFAULT:  (or not specified) Print header

 -W #                 Wait # seconds between hosts if doing multiple.
 --wait               Wait # seconds between commands if -r or -R.
                      DEFAULT:  (or not specified) 0.
                                                   1. [SNMP MODE -i]

=head2 PASSWORD MODE

To activate B<Password Mode>, use the -P option.

 -P password |        Decrypts the provided type 7 encrypted password.
    file.confg        Loops through the provided Cisco router config 
 --Password           file and decrypts all type 7 passwords found.

 -d file | word       Use file (or provided word) as dictionary input 
 --dictionary         to try to crack the provided MD5 (enable secret) 
                      argument to -P. [Requires Crypt::PasswdMD5]

 -e [#]               Encrypt the provided argument to -P.  Use double
 --encrypt            quotes to delimit strings with spaces.  Outputs all 
                      possible Cisco type 7 encryptions by default.  
                      Optional number outputs the single password 
                      encrypted with the provided index; valid values are 
                      0 - 52 inclusive.  Non-number or out of range value 
                      produces password encrypted with a random index.

 -s [salt]            If specified, encrypt -P argument to MD5 (enable 
 --salt               secret) password.  Salt must be:
                      1 <= salt <= 7 characters.  Use "" for default.
                      [Requires Crypt::PasswdMD5]

=head2 SNMP MODE

To activate B<SNMP Mode>, use the -s option.

 -s community |       SNMP community string.  Can be read-only or 
   authprot[,privprot]read-write depending on the operation to be 
 --snmp               performed.  If -u and -p (see below) are 
                      specified, this is the SNMP authentication 
                      protocol; either 'md5' or 'sha' optionally 
                      followed by ',' and the privacy protocol 'des' 
                      (default, or not specified), 'aes' or '3des'.

 -u username          SNMP v3 username.
 --username

 -p authpass          SNMP v3 authentication password.
 --password

 -e privpass          SNMP v3 privacy / encryption password.
 --encrypt

 -t [IP_Addr]         SNMP get/put config via TFTP.
 --tftp               DEFAULT:  localhost.

     -c file.confg |  File (with optional path) for TFTP Put.
        path/         Directory of unique files for TFTP Put.  Files in
     --command        directory are <host>.confg.

     -d <dir>         Save directory for TFTP Get.  
     --directory      DEFAULT:  (or not specified) [TFTP root].

     -m <type>        File type to up/down-load.  Valid types are:
     --metric           run, start
                      NOTE:  Use EXTREME caution when TFTP Put to 
                      startup-config (start).  This MUST be a FULL 
                      configuration file as the config file is NOT 
                      merged, but instead OVERWRITES the startup-config.
                      DEFAULT:  (or not specified) run.

     -w               Perform 'write memory' if TFTP successful.

 -l [# [range]]       Return report of line usage.  With optional 
 --lines              number means clear line #.  Range can be 
                      provided with comma (,) for individual lines 
                      and dash (-) for all inclusive range.  For 
                      example:

                                1,9-11,7,3-5,15

                      Clears lines 1 9 10 11 7 3 4 5 15.

     -m "message"     Send message to line(s) specified in -l; do not
     --message        clear lines.  If no # specified, send to all.

 -i [#]               Return report of interfaces on the device. 
 --interface          With optional # means get utilization on
                      interface with ifIndex #.
                      Use '0' for CPU utilization.
                      Use '00' for Memory utilization.

                      Use IP address or hostname for proxy ping.

                        -c #      Packet size in bytes.
                        --command DEFAULT:  (or not specified) 64.

                        -m <name> VRF name if ping must be sourced 
                        --metric  from a VRF instance.
                                  DEFAULT:  (or not specified) [none].

                        -r #      Number of pings per iteration.
                        --repeat  DEFAULT:  (or not specified) 1.

                        -R #      Count of iterations.
                        --Replay  DEFAULT:  (or not specified) 1.

     -c command       Admin up or down interface specified by -i.  
     --command        Valid commands are:
                        up
                        down

                      Range can be provided for -i with comma (,) 
                      for individual interfaces and dash (-) for all
                      inclusive range.  For example:

                                -i 1,9-11 --command down

                      Sets admin status to down for interfaces with 
                      ifIndex 1, 9, 10 and 11.

     -m metric        The metric(s) to measure, comma separated.
     --metric         When -i is specified as ifIndex, values are:
                        multicasts [Multicasts (packets/sec)]
                        broadcasts [Broadcasts (packets/sec)]
                        octets     [Octets     (bits/sec)   ]
                        unicasts   [Unicasts   (packets/sec)]
                        discards   [Discards   (packets/sec)]
                        errors     [Errors     (packets/sec)]
                        unknowns   [Unknowns   (packets/sec)]

                      DEFAULT:  (or not specified) octets.

                      When -i is specified alone, for valid values see:
                        Cisco::SNMP::Interface
                        Cisco::SNMP::IP

                      DEFAULT:  (or not specified) Index, Description,
                                Admin/OperStatus.

     -r #             Repeat -i option # times.
     --repeat         DEFAULT:  (or not specified) 1.
                      Use '0' for infinite.
                      Use 'Ctrl-C' to stop infinite.

     -w               Log output to file "<host>-if<#>.log".  If 
     --write          output file exists, the date is appended to the
                      end of the filename so as to not overwrite.

 -I [-I]              Device inventory from ENTITY-MIB.
 --inventory          -I    = Only units with serial number.
                      -I -I = All units.

     -m metric        The inventory information to return.
     --metric         For valid values see:
                        Cisco::SNMP::Entity

                        DEFAULT:  (or not specified) ModelName, Descr,
                                SerialNum, Firm/SoftwareRev

     -w               Log output to file "<host>-inventory.log".  If 
     --write          output file exists, the date is appended to the 
                      end of the filename so as to not overwrite.

 -w                   Perform 'write memory'.
 --write

If none of the above options are provided other than C<-s>, 
perform SNMP walk of the System MIB (by default).

     -c <oid>         OID to walk, in dotted decimal format.
     --command

     -f               Do NOT load provided translations for System 
     --force          MIB.

     -m file.txt      Tab-delimited MIB file with 2 columns:
     --mib            <dotted OID> <TAB> <Text Translation Name>

=head2 TELNET SSH MODE

To activate B<Telnet Mode>, use the -p option without -s.

B<NOTE:>  Hosts can contain an optional port if the default (23) is 
not sufficient.  This may be the case with Quagga or terminal 
servers.  Use:

    host:port

Port is an integer number: 0 E<lt> port E<lt> 65536

For example:

    hostname:2601              # hostname with port
    10.1.1.1:80                # IPv4 Address with port
    [2001:db8:100::1]:2001     # IPv6 Address with port

 -S                   Use SSH instead of Telnet.
 -ssh

 -p password          Telnet login password.
 --password           To prompt for password with no echo (this 
                      requires user interaction), use -p with no 
                      argument.

                      NOTE:  If passwords have special characters, 
                             use double-quotes to delimit.

 -c file.cfg  |       file.cfg = File (with optional path) of 
    path/     |                  commands to be executed.
    "command"         path/    = Path to unique files for each device.
 --command                       Path MUST end in slash to denote
                                 directory. Unique files in directory 
                                 are <host>.confg.
                      "command"= Double quote delimited string of a 
                                 single Cisco command to execute.

                      If -c is not provided, assume interactive mode.  
                      The user will enter commands to all devices 
                      simultaneously once connected.  Use "tail -f 
                      <LOG_FILE>" (if -w) or -w -w to view the 
                      interactive sessions.  The word "logout" - 
                      without the double-quotes ends the sessions.

                      NOTE:  Interactive mode implies -f after initial 
                             connection and overrides -r, -R and -W.

 -d directory         Working directory for all output files.  
 --dir                DEFAULT:  (or not specified) [Current].

 -e enable            Enable password.
 --enable             To prompt for password with no echo (this 
                      requires user interaction), use -e with no 
                      argument.

 -f                   Force to continue if errors encountered.
 --force              By default, if an error is encountered, it aborts 
                      the session.  This flag continues the session and 
                      simply prints the error.

 -r #                 Repeat each -c command # times.
 --repeat             DEFAULT:  (or not specified) 1.
                      Use '0' for infinite.
                      Use 'Ctrl-C' to stop infinite.

 -R #                 Replay sequence.  Replay the sequence of -c 
 --replay             commands # times.  For example, if -c specifies
                      a file of 2 commands:

                        command1
                        command2

                      and -r = 2 and -R = 2, the executed commands are:

                        command1 [R1r1]
                        command1 [R1r2]
                        command2 [R1r1]
                        command2 [R1r2]
                        command1 [R2r1]
                        command1 [R2r2]
                        command2 [R2r1]
                        command2 [R2r2]

                      DEFAULT:  (or not specified) 1.
                      Use '0' for infinite.
                      Use 'Ctrl-C' to stop infinite.

 -T [-T [...]]        If connecting to a terminal server (reverse 
 --terminal           telnet), a carriage return may be required 
                      to activate the console and produce the login 
                      prompts.  Each -T issues a CR.

 -u username          Username, if required for Telnet login.
 --username

 -w                   Log output to file "<host>.log".  If output 
 --write              file exists, the date is appended to the end of 
                      the filename so as to not overwrite.
   -w -w              Show output on STDOUT.
   -w -w -w           Log output to file "<host>.log" and launch TAIL 
                      program (if found in path) to display log file 
                      real-time.
   -w -w -w -w        Dump input/output hex log to file 
                      "<host>-dump.log".

=head2 PING MODE (DEFAULT)

To activate B<Ping Mode>, do not use any of the options to activate the 
above modes.

 -i # | range         The ports to Ping.  Only valid if -m is NOT 
 --interface          ICMP.  Range can be provided with comma (,) 
                      for individual ports and dash (-) for all 
                      inclusive range.  For example:

                        21-23,80

                      Pings ports 21 22 23 80.

 -m protcol           The protocol to use.
 --metric             Values are:
                        tcp  (DEFAULT)
                        udp
                        icmp (Requires admin privilege)

 -r #                 Repeat each -i interface # times.
 --repeat             DEFAULT:  (or not specified) 1.
                      Use '0' for infinite.
                      Use 'Ctrl-C' to stop infinite.

 -R #                 Sequence replay.  Replay the series of -i 
 --replay             interfaces # times.  For example, if -i = 23,80
                      and -r = 2 and -R = 2, the port Ping sequence is:

                        23 [R1r1]
                        23 [R1r2]
                        80 [R1r1]
                        80 [R1r2]
                        23 [R2r1]
                        23 [R2r2]
                        80 [R2r1]
                        80 [R2r2]

                      DEFAULT:  (or not specified) 1.
                      Use '0' for infinite.
                      Use 'Ctrl-C' to stop infinite.

=head2 GENERAL

 --help               Print Options and Arguments.
 --man                Print complete man page.
 --versions           Print Modules, Perl, OS, Program info.

=head1 EXAMPLES

This script provides many functions and some are mutually exclusive.
Order of operations is:

    -P                 = Password mode
    -s                 = SNMP mode
      -t               =   TFTP
      -l               =   Line
      -i               =   Interface
      -I               =   Inventory
      -w               =   write memory
      (No sub-options) =   SNMP system MIB
    -p                 = Telnet mode
    (No above options) = Ping mode

The following examples provide some guidance as to the many features of 
this script; however, all possible uses are not provided.

=head2 Password Decrypt

Assume router.confg is a Cisco router configuration file.  Simply use 
the command:

  crapps -P router.confg

and all type 7 passwords in the router.confg file will be decoded.  If 
you have a single password, you can enter that at the command line.  
For example:

  crapps -P 030752180500

To attempt to crack MD5 (enable secret) passwords, use a 'dictionary' 
word or file containing 1 word per line.

  crapps -P $1$abcd$Qp3k66V2xaerPx1TbfmC2. -d dictfile.txt

=head2 Password Encrypt

You can encrypt to type 7 passwords by using the -e argument and the 
word you want to encrypt as the -P argument.  For example:

  crapps -P EncryptMe -e

Outputs all possible Cisco type 7 encryption strings for the clear
text "EncryptMe".

To generate MD5 (enable secret) passwords, use a 'salt' as such:

  crapps -P EncryptMe -e -s abcd

=head2 SNMP TFTP PUT

To upload a configuration file to a Cisco IOS devices, you'll need the
SNMP Read/Write community string (rw_comm) in the following examples 
and a configuration file in the TFTP server root directory.  Use the 
following command:

  crapps -s rw_comm -c file.confg host -t

The following example includes a C<wr mem> after and if the config is 
successful.  Also, the configuration file is in a subdirectory of the 
TFTP server, which is running on 192.168.0.1:

  crapps -s rw_comm -c subdir/file.confg host -w -t 192.168.0.1

=head2 SNMP TFTP GET

To download a configuration file from a Cisco IOS devices, you'll need 
the SNMP Read/Write community string.  You'll also need a TFTP server 
able to receive files.  Use the following command:

  crapps -s rw_comm host -t

You can also specify an alternate TFTP server; for example: 10.1.1.1,  
by the -t option.  If the Cisco device is running CatOS, provide the 
CatOS flag:

  crapps -s rw_comm host -C -t 10.1.1.1

=head2 SNMP Lines

To get a list of the current line status on the IOS device, use the 
following command with the SNMP Read Only or Read/Write community
string:

  crapps -s rw_comm host -l

To clear a line, simply provide the line number from the above command's
output.  For example, to clear line 2 and 4, use:

  crapps -s rw_comm host -l 2,4

To send a message to all terminal lines, use:

  crapps -s rw_comm host -l --message "message text"

=head2 SNMP Interface Utilization

To get a list of the current IfIndexes on the IOS device, use the 
following command with the SNMP Read Only or Read/Write community 
string:

  crapps -s rw_comm host -i

From the returned list, you can monitor the utilization on a specific 
interface by using the IfIndex as an input to the -i option.  For 
example, the interface with IfIndex '8' is monitored with the following 
command:

  crapps -s rw_comm host -i 8

CPU can be monitored with the following command:

  crapps -s rw_comm host -i 0

Memory can be monitored with the following command:

  crapps -s rw_comm host -i 00

=head3 EXTRA:  Graph Utilization

An external graphing program such as GnuPlot can be used to graph in real-time 
the utilization returned from this script.  For example, to graph the 
output utilization on an interface with IfIndex 3 at a 10 second polling 
interval, use (note the following lines should all be typed on the same 
command line before pressing "Enter/Return"):

=head4 Windows

  crapps -s rw_comm host -i 3 -W 10 -r 0 --noheader -F "" |
  perl -ane "$|=1;print\"$F[3]\n\""

=head4 Unix

  crapps -s rw_comm host -i 3 -W 10 -r 0 --noheader -F "" |
  perl -ane '$|=1;print"$F[3]\n"'

Following the above command, use a pipe (|) to redirect to the plotting 
program or wrapper for the plotting program.

The '$F[3]' refers to the column in the output.  To graph something else, 
use the numbers as below, for example:

  Timestamp                  In  In %            Out Out %
  --------------------------------------------------------
  20090916191430           0.00  0.00           0.00  0.00
       [0]                 [1]   [2]            [3]   [4]

Note, the 10 second polling interval is the minimum recommended interval 
due to the fidelity of the Cisco SNMP MIB updates.

=head2 SNMP Proxy Ping

A proxy ping - a ping from a remote router to a supplied destination - 
can be performed.  The following command sends a proxy ping from host 
C<source> to host C<destination> 5 times with 3 pings per time, with a 
2 second interval between each time:

  crapps -s rw_comm source -i destination -R 5 -r 3 -W 2

Append C<-c 200> to the above command to use a packet size of 200 
bytes.

=head2 SNMP Write Memory

To force the host to save its current configuration to memory, use the
following command:

  crapps -s rw_comm -w host

=head2 Telnet Example

Simple Telnet can be done with the following command, assuming you know 
the password:

  crapps -p password host

If you need to do privledged commands, use the -e option for enable 
password.  Also, it's probably good to either save the transcript file
or view it real time if you have a TAIL program installed.  Do this with 
the -w option.

  crapps -p password -e enab_pass host -w

If you'd like to execute the same series of several commands on several 
routers, use a command file and a host file:

  crapps -p password -e enab_pass -c cmdfile.txt hosts.txt -w

=head2 Ping Example

To simply Ping a host, use the following:

  crapps host

This will send an echo request to the host's TCP echo port.  To specify 
a different protocol (other than the default TCP), use -m, for example:

  crapps -m icmp host -r 4

The above command sends 4 ICMP echo requests to the host.  Note that 
ICMP requires administrator privledge.

=head1 LICENSE

This software is released under the same terms as Perl itself.
If you don't know what that means visit L<http://perl.com/>.

=head1 AUTHOR

Copyright (C) Michael Vincent 2008-2015

L<http://www.VinsWorld.com>

All rights reserved

=cut
