#
# (c) Jan Gehring <jan.gehring@gmail.com>
# 
# vim: set ts=3 sw=3 tw=0:
# vim: set expandtab:

package Rex::Virtualization::LibVirt::hypervisor;

use strict;
use warnings;

use Rex::Logger;
use Rex::Commands::Run;

use XML::Simple;

use Data::Dumper;

sub execute {
   my ($class, $arg1, %opt) = @_;

   unless($arg1) {
      die("You have to define the vm name!");
   }

   my ($xml, @dominfo, $dom);
   if ($arg1 eq 'capabilities') {
      my $cmd = "virsh capabilities";
      if (defined($opt{type})) {
         #known and tested : qemu:///system , lxc:///
         #but they do give odd values
         $cmd = "virsh --connect $opt{type} capabilities";
      }
      @dominfo = run $cmd;
      if($? != 0) {
         # can't die here, this is what happens if you ask a host 
         #that doesn't have that libvirt driver (type) installed
         #or has no libvirt at all
         Rex::Logger::info("Error running virsh dominfo ($cmd)");
         return {};
      }

      my $xs = XML::Simple->new();
      $xml = $xs->XMLin(join("",@dominfo), KeepRoot => 1, KeyAttr => 1, ForceContent => 1);
   } else {
      Rex::Logger::debug("Unknown action $arg1");
      die("Unknown action $arg1");
   }
  
   my %ret = ();
   my ($k, $v);

   if(ref($xml->{'capabilities'}->{'guest'}) ne "ARRAY") {
      $xml->{'capabilities'}->{'guest'} = [ $xml->{'capabilities'}->{'guest'} ];
   }

   for my $line (@{$xml->{'capabilities'}->{'guest'}}) {

      $ret{$line->{'arch'}->{'name'}} = 'true'        
         if defined($line->{'arch'}->{'name'});

      #TODO: can't do this - one host can have lots of emulators
      $ret{'emulator'} = $line->{'arch'}->{'emulator'}->{'content'}
         if defined($line->{'arch'}->{'emulator'}->{'content'});

      $ret{'loader'} = $line->{'arch'}->{'loader'}->{'content'}
         if defined($line->{'arch'}->{'loader'}->{'content'});

      $ret{$line->{'os_type'}->{'content'}} = 'true'
         if defined($line->{'os_type'}->{'content'});

      if(defined($line->{'arch'}->{'domain'}) && ref($line->{'arch'}->{'domain'}) eq 'ARRAY') {
         for (@{$line->{'arch'}->{'domain'}}) {
            $ret{$_->{'type'}} = 'true';
         }
      } else {
         $ret{$line->{'arch'}->{'domain'}->{'type'}} = 'true'    
            if defined($line->{'arch'}->{'domain'}->{'type'});
      }
   }

   return \%ret;

}

1;
