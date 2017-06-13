#!/usr/local/bin/perl
# ~GG~
use IO::Socket;
use IO::Socket::SSL;
use IO::Select;

# Multithreading style
use threads;
use threads::shared;
use Thread::Queue;

# For coloring report
use Term::ANSIColor qw(:constants);
# CLEAR, RESET, BOLD, DARK, UNDERLINE, 
# UNDERSCORE, BLINK, REVERSE, CONCEALED, 
# BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, 
# CYAN, WHITE, ON_BLACK, ON_RED, ON_GREEN, 
# ON_YELLOW, ON_BLUE, ON_MAGENTA, ON_CYAN, and ON_WHITE

# Good coder always use this
use strict;

# Global declaration
my $worker = Thread::Queue->new();
my %urlhash : shared;
my $domain : shared;

# We hate this words
my $blist = "(sourcecodeonline\.com|paypal\.com|linked\.in|amazon\.com|php\.net|r0\.ru|jenkins-ci\.|eclipse\.org|wikipedia\.|travis-ci\.com|gitlab\.com|stackoverflow\.com|tutorialspoint\.com|\/\/t\.co|google|youtube|jsuol\.com|\.radio\.uol\.|b\.uol\.|barra\.uol\.|whowhere\.|hotbot\.|amesville\.|lycos|lygo\.|orkut\.|schema\.|blogger\.|\.bing\.|w3\.|yahoo\.|yimg\.|creativecommons\.org|ndj6p3asftxboa7j\.|\.torproject\.org|\.lygo\.com|\.apache\.org|\.hostname\.|document\.|live\.|microsoft\.|ask\.|shifen\.com|answers\.|analytics\.|googleadservices\.|sapo\.pt|favicon\.|blogspot\.|wordpress\.|\.css|scripts\.js|jquery-1\.|dmoz\.|gigablast\.|aol\.|\.macromedia\.com|\.sitepoint\.|yandex\.|www\.tor2web\.org|\.securityfocus\.com|\.Bootstrap\.|\.metasploit\.com|aolcdn\.|altavista\.|clusty\.|teoma\.|baiducontent\.com|wisenut\.|a9\.|uolhost\.|w3schools\.|msn\.|baidu\.|hao123\.|shifen\.|procog\.|facebook\.|instagram\.|twitter\.|flickr\.|\.adobe\.com|oficinadanet\.|elephantjmjqepsw\.|\.shodan\.io|kbhpodhnfxl3clb4|\.scanalert\.com|\.prototype\.|feedback\.core|4shared\.|\.KeyCodeTab|\.style\.|www\/cache\/i1|\.className\.|=n\.|a\.Ke|Y\.config|\.goodsearch\.com|style\.top|n\.Img|n\.canvas\.|t\.search|Y\.Search\.|a\.href|a\.currentStyle|a\.style|yastatic\.|\.oth\.net|\.hotbot\.com|\.zhongsou\.com|ezilon\.com|\.example\.com|location\.href|\.navigation\.|\.bingj\.com|Y\.Mobile\.|srpcache?p|stackoverflow\.|shifen\.|baidu\.|baiducontent\.|gstatic\.|php\.net|wikipedia\.|webcache\.|inurl\.|naver\.|navercorp\.|windows\.|window\.|\.devmedia|imasters\.|\.inspcloud\.com|\.lycos\.com|\.scorecardresearch\.com|\.target\.|JQuery\.min|Element\.location\.|exploit-db|packetstormsecurity\.|1337day|owasp|\.sun\.com|mobile10\.dtd|onabort=function|inurl\.com\.br|purl\.org|\.dartsearch\.net|r\.cb|\.classList\.|\.pt_BR\.|github|microsofttranslator\.com|\.compete\.com|\.sogou\.com|gmail\.|blackle\.com|boorow\.com|gravatar\.com|sourceforge\.|\.mozilla\.org|feedburner\.|opera\.com|pinterest\.)";
my $blist_file = "(\.css|\.jpg|\.gif|\.png|\.jpeg|\.pdf|\.txt|\.doc|\.svg|\.xls|\.js|\.ico|\.xml|\.swf|\.mp3|\.flv|\.mp4|\.mpg|\.mpeg|\.asp|\.wmv|\.wav|\.mov|\.3gp|\.mkv|\.tar\.|\.zip|\.rar|\.ppt)";

# Hello thanks for sharing
sub recursiveget{
	$urlhash{$_[0]}++;
	my $target = $_[0];
	my $https = 0;
	my $data = "";
	my $host = $target;
	$host  =~ s/https:\/\///;
	$host  =~ s/http:\/\///;
	my $page = $host;
	$host  =~ s/href=\"?http:\/\///;
	$host  =~ s/([-a-zA-Z0-9\.]+)\/.*/$1/;
	$page =~ s/$host//;
	if ( $page eq "" ) { $page = "/"; }
	if($target =~ /^https:/){
		$https = 1;
	}elsif($target =~ /^http:/){
		$https = 0;
	}
	if($https == 1){
		$data = &query_ssl($target);
	}else{
		$data = &query($target);
	}	
	if($data=~ m/HTTP\/1\.\d +30\d/i && $data=~ m/Location: (.*)\r\n/i){
		my $redir = ceklink($1, $host, $page, $https);		
		print CYAN, "Redirect: $target -> $redir\n", RESET;
	  return if $urlhash{$redir}++;
	  &recursiveget($redir);
	}
	elsif($data !~ m/HTTP\/1\.\d +200/i){
		if($data =~ m/HTTP\/1\.\d +(\d\d\d).*/i){
			print RED, "Error: $target ".$1."\n", RESET;
	    return;
		}
	}
	else{
		while($data=~ m/href=["']([^"']+)["']/ig ){
			if(($1 !~ m/(mailto:|irc:|^#|javascript)|$blist|$blist_file/i)){
				my $newurl = ceklink($1, $host, $page, $https);
				next if $urlhash{$newurl}++;
				next if $newurl !~ /$domain/;
				if(($newurl =~ /\?/) && ($newurl =~ /\=/)){
					print BOLD GREEN, "[+] Possible target: $newurl\n", RESET;
				}else{
					print WHITE, "Found: $newurl\n", RESET;
				}
				# Add to queue
				$worker->enqueue($newurl);
			}
		}
		print YELLOW, "$target\t\tOK\n", RESET;
	}
}

sub ceklink($){
	my $temp = $_[0];
	my $host = $_[1];
	my $page = $_[2];
	my $https = $_[3];
	my $newurl = "";
	if($temp =~ m/(^http:\/\/|^https:\/\/)/i){
		$newurl = $temp;
	}elsif(($temp =~ m/^\/\//) && ($temp !~ /$host/)){
		if($https == 1){
			$newurl = "https:".$temp;
		}else{
			$newurl = "http:".$temp;
		}
	}elsif($temp =~ m/^\//){
		if($https == 1){
			$newurl = "https://".$host.$temp;
		}else{
			$newurl = "http://".$host.$temp;
		}
	}elsif($temp =~ m/^\.\.\//){
		$temp =~ s/\.\.\///g;
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}elsif($temp =~ m/^\.\//){
		$temp =~ s/\.\///g;
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}elsif($temp =~ m/^\?/){
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}elsif($temp =~ m/^\~/){
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}elsif($temp =~ m/^[a-zA-Z0-9]/){
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}elsif($temp =~ m/^\s\//){
		$temp =~ s/\s//;
		if($https == 1){
			$newurl = "https://".$host.$temp;
		}else{
			$newurl = "http://".$host.$temp;
		}
	}elsif($temp =~ m/^\t\//){
		$temp =~ s/\t//;
		if($https == 1){
			$newurl = "https://".$host.$temp;
		}else{
			$newurl = "http://".$host.$temp;
		}
	}elsif($temp =~ m/^\s[a-zA-Z0-9]/){
		$temp =~ s/\s//;
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}elsif($temp =~ m/^\t[a-zA-Z0-9]/){
		$temp =~ s/\t//;
		if($https == 1){
			$newurl = "https://".$host."/".$temp;
		}else{
			$newurl = "http://".$host."/".$temp;
		}
	}else{
		if($https == 1){
			$newurl = "https://".$host.$page.$temp;
		}else{
			$newurl = "http://".$host.$page.$temp;
		}
	}
	# Clean the double slash			
	if($newurl =~ /^https:/){
		$newurl =~ s/https:\/\///;
		$newurl =~ s/\/\/\/\//\//g;
		$newurl =~ s/\/\/\//\//g;
		$newurl =~ s/\/\//\//g;
		$newurl = "https://".$newurl;
	}
	if($newurl =~ /^http:/){
		$newurl =~ s/http:\/\///;
		$newurl =~ s/\/\/\/\//\//g;
		$newurl =~ s/\/\/\//\//g;
		$newurl =~ s/\/\//\//g;
		$newurl = "http://".$newurl;
	}
	$newurl = repairlink($newurl);
	return $newurl;
}

sub repairlink($) {
	my $url = $_[0];
	$url =~ s/&amp;/&/ig;
	$url =~ s/\%252F;/\//ig;
	$url =~ s/\%3a/:/ig;
	$url =~ s/\%2c/,/ig;
	$url =~ s/\%2f/\//ig;
	$url =~ s/\%26/&/ig;
	$url =~ s/\%22/\"/ig;
	$url =~ s/\%5c/\\/ig;
	$url =~ s/\%3d/=/ig;
	$url =~ s/\%3f/\?/ig;
	$url =~ s/\%3b/;/ig;
	return $url;
}


sub doOperation () {
    my $ithread = threads->tid();
    while (my $url = $worker->dequeue()) {
        recursiveget($url);
    }
}

# Query tidak perlu menggunakan LWP untuk compatibilitas
sub query($) {
	my $url = $_[0];
	$url =~ s/http:\/\///;
	my $host  = $url;
	my $query = $url;
	my $page  = "";
	$host  =~ s/href=\"?http:\/\///;
	$host  =~ s/([-a-zA-Z0-9\.]+)\/.*/$1/;
	$query =~ s/$host//;
	if ( $query eq "" ) { $query = "/"; }
	eval {
		my $sock = IO::Socket::INET->new(PeerAddr => "$host", PeerPort => "80", Proto => "tcp") or return;
		my $select = IO::Select->new($sock);
		print $sock "GET $query HTTP/1.0\r\nHost: $host\r\nAccept: */*\r\nUser-Agent: Feedfetcher-Google; (+http://www.google.com/feedfetcher.html)\r\n\r\n";
		my $rc;
		while (1) {
			$! = undef;               
    	if ($select->can_read(7)) {
      	$rc = sysread($sock, $page, 1024*1024, length($page));
      	next if $rc;            
      	last if defined($rc);   
    	}else {
      	$rc = $! ? undef : 1;   
      	last if $rc;            
    	};
    	last;
		}
	};
	return $page;
}

# For https we use ssl socket
sub query_ssl($){
	my $url = $_[0];
	$url =~ s/https:\/\///;
	my $host  = $url;
	my $query = $url;
	my $page  = "";
	$host  =~ s/href=\"?http:\/\///;
	$host  =~ s/([-a-zA-Z0-9\.]+)\/.*/$1/;
	$query =~ s/$host//;
	if ( $query eq "" ) { $query = "/"; }
	eval {
		my $sock = IO::Socket::SSL->new(PeerHost => "$host", PeerPort => "https", SSL_verify_mode => SSL_VERIFY_NONE) or return;
		my $select = IO::Select->new($sock);
		print $sock "GET $query HTTP/1.1\r\nHost: $host\r\nAccept: */*\r\nUser-Agent: Feedfetcher-Google; (+http://www.google.com/feedfetcher.html)\r\n\r\n";
		my $rc;
		while (1) {
			$! = undef;               
    	if ($select->can_read(7)) {
      	$rc = sysread($sock, $page, 1024*1024, length($page));
      	next if $rc;            
      	last if defined($rc);   
    	}else {
      	$rc = $! ? undef : 1;   
      	last if $rc;            
    	};
    	last;
		}
	};
	return $page;
}

sub usage{
	print "Usage: $0 http://target.com/\n";
}

if(!$ARGV[0]){
	usage();
	exit;
}

print RED,"ˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊ\n", RESET;
print YELLOW,"ˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊ\n", RESET;
print GREEN,"ˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊGG-CRAWLERˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊ\n", RESET;
print BLUE,"ˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊ\n", RESET;
print CYAN,"ˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊ\n", RESET;
print MAGENTA,"ˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊˋˏ~ˎˊˋˏGˎˊˋˏGˎˊˋˏ~ˎˊ\n", RESET;

# Push data to queue
$domain = $ARGV[0];
$domain =~ s/https:\/\///;
$domain =~ s/http:\/\///;
$domain =~ s/href=\"?http:\/\///;
$domain =~ s/([-a-zA-Z0-9\.]+)\/.*/$1/;
$domain =~ s/([^\.]*)\.([-a-zA-Z0-9\.]+)/$2/;
recursiveget($ARGV[0]);
# Loop until next year
do{
	print ON_RED, "[".gmtime()."] - ~GG~ crawler started! ~GG~ - [".(scalar $worker->pending())."]", RESET;
	print CLEAR, "\n", RESET;
	my $maxNumberOfParallelJobs = 3;
	my @threads = map threads->create(\&doOperation), 1 .. $maxNumberOfParallelJobs;
	$worker->enqueue((undef) x $maxNumberOfParallelJobs);
	$_->join for @threads;
}while((scalar $worker->pending()) > 0);
print ON_RED, "[".gmtime()."] - ~GG~ crawler finish!! ~GG~ - [".(scalar %urlhash)."]", RESET;
print CLEAR, "\n", RESET;

