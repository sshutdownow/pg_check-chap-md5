CREATE OR REPLACE FUNCTION checkchappassword(text, text, text)
  RETURNS boolean AS
$BODY$
use Digest::MD5; 
my $chap_password = pack("H*", $_[0]); 
my $chap_challenge = pack("H*", $_[1]);
my $md5 = new Digest::MD5; 
$md5->reset; 
$md5->add(substr($chap_password, 0, 1)); 
$md5->add($_[2]);
$md5->add($chap_challenge);
return $md5->digest() eq substr($chap_password, 1)?"TRUE":"FALSE";
$BODY$
  LANGUAGE plperlu STRICT
  COST 100;
