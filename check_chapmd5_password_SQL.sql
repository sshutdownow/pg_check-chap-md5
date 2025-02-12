-- DROP FUNCTION check_chapmd5_password(text, text, text);

CREATE OR REPLACE FUNCTION check_chapmd5_password(chap_password text, chap_challenge text, clear_password text)
 RETURNS boolean
 LANGUAGE sql
 IMMUTABLE STRICT
AS $function$
  SELECT md5(substr(decode(chap_password, 'hex'), 1, 1 ) || clear_password::bytea || decode(chap_challenge, 'hex'))::uuid = encode(substr(decode(chap_password, 'hex'), 2), 'hex')::uuid;
$function$;

-- SELECT check_chapmd5_password('00777f2a3f6a2e661947b520c6777e0b25', '45c915d82d67257209048420a31292d3', 'password')
