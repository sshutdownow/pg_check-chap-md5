-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION check_chapmd5_password" to load this file. \quit

CREATE FUNCTION check_chapmd5_password(chap_password text, chap_challenge text, clear_password text) RETURNS boolean
    AS '$libdir/check_chapmd5_password', 'check_chapmd5_password'
    LANGUAGE C IMMUTABLE STRICT;
