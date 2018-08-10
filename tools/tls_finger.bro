module TlsFingerprint;

## This script comes from https://www.securityartwork.es/2017/02/02/tls-client-fingerprinting-with-bro/

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        tls_version: string &log;
        ciphers: vector of string &log;
    };
}

event bro_init() &priority=5
{
    Log::create_stream(TlsFingerprint::LOG, [$columns=Info, $path="tls_finger"]);
}

event ssl_client_hello (c: connection,
    version: count,
    possible_ts: time,
    client_random: string,
    session_id: string,
    ciphers: index_vec)
{
    local ciphers_str: vector of string;
    local rec: TlsFingerprint::Info;

    for (i in ciphers) {
        ciphers_str[i] = SSL::cipher_desc[ciphers[i]];
    }

    rec$ts = network_time();
    rec$uid = c$uid;
    rec$id = c$id;
    rec$tls_version = SSL::version_strings[version];
    #rec$ciphers = join_string_vec(ciphers_str, ",");
    rec$ciphers = ciphers_str;

    Log::write(TlsFingerprint::LOG, rec);
}