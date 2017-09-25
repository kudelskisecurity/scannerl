%%% SSL helper
%%%
%%% refs:
%%%   https://tools.ietf.org/search/rfc6125#section-6.4.3
%%%   http://erlang.org/doc/man/ssl.html#connect-3
%%%

-module(utils_ssl).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([
    get_ca_path/0,
    get_opts_verify/1,
    get_opts_noverify/0
  ]).
-include_lib("public_key/include/public_key.hrl").

-define(SSLPATH_DEBIAN, "/etc/ssl/certs/ca-certificates.crt").
-define(SSLDEPTH, 2).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_ca_path() ->
  ?SSLPATH_DEBIAN.

%% to use like
%%    ?COPTS ++ get_opts_verify([])
get_opts_verify([]) ->
  % do not check dns
  [
    {cacertfile, get_ca_path()},
    {verify, verify_peer},
    {depth, ?SSLDEPTH}
  ];
get_opts_verify(Domain) ->
  % check everything as well as the domain matching
  [
    {cacertfile, get_ca_path()},
    {verify, verify_peer},
    {depth, ?SSLDEPTH},
    {verify_fun, {fun check_cert/3, [Domain]}}
  ].
get_opts_noverify() ->
  % do not verify anything about the certificate
  [].


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% function to use as "verify_fun" for SSL
%% will:
%%  - check for validity
%%  - check for expired
%%  - check for bad extension
%%  - check for hostname matching
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
check_cert(_,{bad_cert, _} = Reason, _) ->
  {fail, Reason};
check_cert(_,{extension, _}, UserState) ->
  {unknown, UserState};
check_cert(_, valid, UserState) ->
  {valid, UserState};
check_cert(Cert, valid_peer, UserState) ->
  C = Cert#'OTPCertificate'.tbsCertificate,
  Ext = C#'OTPTBSCertificate'.extensions,
  {value, {_,_,_, DNSs}} = lists:keysearch(?'id-ce-subjectAltName', #'Extension'.extnID, Ext),
  [Ori] = UserState,
  DNSList = [Hostname || {_, Hostname} <- DNSs],
  Comp = dnsnames_match_dns(Ori, DNSList),
  case Comp of
    true ->
      {valid, UserState};
    false ->
      {fail, bad_cert}
  end.

% match the queried dns against a list
% of DNSs provided in the certificate
dnsnames_match_dns(_Queried, []) ->
  false;
dnsnames_match_dns(Queried, [H|T]) ->
  Res = dnsname_match_dns(Queried, H),
  case Res of
    true ->
      true;
    false ->
      dnsnames_match_dns(Queried, T)
  end.

% match the queried dns against a specific
% provided DNS in the certificate
dnsname_match_dns(Queried, Presented) ->
  Ql = lists:reverse(string:tokens(Queried, ".")),
  Pl = lists:reverse(string:tokens(Presented, ".")),
  match_dns(Ql, Pl).

% match each DNS part in reverse
% for two dns (left is the queried dns,
% and right the certificate provided one).
match_dns([], []) ->
  true;
match_dns([], _) ->
  false;
match_dns(_, []) ->
  false;
match_dns([_H1|T1], ["*"|_T2]) ->
  match_dns(T1, []);
match_dns([H1|T1], [H2|T2]) ->
  case string:str(H2, "*") == 0 of
    true ->
      case string:equal(H1, H2) of
        false ->
          false;
        true ->
          match_dns(T1, T2)
      end;
    false ->
      match_wildcard(H1, H2)
  end.

% matching when wildcard is provided
match_wildcard(Against, Wild) ->
  Idx = string:str(Wild, "*"),
  case Idx == 0 of
    true ->
      false;
    false ->
      Left = string:sub_string(Wild, 1, Idx-1),
      Right = string:sub_string(Wild, Idx+1),
      match_wildcard(Against, Left, Right)
  end.
match_wildcard(Against, Left, Right) ->
  Ll = length(Left),
  Lr = length(Right),
  Aleft = string:left(Against, Ll),
  Aright = string:right(Against, Lr),
  string:equal(Aleft, Left) and string:equal(Aright, Right).

