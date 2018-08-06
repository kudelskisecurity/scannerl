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
    get_opts_noverify/0,
    get_certif/1,
    upgrade_socket/3
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

% return {ok, Cert} with the certificate from an SSL-enabled socket
% otherwise return {error, Reason} in case of error
get_certif(Socket) ->
  try
    case ssl:peercert(Socket) of
      {error, Reason} ->
        {error, [bad_or_no_certificate, Reason]};
      {ok, Cert} ->
        C = public_key:pkix_decode_cert(Cert, plain),
        D = public_key:pem_entry_encode('Certificate', C),
        E = public_key:pem_encode([D]), {ok, E}
    end
  catch
    %error:{Type, Ex} ->
    %  %io:fwrite("ex: ~n~p~n", [Ex]),
    %  {result, {{error, up}, Type}};
    _Type:Exception ->
      %io:fwrite("Type: ~n~p~n", [Type]),
      %io:fwrite("Exception:~n~p~n", [Exception]),
      {error, [unexpected_data, Exception]}
  end.

%% upgrade a socket with SSL
%% returns {ok, NewSocket} or {error, Reason}
%% Opt can be empty == []
upgrade_socket(Socket, Opt, Timeout) ->
  % first ensure the socket is opened
  case erlang:port_info(Socket) of
    undefined ->
      {error, socket_closed};
    _ ->
      upgrade_socket_to_ssl(Socket, Opt, Timeout)
  end.

%% upgrade socket with SSL
upgrade_socket_to_ssl(Socket, Opt, Timeout) ->
  case ssl:start() of
    ok ->
      % set socket to active false
      inet:setopts(Socket, [{active, false}]),
      % upgrade the socket
      case ssl:connect(Socket, Opt, Timeout) of
        {ok, TLSSocket} ->
          {ok, TLSSocket};
        {ok, TLSSocket, _Ext} ->
          {ok, TLSSocket};
        {error, Reason} ->
          {error, Reason}
      end;
    {error, Reason} ->
      {error, Reason}
  end.
