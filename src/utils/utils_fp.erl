%% utils for the fingerprinting modules

-module(utils_fp).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-include_lib("kernel/include/inet.hrl").

-export([lookup/2, lookup/3, int_to_ip/1, cidr_contains/2,
  timestamp_string/0, timestamp_epoch/0,
  lookupwww/2, list_to_hex/1, int_to_hex/1,
  is_valid_integer/1, stringify/1, is_valid_string/1]).

-define(DNSERR, "dns_").
-define(NXPRE, "www.").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% lookup domain name
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% if it's an IP, simply return it
lookup({_,_,_,_}=Ip, _Timeout) ->
  {ok, Ip};
% otherwise, look it up and take the first response if any
lookup(Domain, Timeout) ->
  try
    inet_db:add_resolv("/etc/resolv.conf"),
    case inet_res:getbyname(Domain ++ ".", a, Timeout) of
      {ok, Hostent} ->
        Addr = hd(Hostent#hostent.h_addr_list),
        {ok, Addr};
      {error, Reason} ->
        En = ?DNSERR ++ atom_to_list(Reason),
        {error, list_to_atom(En)}
    end
  catch
    _:_ ->
      {error, list_to_atom(?DNSERR ++ "exception")}
  end.

lookupwww(Domain, Timeout) ->
  case lookup(Domain, Timeout) of
    {ok, Addr} ->
      {ok, Addr};
    {error, dns_nxdomain} ->
      case Domain of
        ?NXPRE ++ _ ->
          {error, dns_nxdomain};
        _ ->
          lookup(?NXPRE ++ Domain, Timeout)
      end;
    {error, Reason} ->
      {error, Reason}
  end.

lookup(Domain, Timeout, Www) when Www == true ->
  lookupwww(Domain, Timeout);
lookup(Domain, Timeout, _) ->
  lookup(Domain, Timeout).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% IP utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% transform int to IP
int_to_ip(Int) ->
  {Int bsr 24, (Int band 16777215) bsr 16, (Int band 65535) bsr 8, Int band 255}.

% returns true if second argument is contained withing
% low and top addresses
cidr_contains({{A, B, C, D}, {E, F, G, H}}, {W, X, Y, Z}) ->
    (((W >= A) andalso (W =< E)) andalso
     ((X >= B) andalso (X =< F)) andalso
     ((Y >= C) andalso (Y =< G)) andalso
     ((A >= D) andalso (Z =< H)));
cidr_contains(_, _) ->
  false.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% return timestamp YYYYmmddHHMMSS
timestamp_string() ->
  Now = calendar:local_time(),
  {{Y,M,D}, {H,Min,S}} = Now,
  Str = io_lib:fwrite("~w~2..0w~2..0w~2..0w~2..0w~2..0w", [Y, M, D, H, Min, S]),
  lists:flatten(Str).

% return epoch
timestamp_epoch() ->
  {M, S, _} = os:timestamp(),
  (M*1000000)+S.

% hexlify binary
list_to_hex(L) ->
       lists:map(fun(X) -> int_to_hex(X) end, L).
int_to_hex(N) when N < 256 ->
       [hex(N div 16), hex(N rem 16)].
hex(N) when N < 10 ->
       $0+N;
hex(N) when N >= 10, N < 16 ->
       $a + (N-10).

% is a valid int
% well this suits our need but might not be very ethical
is_valid_integer(nil) ->
  true;
is_valid_integer(Val) ->
  Int = (catch erlang:list_to_integer(Val)),
  is_number(Int).

% is a valid string
is_valid_string(List) when is_list(List) ->
  lists:all(fun isprint/1, List);
is_valid_string(_) ->
  false.

isprint(X) when X >= 32, X < 127 -> true;
isprint(_) -> false.

% Stringify
% removes all unreadable char so that
% the list is readable as a result
% expects a list (not a binary) (use binary_to_list)
stringify(TB) ->
  stringify(TB, []).
stringify([], Acc) ->
  Acc;
stringify([H|T], Acc) ->
  case isprint(H) of
    true ->
      stringify(T, Acc ++ [H]);
    false ->
      stringify(T, Acc)
  end.

