%%% helper function for targets
%%%
%%% a tgt can be:
%%%   - a single IP  (ex: 192.168.0.1)
%%%   - a cidr range (ex: 10.0.0.0/24)
%%%   - a string (ex: www.myip.ch)
%%%

-module(tgt).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

% exported function
-export([get_tgts/1, minrange/2]).
-export([parse_ip/2, parse_domain/2]).

-record(tgt, {
    ip,
    prefix,
    port=undefined
}).

-define(log2denom, 0.69314718055994529).
-define(MINCIDR, 24).
-define(PORTSEP, ":").
-define(RANGESEP, "/").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% convert
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
ip_to_int({A, B, C, D}) ->
  (A*16777216)+(B*65536)+(C*256)+D.

bin_to_ip(Bin) ->
  list_to_tuple(binary_to_list(Bin)).

int_to_ip(Int) ->
  {Int bsr 24, (Int band 16777215) bsr 16, (Int band 65535) bsr 8, Int band 255}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% cidr/ip bits op
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% returns the integer value of the masked IP
get_base(Tgt) ->
  Ip = Tgt#tgt.ip,
  Prefix = Tgt#tgt.prefix,
  Mask = bnot(1 bsl Prefix),
  Int = ip_to_int(Ip),
  (Int bsr (32-Prefix)) band Mask.

% mask an ip
% @Ip: a valid ip addr
% @Prefix: an int
% returns a integer representation of the IP
mask_ip(Ip, Prefix) ->
  Inv = 32 - Prefix,
  Tmp = #tgt{ip=Ip, prefix=Prefix},
  Val = get_base(Tmp),
  (Val bsl (Inv)) bor (0 bsl (Inv)).

% extend base integer with zeros
complete_ip(Tgt, Val) ->
  Base = get_base(Tgt),
  Prefix = Tgt#tgt.prefix,
  Inv = 32 - Prefix - 1,
  Lip = bin_to_ip(<<Base:Prefix, Val:1, 0:Inv>>),
  #tgt{ip=Lip,prefix=(Prefix+1),port=Tgt#tgt.port}.

% get lower range
lower(Tgt) ->
  complete_ip(Tgt, 0).

% get upper range
higher(Tgt) ->
  complete_ip(Tgt, 1).
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% utilities
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
list_divide([], Agg) ->
  Agg;
list_divide([H|T], Agg) ->
  list_divide(T, Agg ++ divide(H)).

rec_divide(0, Acc) ->
  Acc;
  %list_divide(Acc, []);
rec_divide(Cnt, Acc) ->
  rec_divide(Cnt-1, list_divide(Acc, [])).

% divide a tgt in two if possible
divide(Tgt = #tgt{ip=_,prefix=Prefix,port=_}) when Prefix > 31 ->
  [Tgt];
divide(Tgt = #tgt{ip=_,prefix=Prefix,port=_}) when Prefix < 0 ->
  [Tgt];
divide(Tgt = #tgt{ip=_,prefix=_,port=_}) ->
  [lower(Tgt), higher(Tgt)];
divide(_) ->
  [].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% range sub-division
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% subdivide range into /24
minrange(Tgt=#tgt{ip=_,prefix=Prefix,port=_}, Minrange) when Prefix < Minrange ->
  % calculate how many times we need to divide
  Div = Minrange - Prefix,
  rec_divide(Div, [Tgt]);
minrange(Tgt, _) ->
  [Tgt].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% parse and count
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% parse prefix in the form /<prefix>
parse_prefix([]) ->
  32;
parse_prefix(String) ->
  try
    list_to_integer(String)
  catch
    error:badarg ->
      32
  end.

% parse the port part if any in the form :<port>
parse_port([], Defport) ->
  Defport;
parse_port([Val], Defport) ->
  try
    list_to_integer(Val)
  catch
    error:badarg ->
      Defport
  end;
parse_port(Val, Defport) ->
  try
    list_to_integer(Val)
  catch
    error:badarg ->
      Defport
  end.

% parse a domain and return a tgt record
parse_domain(String, Defport) ->
  E = string:tokens(String, ?PORTSEP),
  #tgt{ip=hd(E), prefix=32, port=parse_port(tl(E), Defport)}.

% returns {Prefix, Port}
parse_ip_more([], Defport) ->
  {32, Defport};
parse_ip_more(?RANGESEP ++ Rest, Defport) ->
  {parse_prefix(Rest), Defport};
parse_ip_more(?PORTSEP ++ Rest, Defport) ->
  E = string:tokens(Rest, ?RANGESEP),
  Prefix = parse_prefix(tl(E)),
  {Prefix, parse_port(hd(E), Defport)}.

% parse an ip and return a tgt record
% format: 192.168.0.1:8080/32
parse_ip(String, Defport) ->
  try
    {A, Rest1} = string:to_integer(String),
    {B, Rest2} = string:to_integer(tl(Rest1)),
    {C, Rest3} = string:to_integer(tl(Rest2)),
    {D, Rest4} = string:to_integer(tl(Rest3)),
    {Prefix, Port} = parse_ip_more(Rest4, Defport),
    {ok, #tgt{ip=int_to_ip(mask_ip({A,B,C,D}, Prefix)), prefix=Prefix, port=Port}}
  of
    {ok, Res} -> {ok, Res}
  catch
    _Exception:Reason -> {error, Reason}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% explode range
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% get a list of all target in a tgt record
get_tgts(#tgt{ip=Ip,prefix=32,port=Port}) ->
  [{Ip,Port}];
get_tgts(#tgt{ip=Ip,prefix=Prefix,port=Port}) ->
  Inv = 32 - Prefix,
  Max = round(math:pow(2, Inv)) - 1,
  Base = ip_to_int(Ip),
  [{int_to_ip(Base+Inc),Port} || Inc <- lists:seq(0, Max)].

