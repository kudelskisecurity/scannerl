%%% MySql fingerprint module
%%% returns MySQL version string
%%%
%%% Output:
%%% server version string
%%%

-module(fp_mysql_greeting).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-behavior(fp_module).
-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 3306).    % mysql port
-define(TYPE, tcp).     % transport type
-define(MAXPKT, 1).     % only greeting packet is needed
-define(DESCRIPTION, "TCP/3306: Mysql version identification").
-define(ARGUMENTS, []).

-define(PROTO, 16#0a). % only interested in protocol version 10

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_default_args() ->
  #args{module=?MODULE, type=?TYPE, port=?PORT,
    timeout=?TIMEOUT, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

callback_next_step(Args) when Args#args.moddata == undefined ->
  {continue, Args#args.maxpkt, "", true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  {result, {{error,up}, timeout}};
callback_next_step(Args) ->
  {result, parse_header(Args, Args#args.datarcv)}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% parsing
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% parse the header
parse_header(Args,
  <<
    Pldlen:24/little,  % 3 bytes payload length
    _:8,               % 1 byte sequence id or packet nb
    Pld/binary         % content
  >>) ->
  debug(Args, "parsing header succeeded"),
  case byte_size(Pld) == Pldlen of
    true ->
      parse_content(Args, Pld);
    false ->
      debug(Args, "bad size provided"),
      {{error, up}, unexpected_data}
  end;
parse_header(Args, _) ->
  debug(Args, "parsing header failed"),
  {{error, up}, unexpected_data}.

%% parse the content
parse_content(_Args,
  <<
    ?PROTO:8,     % protocol version
    Rest/binary
  >>) ->
  case find_null(Rest, 1) of
    error ->
      {{error, up}, unexpected_data};
    {Version, _Bin} ->
      {{ok, result}, [binary_to_list(Version)]}
  end;
parse_content(_Args, _) ->
  {{error, up}, unexpected_data}.

%% find null terminated string
find_null(Bin, Pos) ->
  case Bin of
    <<Start:Pos/binary, 0, Rest/binary>> ->
      % found
      {Start, Rest};
    <<Bin:Pos/binary>> ->
      % not found
      error;
    <<_:Pos/binary, _/binary>>=B ->
      % go forward
      find_null(B, Pos+1)
  end.
