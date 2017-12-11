%%% Modbus fingerprinting module
%%% returns data from the modbus response
%%%
%%% Output:
%%%   true: it is modbus
%%%   false: it is modbus but a protocol error is returned
%%%

-module(fp_modbus).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-author("David Rossier - david.rossier@kudelskisecurity.com").

-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

%% our record for this fingerprint
-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 502). % Modbus port
-define(TYPE, tcp). % transport type
-define(MAXPKT, 4). % max packet expected
-define(READ_DEVICE_ID_FUNCTION_CODE, 16#2b).
-define(MAX_ERROR, 16#0B).
-define(PAYLOAD, [16#00, % transaction ID
                  16#00,
                  16#00, % protocol
                  16#00,
                  16#00, % length
                  16#05,
                  16#00, % unit ID
                  ?READ_DEVICE_ID_FUNCTION_CODE, % function code, Read device identification
                  16#0e, % subcode
                  16#01, % read device ID code
                  16#00 % object id
                 ]).
-define(DESCRIPTION, "TCP/502: Modbus identification").
-define(ARGUMENTS, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% public API to get {port, timeout}
get_default_args() ->
  #args{module=?MODULE, type=?TYPE, port=?PORT,
    timeout=?TIMEOUT, maxpkt=?MAXPKT}.

get_description() ->
  ?DESCRIPTION.

get_arguments() ->
  ?ARGUMENTS.

% callback
callback_next_step(Args) when Args#args.moddata == undefined ->
  % first packet
  {continue, Args#args.maxpkt, ?PAYLOAD, true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  % no packet received
  debug(Args, "no packet received"),
  {result, {{error, up}, timeout}};
callback_next_step(Args) ->
  debug(Args, "packet received"),
  parse_payload(Args, binary_to_list(Args#args.datarcv)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
    {Args#args.target, Args#args.id}, Args#args.debugval).

parse_payload(_Args, Data) ->
  LowerData = string:to_lower(utils_fp:stringify(Data)),

  List = [
      {"ftp", {error, ftp} },
      {"200 ", {error, ftp} },
      {"250 ", {error, ftp} },
      {"300 ", {error, ftp} },
      {"printer", {error, printer} },
      {"telnet", {error, telnet} },
      {"firewall", {error, firewall} },
      {"html", {error, http} },
      {"550 ", {error, ftp} },
      {"finger", {error, finger}},
      {"http", {error, http} },
      {"ssh", {error, ssh} },
      {"login", {error, finger}},
      {"user", {error, finger}},
      {"email", {error, finger}}
    ],
  Result = check_list(List, LowerData),
  Final = case Result of
    {error, Reason} ->
      {{error,up}, Reason};
    probable ->
      parse_modbus(Data)
  end,
  {result, Final}.

% first check if does not contain other
% specific recognized patterns
check_list([], _Data) ->
  probable;
check_list([H|T], Data) ->
  {Check, Result} = H,
  case string:str(Data, Check) > 0 of
    true ->
      Result;
    false ->
      check_list(T, Data)
  end.

% then parse the modbus payload
parse_modbus(Data) ->
  BinaryData = list_to_binary(Data),
  case BinaryData of
    <<
      _TrId:16,
      _Protocol:16,
      0,
      _Length:8,
      _UnitId,
      FctCode,
      _SubCode,
      _ReadDeviceCode,
      _OID/binary
    >> ->
      check_function_code(FctCode);
    <<
      _TrId:16,
      _Protocol:16,
      Len:8,
      _Length:Len/binary-unit:8,
      _UnitId,
      FctCode,
      _SubCode,
      _ReadDeviceCode,
      _OID/binary
    >> ->
      check_function_code(FctCode);
    _ ->
      {{error, up}, unexpected_data}
  end.

% check modbus fonction code
check_function_code(?READ_DEVICE_ID_FUNCTION_CODE) ->
  {{ok,result}, true};
check_function_code(Code) when Code =< ?MAX_ERROR ->
  {{ok,result}, false};
check_function_code(_) ->
  {{error,up}, unexpected_data}.

