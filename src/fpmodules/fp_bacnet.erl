%%% bacnet fingerprinting module
%%%
%%% Output:
%%% {{ok,result}, true}
%%%

-module(fp_bacnet).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-author("David Rossier - david.rossier@kudelskisecurity.com").

-behavior(fp_module).
-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

%% our records for this fingerprint
-define(TIMEOUT, 3000). % milli-seconds
-define(PORT, 47808). % bacnet port
-define(TYPE, udp). % transport type
-define(MAXPKT, 2). % max packet expected
-define(BACNETMAGIC, 16#81).
-define(BACNET, [?BACNETMAGIC, % bacnet magic
                 16#0a, % unicast NPDU
                 16#00,16#23, % payload length
                 16#01, % protocol version
                 16#04, % expect a reply
                 16#00, % confirmed-request PDU with flags 0000
                 16#05, % max response size (up to 1476 bytes)
                 16#00, % invoke ID
                 16#0e, % ReadPropertyMultiple
                 16#0c, % open context tag 0
                 16#02,16#3f,16#ff,16#ff, % object identifier (Device)
                 16#1e, % open context tag 1
                 16#09, % open property tag
                 16#4b, % object ID
                 16#09, % new property
                 16#78, % vendor id
                 16#09,16#79, % object
                 16#09,16#2c, % object
                 16#09,16#0c, % object
                 16#09,16#4d, % object
                 16#09,16#46, % object
                 16#09,16#1c, % object
                 16#09, % last tag open
                 16#3a, % location
                 16#1f % close list tag
                ]).
-define(DESCRIPTION, "UDP/47808: Bacnet identification").
-define(ARGUMENTS, []).

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

callback_next_step(Args) when Args#args.moddata==undefined ->
  {continue, Args#args.maxpkt, ?BACNET, true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  {result, {{error,unknown}, timeout}};
callback_next_step(Args) ->
  parse_bacnet(binary_to_list(Args#args.datarcv)).

parse_bacnet([H|_T]) ->
  case H of
    ?BACNETMAGIC ->
      {result, {{ok,result}, true}};
    _ ->
      {result, {{error,up}, unexpected_data}}
  end.

