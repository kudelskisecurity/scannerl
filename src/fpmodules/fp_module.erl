%%% This modules set the required functions to implement in any module we create

-module(fp_module).
-author("David Rossier - david.rossier@kudelskisecurity.com").
-export([behaviour_info/1]).

behaviour_info(callbacks) ->
  [
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% get_default_args()
    %%% @return #args record (module, port, type, timeout)
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {get_default_args, 0},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% get_description()
    %%% @return String text
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {get_description, 0},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% get_arguments()
    %%% @return String text
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {get_arguments, 0},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% callback_next_step(#args record)
    %%% @return {result, Result} | {continue, Nbpacket, Payload, ModData}
    %%%         | {restart, {Target, Port}, ModData}
    %%%
    %%% result: FSM will send result to master
    %%%   Result format is:
    %%%     {{ok,result}, ResultStatus}
    %%%     {{error,up}, Reason}
    %%%     {{error,unknown}, Reason}
    %%%   ResultStatus format is atom or List
    %%%
    %%% continue: send data from the same socket,
    %%%           does not reopen if socket closed.
    %%%   Nbpacket is number of packets to receive
    %%%   Payload is data to send to the target
    %%%   ModData is internal module data
    %%%
    %%% restart: open a new socket using Target,Port
    %%%   Target is the new domain/ip addr to target
    %%%   Port is the new port to target
    %%%   ModData is internal module data
    %%%   Use Target=undefined and Port=Undefined to reuse
    %%%   the same target/port
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {callback_next_step, 1}
  ];
behaviour_info(_) ->
  undefined.
