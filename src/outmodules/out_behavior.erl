%%% This modules set the required functions to implement in any output module.

-module(out_behavior).
-author("David Rossier - david.rossier@kudelskisecurity.com").
-export([behaviour_info/1]).

behaviour_info(callbacks) ->
  [
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% init(Scaninfo, Options)
    %%% @return Object
    %%% Scaninfo contains information on the scan
    %%% Options is the options given to the module
    %%%   (mod:opts)
    %%% Object is a record defining the informations
    %%%   needed by the output module.
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {init, 2},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% clean(Object, Scaninfo)
    %%% Object is a record defining the informations
    %%%   needed by the output module.
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {clean, 1},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% get_description()
    %%% Used by ./scannerl -l to have description of the
    %%%   output modules
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {get_description, 0},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% get_arguments()
    %%% Used by ./scannerl -l to have the arguments of the
    %%%   output modules
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {get_arguments, 0},
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    %%% output(Object, Msg)
    %%% Object is a record defining the informations
    %%%   needed by the output module.
    %%% Msg is the data to write to the output
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    {output, 2}
  ];
behaviour_info(_) ->
  undefined.
