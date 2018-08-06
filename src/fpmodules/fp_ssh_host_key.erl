%%% SSH host key fingerprint module
%%%
%%% Output:
%%% ip and certificate in pem
%%%
%%% to test localhost on port 40000:
%%%   $ sudo /usr/sbin/sshd -p 40000 -D -d -h /etc/ssh/ssh_host_rsa_key
%%%   $ ssh-keyscan -p 40000 127.0.0.1
%%%   $ ./build.sh && ./scannerl -m ssh_host_key -f 127.0.0.1:40000
%%%

-module(fp_ssh_host_key).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-behavior(fp_module).

-include("../includes/args.hrl").

-export([callback_next_step/1]).
-export([get_default_args/0]).
-export([get_description/0]).
-export([get_arguments/0]).

%% our record for this fingerprint
-define(TIMEOUT, 3000). %% milli-seconds
-define(PORT, 22).      %% SSH port
-define(TYPE, tcp).     %% transport type
-define(MAXPKT, 1).
-define(SSHOPT, [{connect_timeout, ?TIMEOUT},
                 {idle_time, ?TIMEOUT},
                 {user, "test"}, %% unused
                 {password, "test"}, %% unused
                 {inet, inet}, %% force ipv4
                 {user_dir, "."}, %% make sure $HOME/.ssh is not used
                 {id_string, random}, %% random id at each connect
                 {user_interaction, false}, %% avoid querying the user
                 {silently_accept_hosts, false}, %% ecdsa key
                 {quiet_mode, true}, %% be quiet
                 {pref_public_key_algs,['ssh-rsa']}, %% force RSA key
                 {auth_methods, "publickey"} %% avoid user interaction
                ]).
-define(MPATH, "/tmp/"). %% tmp dir for result certificate
-define(PAYLOAD, "\n").
-define(DESCRIPTION, "TCP/22: SSH host key graber").
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

callback_next_step(Args) when Args#args.moddata == undefined ->
  % first packet
  {continue, Args#args.maxpkt, get_payload(), true};
callback_next_step(Args) when Args#args.packetrcv < 1 ->
  % no packet received
  {result, {{error, up}, timeout}};
callback_next_step(Args) ->
  % connect using SSH
  case Args#args.ctarget of
    {_,_,_,_} ->
      % convert target to string
      ssh_connect(Args, inet:ntoa(Args#args.ctarget));
    _ ->
      ssh_connect(Args, Args#args.ctarget)
  end.

% initiate the ssh connection using the ssh application
ssh_connect(Args, Target) ->
  ssh:start(),
  %% this is pretty ugly but since erlang doesn't allow to re-assign
  %% variable and the communication with the callback is one-way only
  %% when providing custom options, there's no way to retrieve the certificate.
  %% Thus going through a file.
  Path = ?MPATH ++ randfilename(10, ""),
  Algos = keep_only_rsa(),
  Opts = ?SSHOPT ++ [{key_cb, {ssh_key_cb, [Path]}}] ++
         [{preferred_algorithms, Algos}],
  case ssh:connect(Target, Args#args.cport, Opts, ?TIMEOUT) of
    {ok, Ref} ->
      debug(Args, "error, connection succeeded but shouldn't"),
      ssh:close(Ref),
      {result, {{error, up}, unexpected_data}};
    {error, Reason} ->
      % the connection should actually failed since
      % we didn't accept the certificate
      debug(Args, "connection failed, good"),
      process_res(Args, Path, Reason)
  end.

%% process the result by reading the file
%% and in case it is not there, return the inital
%% error returned by ssh
process_res(Args, Path, Reason) ->
  case check_file(Args, Path, Reason) of
    {ok, Res} ->
      {result, {{ok, result}, Res}};
    {error, R} ->
      {result, {{error, up}, R}}
  end.

%% read file content
open_read_delete(Args, Path) ->
  case file:read_file(Path) of
    {ok, Bin} ->
      debug(Args, "reading content succeeded"),
      L = binary_to_list(Bin),
      Res = case length(string:split(L, ",", all)) of
        2 ->
          {ok, L};
        _ ->
          {error, unexpected_data}
      end,
      file:delete(Path),
      Res;
    {error, Reason} ->
      debug(Args, "open file failed"),
      {error, Reason}
    end.

%% read the result file if any or return
%% the inital ssh error reason
check_file(Args, Path, Oldreason) ->
  case filelib:is_file(Path) of
    true ->
      debug(Args, "file exists"),
      open_read_delete(Args, Path);
    false ->
      debug(Args, "file doesn't exist ???"),
      {error, Oldreason}
  end.

%% construct a random filename
randfilename(0, Acc) ->
    Acc;
randfilename(N, Acc) ->
    randfilename(N - 1, [rand:uniform(26) + 96 | Acc]).

%% this removes any public_key algorithm but ssh-rsa
keep_only_rsa() ->
  lists:keyreplace(public_key, 1, ssh:default_algorithms(),
                   {public_key, ['ssh-rsa']}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% ssh payload
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% provide the first packet payload
get_payload() ->
  list_to_binary(?PAYLOAD).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%% debug
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% send debug
debug(Args, Msg) ->
  utils:debug(fpmodules, Msg,
      {Args#args.target, Args#args.id}, Args#args.debugval).

