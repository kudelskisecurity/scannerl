%% SSH callback for handling public keys and host keys
%% to use with fp_ssh_host_key.erl
%%
%% this will simply store the host key provided by the
%% server in a file which path is provided through the
%% key_cb_private option.
%%
%% http://erlang.org/doc/man/ssh_client_key_api.html
%%

-module(ssh_key_cb).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").
-behaviour(ssh_client_key_api).
-export([add_host_key/3, is_host_key/4, user_key/2]).

-include_lib("public_key/include/public_key.hrl").

%% per behavior: Checks if a host key is trusted.
is_host_key(Pubkey, _Host, _Algorithm, Options)
when is_record(Pubkey, 'RSAPublicKey') ->
  Modulus = Pubkey#'RSAPublicKey'.modulus,
  Exp = Pubkey#'RSAPublicKey'.publicExponent,
  Path = proplists:get_value(key_cb_private, Options),
  T = io_lib:fwrite("~s,~s", [integer_to_list(Modulus),
                              integer_to_list(Exp)]),
  log_to_file(Path, T),
  false;
is_host_key(_Pubkey, _Host, _Algorithm, _Options) ->
  false.

%% per behavior: Fetches the users public key matching the Algorithm.
user_key(_Algo, _Options) ->
  {error, "Not supported"}.

%% per behavior: Adds a host key to the set of trusted host keys.
add_host_key(_Host, _Pubkey, _Options) ->
  ok.

% save to file
% format: <modulus>,<exponent>
log_to_file(Path, Text) ->
  case file:open(Path, [append]) of
    {ok, Fd} ->
      file:write(Fd, Text),
      file:close(Fd);
    {error, Reason} ->
      {error, Reason}
  end.
