%%% MQTT helper
%%%
%%% control packet:
%%%   fixed header (present in all control packets)
%%%   variable header (present in some)
%%%   payload (present in some)
%%%

-module(utils_mqtt).
-author("Adrien Giner - adrien.giner@kudelskisecurity.com").

-export([parse/1, forge_connect/0]).

% control packet type
% see https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718021
-define(TYPE_CONNECT, 1).
-define(TYPE_CONNACK, 2).
-define(SZ_MOD, 128).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing MQTT packet
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% returns:
%   {true, TYPE}: when it is mqtt
%                 TYPE contains the mqtt type of the last message received
%   {false, Data}: when not mqtt
%                  Data contains the data received
parse(<<
    2:4, % fixedhdr - type
    0:4, % fixedhdr - flags
    2:8, % fixedhdr - remaining length
    0:7, % varhdr - reserved
    _:1, % varhdr - sessionPresent
    _Ret:8 % varhdr - returnCode
  >>) ->
  % this is a CONNACK (no payload)
  {true, ?TYPE_CONNACK};
parse(Data) ->
  {false, Data}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Forge MQTT packet
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% create a MQTT packet
% fixedhdr + varhdr + payload
forge_connect() ->
  Var = forge_connect_var(),
  Pld = forge_connect_pld(),
  Tmp = << Var/binary, Pld/binary >>,
  Fixed = get_fixed_header(?TYPE_CONNECT, get_length(Tmp)),
  << Fixed/binary, Tmp/binary >>.

% create a MQTT header
forge_connect_pld() ->
  % get a random char for the id
  Clientid = rand:uniform(26) + 65,
  << 0:8, 1:8, Clientid:8 >>.

% create mqtt content
forge_connect_var() ->
  <<
    0:8, % length msb
    4:8, % length lsb
    77:8, % 'M'
    81:8, % 'Q'
    84:8, % 'T'
    84:8, % 'T'
    4:8, % protocol level (3.1.1) - will return 0x01 if not supported
    0:1, % username flag
    0:1, % password flag
    0:1, % will retain
    0:2, % will QoS
    0:1, % will flag
    1:1, % clean session
    0:1, % reserved field
    0:8, % keep alive MSB
    60:8 % keep alive LSB (60)
  >>.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% utils
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% returns the length of the Data part
% for mqtt
get_length(Data) ->
  get_length_val(byte_size(Data)).

% remaining length
% see https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718023
get_length_val(Sz) when Sz < 128 ->
  % 1 digit
  << Sz:8 >>;
get_length_val(Sz) when Sz < 16384 ->
  % 2 digit
  Mul = trunc(Sz / ?SZ_MOD),
  Rem = (Sz rem ?SZ_MOD) + ?SZ_MOD,
  <<
    1:1, Rem:7,
    Mul:8
   >>;
get_length_val(Sz) when Sz < 2097152 ->
  % 3 digit
  Mul = trunc(Sz / ?SZ_MOD),
  Rem = (Sz rem ?SZ_MOD) + ?SZ_MOD,
  <<
    1:1, ?SZ_MOD:7,
    1:1, Rem:7,
    Mul:8
  >>;
get_length_val(Sz) when Sz < 268435456 ->
  % 4 digit
  Mul = trunc(Sz / ?SZ_MOD),
  Rem = (Sz rem ?SZ_MOD) + ?SZ_MOD,
  <<
    1:1, ?SZ_MOD:7,
    1:1, ?SZ_MOD:7,
    1:1, Rem:7,
    Mul:8
  >>.

% Type is the type of the packet
% Len is the length of variable length header and payload
get_fixed_header(Type = ?TYPE_CONNECT, Len) ->
  << Type:4, 0:4, Len/binary >>.
%get_fixed_header(Type, Len) ->
%  % flags (https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718022)
%  % change that if using for PUBREL | SUBSCRIBE | UNSUBSCRIBE | PUBLISH
%  Flag = 0,
%  << Type:4, Flag:4, Len/binary >>.

