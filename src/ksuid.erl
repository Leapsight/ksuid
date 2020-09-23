%% =============================================================================
%%  ksuid.erl -
%%
%%  Copyright (c) 2020 Leapsight Holdings Limited. All rights reserved.
%%
%%  Licensed under the Apache License, Version 2.0 (the "License");
%%  you may not use this file except in compliance with the License.
%%  You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%%  Unless required by applicable law or agreed to in writing, software
%%  distributed under the License is distributed on an "AS IS" BASIS,
%%  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%  See the License for the specific language governing permissions and
%%  limitations under the License.
%% =============================================================================


%% -----------------------------------------------------------------------------
%% @doc An implementation of K-Sortable Unique Identifiers as documented in
%% https://segment.com/blog/a-brief-history-of-the-uuid/.
%%
%% The string representation is fixed at 27-characters encoded using a base62
%% encoding that also sorts lexicographically.
%% @end
%% -----------------------------------------------------------------------------
-module(ksuid).


-define(LEN, 160).
-define(ENCODED_LEN, 27).

%%  Timestamp epoch is adjusted to March 5th, 2014
-define(SECS_EPOCH, 1400000000).
-define(MILLIS_EPOCH, ?SECS_EPOCH * 1000).
-define(MICROS_EPOCH, ?MILLIS_EPOCH * 1000).
-define(NANOS_EPOCH, ?MICROS_EPOCH * 1000).

-type t()           ::  binary().
-type time_unit()   ::  second | millisecond | microsecond | nanosecond.


-export([gen_id/0]).
-export([gen_id/1]).
-export([local_time/1]).
-export([local_time/2]).



%% =============================================================================
%% API
%% =============================================================================




%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec gen_id() -> t().

gen_id() ->
    gen_id(second).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec gen_id(time_unit()) -> t().

gen_id(second = Unit) ->
    do_gen_id(Unit);

gen_id(millisecond = Unit) ->
    do_gen_id(Unit);

gen_id(Unit) ->
    error({badarg, Unit}).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec local_time(Base62 :: binary()) -> {ok, erlang:datetime()}.

local_time(Base62) ->
    local_time(Base62, second).


%% -----------------------------------------------------------------------------
%% @doc
%% @end
%% -----------------------------------------------------------------------------
-spec local_time(Base62 :: binary(), Unit :: erlang:time_unit()) ->
    erlang:datetime() | no_return().

local_time(Base62, second) ->
    Bin = base62:decode(Base62),
    <<Timestamp:32/integer, _/binary>> = <<Bin:?LEN/integer>>,
    calendar:system_time_to_local_time(Timestamp + ?SECS_EPOCH, second);

local_time(Base62, millisecond) ->
    Bin = base62:decode(Base62),
    <<Timestamp:64/integer, _/binary>> = <<Bin:?LEN/integer>>,
    calendar:system_time_to_local_time(Timestamp + ?MILLIS_EPOCH, millisecond).


%% =============================================================================
%% PRIVATE
%% =============================================================================



%% @private
do_gen_id(second) ->
    Timestamp = erlang:system_time(second) - ?SECS_EPOCH,
    <<Id:?LEN/integer>> = append_payload(<<Timestamp:32/integer>>),
    encode(Id);

do_gen_id(millisecond) ->
    Timestamp = erlang:system_time(millisecond) - ?MILLIS_EPOCH,
    <<Id:?LEN/integer>> = append_payload(<<Timestamp:64/integer>>),
    encode(Id).


%% @private
append_payload(Timestamp) ->
    PayloadSize = trunc((?LEN - bit_size(Timestamp)) / 8),
    Payload = payload(PayloadSize),
    <<Timestamp/binary, Payload/binary>>.


%% @private
payload(ByteSize) ->
    crypto:strong_rand_bytes(ByteSize).


%% @private
encode(Id) ->
    Base62 = base62:encode(Id),
    list_to_binary(
        lists:flatten(string:pad(Base62, ?ENCODED_LEN, leading, $0))
    ).