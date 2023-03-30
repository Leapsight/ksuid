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
%% KSUID is an abbreviation for K-Sortable Unique IDentifier. It combines the
%% simplicity and security of UUID Version 4 with the lexicographic k-ordering
%% properties of Boundary's Flake.
%%
%% KSUIDs are larger than UUIDs and Flake IDs, weighing in at 160 bits. They
%% consist of a 32-bit timestamp and a 128-bit randomly generated payload. The
%% uniqueness property does not depend on any host-identifiable information or
%% the wall clock. Instead it depends on the improbability of random collisions
%% in such a large number space, just like UUID Version 4. To reduce
%% implementation complexity, the 122-bits of UUID Version 4 are rounded up to
%% 128-bits, making it 64-times more collision resistant as a bonus, even when
%% the additional 32-bit timestamp is not taken into account.
%%
%% The default timestamp provides 1-second resolution. If a higher resolution
%% timestamp is desired, payload bits can be traded for more timestamp bits.
%%
%% A “custom” epoch is used that ensures >100 years of useful life. The epoch
%% offset (14e8) was also chosen to be easily remembered and quickly singled
%% out out by human eyes.
%%
%% KSUID provides two fixed-length encodings: a 20-byte binary encoding and a
%% 27-character base62 encoding. The lexicographic ordering property is
%% provided by encoding the timestamp using big endian byte ordering. The
%% base62 encoding is tailored to map to the lexicographic ordering of
%% characters in terms of their ASCII order.
%% @end
%% -----------------------------------------------------------------------------
-module(ksuid).


-define(LEN, 160).
-define(ENCODED_LEN, 27).

%%  Timestamp epoch is adjusted to Tuesday, 13 May 2014 16:53:20
-define(SECS_EPOCH, 1400000000).
-define(MILLIS_EPOCH, ?SECS_EPOCH * 1000).
-define(MICROS_EPOCH, ?MILLIS_EPOCH * 1000).
-define(NANOS_EPOCH, ?MICROS_EPOCH * 1000).

-type t()           ::  binary().
-type time_unit()   ::  second | millisecond.
                        % | microsecond | nanosecond.

-export([gen_id/0]).
-export([gen_id/1]).
-export([min/0]).
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
%% @doc The minimum posible id e.g. Tuesday, 13 May 2014 16:53:20
%% @end
%% -----------------------------------------------------------------------------
-spec min() -> t().

min() ->
    <<"000000000000000000000000000">>.


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
do_gen_id(min) ->
    Timestamp = 0,
    <<Id:?LEN/integer>> = append_payload(<<Timestamp:32/integer>>),
    encode(Id);

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