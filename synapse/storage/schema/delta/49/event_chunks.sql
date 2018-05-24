/* Copyright 2018 New Vector Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

ALTER TABLE events ADD COLUMN chunk_id BIGINT;

INSERT INTO background_updates (update_name, progress_json) VALUES
    ('events_chunk_index', '{}');

-- Stores how chunks of graph relate to each other
CREATE TABLE chunk_graph (
    chunk_id BIGINT NOT NULL,
    prev_id BIGINT NOT NULL
);

CREATE UNIQUE INDEX chunk_graph_id ON chunk_graph (chunk_id, prev_id);
CREATE INDEX chunk_graph_prev_id ON chunk_graph (prev_id);

-- The extremities in each chunk. Note that these are pointing to events that
-- we don't have, rather than boundary between chunks.
CREATE TABLE chunk_backwards_extremities (
    chunk_id BIGINT NOT NULL,
    event_id TEXT NOT NULL
);

CREATE INDEX chunk_backwards_extremities_id ON chunk_backwards_extremities(chunk_id, event_id);
CREATE INDEX chunk_backwards_extremities_event_id ON chunk_backwards_extremities(event_id);

-- Maintains an absolute ordering of chunks. Gets updated when we see new
-- edges between chunks.
CREATE TABLE chunk_linearized (
    chunk_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    ordering DOUBLE PRECISION NOT NULL
);

CREATE UNIQUE INDEX chunk_linearized_id ON chunk_linearized (chunk_id);
CREATE INDEX chunk_linearized_ordering ON chunk_linearized (room_id, ordering);


-- We set chunk IDs and topological orderings for all forwawrd extremities, this
-- ensure that all joined rooms have at least one chunk that can be used to
-- calculate initial sync results with.
--
-- We just set chunk ID to the stream ordering, since stream ordering happens to
-- be a unique integer. We also cap the topological ordering, as a) it no longer
-- needs to match the depth and b) we'll have events with a topological ordering
-- of MAXINT
--
-- (NOTE: sqlite and postgres don't have a common way of doing `min(x,y)`, hence
-- the case statement.
UPDATE events
SET
    chunk_id = stream_ordering,
    topological_ordering = CASE
        WHEN topological_ordering < 100000 THEN topological_ordering
        ELSE 100000
        END
WHERE
    event_id IN (
        SELECT event_id FROM event_forward_extremities
    );

-- We need to ensure that new chunks are given an order. Since we're only doing
-- extremities we know that the events don't point to each other, so the chunks
-- are disconnected, meaning the ordering doesn't matter and simply needs to be
-- unique. Reusing stream_ordering then works
INSERT INTO chunk_linearized (chunk_id, room_id, ordering)
SELECT chunk_id, room_id, stream_ordering
FROM event_forward_extremities
INNER JOIN events USING (room_id, event_id);
