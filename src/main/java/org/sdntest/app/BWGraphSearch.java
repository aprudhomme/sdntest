/*
 * Copyright 2014-2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sdntest.app;

//import org.onlab.graph.*;
import org.onlab.graph.Vertex;
import org.onlab.graph.Edge;
import org.onlab.graph.Graph;
import org.onlab.graph.EdgeWeight;
import org.onlab.graph.Heap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Dijkstra shortest-path graph search algorithm capable of finding not just
 * one, but all shortest paths between the source and destinations.
 */
public class BWGraphSearch<V extends Vertex, E extends Edge<V>>
        extends MyAbstractGraphPathSearch<V, E> {

    private final org.slf4j.Logger log = getLogger("SDNTest");

    @Override
    public Result<V, E> search(Graph<V, E> graph, V src, V dst,
            EdgeWeight<V, E> weight, int maxPaths) {
        return search(graph, src, dst, weight, maxPaths, 0.0);
    }

    public Result<V, E> search(Graph<V, E> graph, V src, V dst,
                               EdgeWeight<V, E> weight, int maxPaths, double bwThresh) {
        checkArguments(graph, src, dst);

        double thresh;
        if (bwThresh > 0.0) {
            thresh = bwThresh;
        } else {
            thresh = Double.MAX_VALUE;
        }

        // Use the default result to remember cumulative costs and parent
        // edges to each each respective vertex.
        DefaultResult result = new DefaultResult(src, dst, maxPaths);

        // use max bandwidth from src to self
        result.updateVertex(src, null, Double.MAX_VALUE, false);
        //result.updateVertex(src, null, 0.0, false);

        if (graph.getEdges().isEmpty()) {
            result.buildPaths();
            return result;
        }

        // Use the min priority queue to progressively find each nearest
        // vertex until we reach the desired destination, if one was given,
        // or until we reach all possible destinations.
        Heap<V> minQueue = createMinQueue(graph.getVertexes(),
                                          new PathCostComparator(result));
        while (!minQueue.isEmpty()) {
            // Get the nearest vertex
            V nearest = minQueue.extractExtreme();
            //log.info("nearest: {}", nearest);
            if (nearest.equals(dst)) {
                break;
            }

            // Find its cost and use it to determine if the vertex is reachable.
            double cost = result.cost(nearest);
            //log.info("cost: {}", cost);
            //if (cost < Double.MAX_VALUE) {
            if (cost > 0.0) {
                // If the vertex is reachable, relax all its egress edges.
                for (E e : graph.getEdgesFrom(nearest)) {
                    //log.info("relaxEdge: {}", e);
                    result.relaxEdge(e, cost, weight, thresh, true);
                }
            }

            // Re-prioritize the min queue.
            minQueue.heapify();
        }

        // Now construct a set of paths from the results.
        //log.info("buildPaths");
        result.buildPaths();
        //log.info("Done");
        return result;
    }

    // Compares path weights using their accrued costs; used for sorting the
    // min priority queue.
    private final class PathCostComparator implements Comparator<V> {
        private final DefaultResult result;

        private PathCostComparator(DefaultResult result) {
            this.result = result;
        }

        @Override
        public int compare(V v1, V v2) {
            //double delta = result.cost(v2) - result.cost(v1);
            // reverse to max priority queue
            double delta = result.cost(v1) - result.cost(v2);
            return delta < 0 ? -1 : (delta > 0 ? 1 : 0);
        }
    }

    // Creates a min priority queue from the specified vertexes and comparator.
    private Heap<V> createMinQueue(Set<V> vertexes, Comparator<V> comparator) {
        return new Heap<>(new ArrayList<>(vertexes), comparator);
    }

}
