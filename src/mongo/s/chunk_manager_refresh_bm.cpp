/**
 *    Copyright (C) 2018-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/platform/basic.h"

#include <benchmark/benchmark.h>

#include "mongo/base/init.h"
#include "mongo/db/s/collection_metadata.h"
#include "mongo/platform/random.h"
#include "mongo/s/chunk_manager.h"
#include "mongo/util/assert_util.h"
#include "mongo/util/str.h"

namespace mongo {
namespace {

const NamespaceString kNss("test", "foo");

ShardId getShardId(int i) {
    return {std::string(str::stream() << "shard_" << i)};
}

ChunkRange getRangeForChunk(int i, int nChunks) {
    invariant(i >= 0);
    invariant(nChunks > 0);
    invariant(i < nChunks);
    auto min = (i == 0) ? BSON("_id" << MINKEY) : BSON("_id" << (i - 1) * 100);
    auto max = (i == nChunks - 1) ? BSON("_id" << MAXKEY) : BSON("_id" << i * 100);
    return {std::move(min), std::move(max)};
}

template <typename ShardSelectorFn>
auto makeChunkManagerWithShardSelector(int nShards, uint32_t nChunks, ShardSelectorFn selectShard) {
    const auto collEpoch = OID::gen();
    const auto collName = NamespaceString("test.foo");
    const auto shardKeyPattern = KeyPattern(BSON("_id" << 1));

    std::vector<ChunkType> chunks;
    chunks.reserve(nChunks);
    for (uint32_t i = 0; i < nChunks; ++i) {
        chunks.emplace_back(collName,
                            getRangeForChunk(i, nChunks),
                            ChunkVersion{i + 1, 0, collEpoch},
                            selectShard(i, nShards, nChunks));
    }

    auto routingTableHistory = RoutingTableHistory::makeNew(
        collName, UUID::gen(), shardKeyPattern, nullptr, true, collEpoch, chunks);
    auto chunkManager = std::make_shared<ChunkManager>(routingTableHistory, boost::none);
    return std::make_unique<CollectionMetadata>(std::move(chunkManager), getShardId(0));
}

ShardId pessimalShardSelector(int i, int nShards, int nChunks) {
    return getShardId(i % nShards);
}

ShardId optimalShardSelector(int i, int nShards, int nChunks) {
    invariant(nShards <= nChunks);
    const auto shardNum = (int64_t(i) * nShards / nChunks) % nShards;
    return getShardId(shardNum);
}

MONGO_COMPILER_NOINLINE auto makeChunkManagerWithPessimalBalancedDistribution(int nShards,
                                                                              uint32_t nChunks) {
    return makeChunkManagerWithShardSelector(nShards, nChunks, pessimalShardSelector);
}

MONGO_COMPILER_NOINLINE auto makeChunkManagerWithOptimalBalancedDistribution(int nShards,
                                                                             uint32_t nChunks) {
    return makeChunkManagerWithShardSelector(nShards, nChunks, optimalShardSelector);
}

MONGO_COMPILER_NOINLINE auto runIncrementalUpdate(const CollectionMetadata& cm,
                                                  const std::vector<ChunkType>& newChunks) {
    auto rt = cm.getChunkManager()->getRoutingHistory()->makeUpdated(newChunks);
    return std::make_unique<CollectionMetadata>(std::make_shared<ChunkManager>(rt, boost::none),
                                                getShardId(0));
}

void BM_IncrementalRefreshWithNoChange(benchmark::State& state) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);
    auto cm = makeChunkManagerWithOptimalBalancedDistribution(nShards, nChunks);

    auto postMoveVersion = cm->getChunkManager()->getVersion();
    const auto collName = NamespaceString(cm->getChunkManager()->getns());
    std::vector<ChunkType> newChunks;
    newChunks.emplace_back(collName, getRangeForChunk(0, nChunks), postMoveVersion, getShardId(0));

    for (auto keepRunning : state) {
        benchmark::DoNotOptimize(runIncrementalUpdate(*cm, newChunks));
    }
}

BENCHMARK(BM_IncrementalRefreshWithNoChange)
    ->Args({1, 1})
    ->Args({4, 10})
    ->Args({4, 100})
    ->Args({4, 1000})
    ->Args({4, 10000})
    ->Args({4, 100000});

void BM_IncrementalRefreshOfPessimalBalancedDistribution(benchmark::State& state) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);
    auto cm = makeChunkManagerWithPessimalBalancedDistribution(nShards, nChunks);

    auto postMoveVersion = cm->getChunkManager()->getVersion();
    const auto collName = NamespaceString(cm->getChunkManager()->getns());
    std::vector<ChunkType> newChunks;
    postMoveVersion.incMajor();
    newChunks.emplace_back(collName, getRangeForChunk(1, nChunks), postMoveVersion, getShardId(0));
    postMoveVersion.incMajor();
    newChunks.emplace_back(collName, getRangeForChunk(3, nChunks), postMoveVersion, getShardId(1));

    for (auto keepRunning : state) {
        benchmark::DoNotOptimize(runIncrementalUpdate(*cm, newChunks));
    }
}

/*
 * Simulate a refresh of the ChunkManager where a number of chunks is migrated from one shard to
 * another.
 *
 * The chunks modified in the routing table are equally spaced.
 */
void BM_IncrementalSpacedRefreshMoveChunks(benchmark::State& state) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);
    const int nUpdates = state.range(2);
    auto cm = makeChunkManagerWithPessimalBalancedDistribution(nShards, nChunks);

    auto lastVersion = cm->getChunkManager()->getVersion();

    std::vector<ChunkType> newChunks;
    newChunks.reserve(nUpdates);
    const auto updateSpacing = nChunks / nUpdates;
    for (int i = 0; i < nUpdates; i++) {
        const auto idx = i * updateSpacing;
        lastVersion.incMajor();
        newChunks.emplace_back(kNss,
                               getRangeForChunk(idx, nChunks),
                               lastVersion,
                               pessimalShardSelector(idx, nShards, nChunks));
    }

    std::mt19937 g;
    g.seed(456);
    std::shuffle(newChunks.begin(), newChunks.end(), g);

    for (auto _ : state) {
        benchmark::DoNotOptimize(runIncrementalUpdate(*cm, newChunks));
    }
}

BENCHMARK(BM_IncrementalSpacedRefreshMoveChunks)
    ->Args({4, 1, 1})
    ->Args({4, 10, 1})
    ->Args({4, 100, 1})
    ->Args({4, 1000, 1})
    ->Args({4, 10000, 1})
    ->Args({4, 100000, 1})
    ->Args({4, 10000, 10})
    ->Args({4, 10000, 100})
    ->Args({4, 10000, 1000})
    ->Args({4, 10000, 10000});

/*
 * Simulate a refresh of the ChunkManager where a number of chunks is merged together.
 */
void BM_IncrementalSpacedRefreshMergeChunks(benchmark::State& state) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);
    const int nUpdates = state.range(2);
    auto cm = makeChunkManagerWithOptimalBalancedDistribution(nShards, nChunks);

    auto lastVersion = cm->getChunkManager()->getVersion();

    std::vector<ChunkType> newChunks;
    newChunks.reserve(nUpdates);
    invariant(nUpdates <= nShards);
    const auto shardSpacing = nShards / (nUpdates + 1);
    std::set<ShardId> shardsToMerge;
    for (int i = 0; i < nUpdates; i++) {
        invariant(i * shardSpacing <= nShards);
        shardsToMerge.emplace(getShardId(i * shardSpacing));
    }

    ShardId shardId;
    std::vector<ChunkRange> rangesToMerge;

    const auto flushRanges = [&] {
        if (rangesToMerge.empty()) {
            return;
        }

        lastVersion.incMajor();
        newChunks.emplace_back(
            kNss,
            ChunkRange(rangesToMerge.front().getMin(), rangesToMerge.back().getMax()),
            lastVersion,
            shardId);
        rangesToMerge.clear();
    };

    for (int i = 0; i < nChunks; i++) {
        auto nextShardId = pessimalShardSelector(i, nShards, nChunks);
        if (nextShardId != shardId) {
            flushRanges();
            shardId = nextShardId;
        }
        if (shardsToMerge.count(shardId) == 1) {
            rangesToMerge.emplace_back(getRangeForChunk(i, nChunks));
        }
    }
    flushRanges();

    std::mt19937 g;
    g.seed(456);
    std::shuffle(newChunks.begin(), newChunks.end(), g);

    for (auto _ : state) {
        benchmark::DoNotOptimize(runIncrementalUpdate(*cm, newChunks));
    }
}

/*
 * Simulate chunks merge on a routing table of 10000 chunks partitioned among 4 shards.
 *
 * [   0, 2500)  -> shard0
 * [2500, 5000)  -> shard1
 * [5000, 7500)  -> shard2
 * [7500, 10000) -> shard3
 */

BENCHMARK(BM_IncrementalSpacedRefreshMergeChunks)
    ->Args({4, 10000, 1})   // merge all chunks on shard2
    ->Args({4, 10000, 2})   // merge all chunks on shard2 and shard3
    ->Args({4, 10000, 3})   // merge all chunks on shard1, shard2 and shard3
    ->Args({4, 10000, 4});  // merge all chunks on shard1, shard2, shard3 and shard4

template <typename ShardSelectorFn>
auto BM_FullBuildOfChunkManager(benchmark::State& state, ShardSelectorFn selectShard) {
    const int nShards = state.range(0);
    const uint32_t nChunks = state.range(1);

    const auto collEpoch = OID::gen();
    const auto collName = NamespaceString("test.foo");
    const auto shardKeyPattern = KeyPattern(BSON("_id" << 1));

    std::vector<ChunkType> chunks;
    chunks.reserve(nChunks);
    for (uint32_t i = 0; i < nChunks; ++i) {
        chunks.emplace_back(collName,
                            getRangeForChunk(i, nChunks),
                            ChunkVersion{i + 1, 0, collEpoch},
                            selectShard(i, nShards, nChunks));
    }

    for (auto keepRunning : state) {
        auto routingTableHistory = RoutingTableHistory::makeNew(
            collName, UUID::gen(), shardKeyPattern, nullptr, true, collEpoch, chunks);
        auto chunkManager = std::make_shared<ChunkManager>(routingTableHistory, boost::none);
        benchmark::DoNotOptimize(CollectionMetadata(std::move(chunkManager), getShardId(0)));
    }
}

template <typename ShardSelectorFn>
auto BM_GetNextOrphanedRange(benchmark::State& state, ShardSelectorFn selectShard) {
    const int nShards = state.range(0);
    const uint32_t nChunks = state.range(1);

    const auto collEpoch = OID::gen();
    const auto collName = NamespaceString("test.foo");
    const auto shardKeyPattern = KeyPattern(BSON("_id" << 1));

    std::vector<ChunkType> chunks;
    chunks.reserve(nChunks);
    for (uint32_t i = 0; i < nChunks; ++i) {
        chunks.emplace_back(collName,
                            getRangeForChunk(i, nChunks),
                            ChunkVersion{i + 1, 0, collEpoch},
                            selectShard(i, nShards, nChunks));
    }
    auto routingTableHistory = RoutingTableHistory::makeNew(
        collName, UUID::gen(), shardKeyPattern, nullptr, true, collEpoch, chunks);
    auto chunkManager = std::make_shared<ChunkManager>(routingTableHistory, boost::none);
    CollectionMetadata metadata(std::move(chunkManager), getShardId(0));
    const auto emptyReceivingChunks =
        RangeMap{SimpleBSONObjComparator::kInstance.makeBSONObjIndexedMap<BSONObj>()};

    for (auto keepRunning : state) {
        auto startingKey = metadata.getMinKey();
        auto chunkMap = metadata.getOwnedChunks();
        while (true) {
            auto range = metadata.getNextOrphanRange(chunkMap, emptyReceivingChunks, startingKey);
            if (!range) {
                break;
            }

            startingKey = range->getMax();
            benchmark::DoNotOptimize(range);
        }
    }
}

std::vector<BSONObj> makeKeys(int nChunks) {
    constexpr int nFinds = 200000;
    static_assert(nFinds % 2 == 0, "");

    PseudoRandom rand(12345);
    std::vector<BSONObj> keys;
    keys.reserve(nFinds);

    for (int i = 0; i < nFinds; ++i) {
        keys.emplace_back(BSON("_id" << rand.nextInt64(nChunks * 100)));
    }

    return keys;
}

std::vector<std::pair<BSONObj, BSONObj>> makeRanges(const std::vector<BSONObj>& keys) {
    std::vector<std::pair<BSONObj, BSONObj>> ranges;
    ranges.reserve(keys.size() / 2);

    for (size_t i = 0; i < keys.size(); i += 2) {
        auto k1 = keys[i];
        auto k2 = keys[i + 1];
        if (SimpleBSONObjComparator::kInstance.evaluate(k1 == k2)) {
            continue;
        }
        if (SimpleBSONObjComparator::kInstance.evaluate(k1 > k2)) {
            std::swap(k1, k2);
        }
        ranges.emplace_back(k1, k2);
    }

    return ranges;
}

template <typename Container>
class CircularIterator {
public:
    using value_type = typename Container::value_type;
    using const_iterator = typename Container::const_iterator;

    explicit CircularIterator(const Container& container)
        : _begin(container.cbegin()), _end(container.cend()), _curr(_begin) {
        invariant(_begin != _end);
    }

    value_type operator*() const {
        return *_curr;
    }

    const_iterator operator->() const {
        return _curr;
    }

    CircularIterator& operator++() {
        ++_curr;
        if (_curr == _end) {
            _curr = _begin;
        }
        return *this;
    }

    CircularIterator operator++(int) {
        auto result = *this;
        operator++();
        return result;
    }

private:
    const_iterator _begin;
    const_iterator _end;
    const_iterator _curr;
};

template <typename Container>
CircularIterator<Container> makeCircularIterator(const Container& container) {
    return CircularIterator<Container>(container);
}

template <typename CollectionMetadataBuilderFn>
void BM_FindIntersectingChunk(benchmark::State& state,
                              CollectionMetadataBuilderFn makeCollectionMetadata) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);

    auto cm = makeCollectionMetadata(nShards, nChunks);
    auto keys = makeKeys(nChunks);
    auto keysIter = makeCircularIterator(keys);

    for (auto keepRunning : state) {
        benchmark::DoNotOptimize(
            cm->getChunkManager()->findIntersectingChunkWithSimpleCollation(*keysIter));
        ++keysIter;
    }

    state.SetItemsProcessed(state.iterations());
}

template <typename CollectionMetadataBuilderFn>
void BM_GetShardIdsForRange(benchmark::State& state,
                            CollectionMetadataBuilderFn makeCollectionMetadata) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);

    auto cm = makeCollectionMetadata(nShards, nChunks);
    auto keys = makeKeys(nChunks);
    auto ranges = makeRanges(keys);
    auto rangesIter = makeCircularIterator(ranges);

    for (auto keepRunning : state) {
        std::set<ShardId> shardIds;
        cm->getChunkManager()->getShardIdsForRange(
            rangesIter->first, rangesIter->second, &shardIds);
        ++rangesIter;
    }

    state.SetItemsProcessed(state.iterations());
}

template <typename CollectionMetadataBuilderFn>
void BM_GetShardIdsForRangeMinKeyToMaxKey(benchmark::State& state,
                                          CollectionMetadataBuilderFn makeCollectionMetadata) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);

    auto cm = makeCollectionMetadata(nShards, nChunks);
    auto min = BSON("_id" << MINKEY);
    auto max = BSON("_id" << MAXKEY);

    for (auto keepRunning : state) {
        std::set<ShardId> shardIds;
        cm->getChunkManager()->getShardIdsForRange(min, max, &shardIds);
    }

    state.SetItemsProcessed(state.iterations());
}

template <typename CollectionMetadataBuilderFn>
void BM_KeyBelongsToMe(benchmark::State& state,
                       CollectionMetadataBuilderFn makeCollectionMetadata) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);

    auto cm = makeCollectionMetadata(nShards, nChunks);
    auto keys = makeKeys(nChunks);
    auto keysIter = makeCircularIterator(keys);

    size_t nOwned = 0;

    for (auto keepRunning : state) {
        if (cm->keyBelongsToMe(*keysIter)) {
            ++nOwned;
        }
        ++keysIter;
    }

    state.counters["nOwned"] = nOwned;
    state.SetItemsProcessed(state.iterations());
}

template <typename CollectionMetadataBuilderFn>
void BM_RangeOverlapsChunk(benchmark::State& state,
                           CollectionMetadataBuilderFn makeCollectionMetadata) {
    const int nShards = state.range(0);
    const int nChunks = state.range(1);

    auto cm = makeCollectionMetadata(nShards, nChunks);
    auto keys = makeKeys(nChunks);
    auto ranges = makeRanges(keys);
    auto rangesIter = makeCircularIterator(ranges);

    size_t nOverlapped = 0;

    for (auto keepRunning : state) {
        if (cm->rangeOverlapsChunk(ChunkRange(rangesIter->first, rangesIter->second))) {
            ++nOverlapped;
        }
        ++rangesIter;
    }

    state.counters["nOverlapped"] = nOverlapped;
    state.SetItemsProcessed(state.iterations());
}

// The following was adapted from the BENCHMARK_CAPTURE() macro where the
// benchmark::internal::Benchmark* is returned rather than declared as a static variable.
#define REGISTER_BENCHMARK_CAPTURE(func, test_case_name, ...) \
    benchmark::RegisterBenchmark(#func "/" #test_case_name,   \
                                 [](benchmark::State& state) { func(state, __VA_ARGS__); })

MONGO_INITIALIZER(RegisterBenchmarks)(InitializerContext* context) {
    std::initializer_list<benchmark::internal::Benchmark*> bmCases{
        REGISTER_BENCHMARK_CAPTURE(BM_FullBuildOfChunkManager, Pessimal, pessimalShardSelector),
        REGISTER_BENCHMARK_CAPTURE(BM_FullBuildOfChunkManager, Optimal, optimalShardSelector),
        REGISTER_BENCHMARK_CAPTURE(BM_GetNextOrphanedRange, Pessimal, pessimalShardSelector),
        REGISTER_BENCHMARK_CAPTURE(BM_GetNextOrphanedRange, Optimal, optimalShardSelector),
        REGISTER_BENCHMARK_CAPTURE(
            BM_FindIntersectingChunk, Pessimal, makeChunkManagerWithPessimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_FindIntersectingChunk, Optimal, makeChunkManagerWithOptimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_GetShardIdsForRange, Pessimal, makeChunkManagerWithPessimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_GetShardIdsForRange, Optimal, makeChunkManagerWithOptimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(BM_GetShardIdsForRangeMinKeyToMaxKey,
                                   Pessimal,
                                   makeChunkManagerWithPessimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(BM_GetShardIdsForRangeMinKeyToMaxKey,
                                   Optimal,
                                   makeChunkManagerWithOptimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_KeyBelongsToMe, Pessimal, makeChunkManagerWithPessimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_KeyBelongsToMe, Optimal, makeChunkManagerWithOptimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_RangeOverlapsChunk, Pessimal, makeChunkManagerWithPessimalBalancedDistribution),
        REGISTER_BENCHMARK_CAPTURE(
            BM_RangeOverlapsChunk, Optimal, makeChunkManagerWithOptimalBalancedDistribution),
    };

    for (auto bmCase : bmCases) {
        bmCase->Args({2, 2})
            ->Args({1, 10000})
            ->Args({10, 10000})
            ->Args({100, 10000})
            ->Args({1000, 10000})
            ->Args({10, 10})
            ->Args({10, 100})
            ->Args({10, 1000});
    }

    return Status::OK();
}

}  // namespace
}  // namespace mongo
