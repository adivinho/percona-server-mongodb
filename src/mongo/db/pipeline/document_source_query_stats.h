/**
 *    Copyright (C) 2022-present MongoDB, Inc.
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

#pragma once

#include "mongo/db/pipeline/document_source.h"
#include "mongo/db/pipeline/lite_parsed_document_source.h"
#include "mongo/db/query/query_stats.h"
#include "mongo/util/producer_consumer_queue.h"

namespace mongo {

using namespace query_stats;

class DocumentSourceQueryStats final : public DocumentSource {
public:
    static constexpr StringData kStageName = "$queryStats"_sd;

    class LiteParsed final : public LiteParsedDocumentSource {
    public:
        static std::unique_ptr<LiteParsed> parse(const NamespaceString& nss,
                                                 const BSONElement& spec);

        LiteParsed(std::string parseTimeName, bool applyHmacToIdentifiers, std::string hmacKey)
            : LiteParsedDocumentSource(std::move(parseTimeName)),
              _applyHmacToIdentifiers(applyHmacToIdentifiers),
              _hmacKey(hmacKey) {}

        stdx::unordered_set<NamespaceString> getInvolvedNamespaces() const override {
            return stdx::unordered_set<NamespaceString>();
        }

        PrivilegeVector requiredPrivileges(bool isMongos,
                                           bool bypassDocumentValidation) const override {
            return {Privilege(ResourcePattern::forClusterResource(), ActionType::queryStatsRead)};
            ;
        }

        bool allowedToPassthroughFromMongos() const final {
            // $queryStats must be run locally on a mongod.
            return false;
        }

        bool isInitialSource() const final {
            return true;
        }

        void assertSupportsMultiDocumentTransaction() const {
            transactionNotSupported(kStageName);
        }

        bool _applyHmacToIdentifiers;

        std::string _hmacKey;
    };

    static boost::intrusive_ptr<DocumentSource> createFromBson(
        BSONElement elem, const boost::intrusive_ptr<ExpressionContext>& pExpCtx);

    virtual ~DocumentSourceQueryStats() = default;

    StageConstraints constraints(
        Pipeline::SplitState = Pipeline::SplitState::kUnsplit) const override {
        StageConstraints constraints{StreamType::kStreaming,
                                     PositionRequirement::kFirst,
                                     HostTypeRequirement::kLocalOnly,
                                     DiskUseRequirement::kNoDiskUse,
                                     FacetRequirement::kNotAllowed,
                                     TransactionRequirement::kNotAllowed,
                                     LookupRequirement::kNotAllowed,
                                     UnionRequirement::kNotAllowed};

        constraints.requiresInputDocSource = false;
        constraints.isIndependentOfAnyCollection = true;
        return constraints;
    }

    boost::optional<DistributedPlanLogic> distributedPlanLogic() final {
        return boost::none;
    }

    const char* getSourceName() const override {
        return kStageName.rawData();
    }

    Value serialize(SerializationOptions opts = SerializationOptions()) const final override;

    void addVariableRefs(std::set<Variables::Id>* refs) const final {}

private:
    DocumentSourceQueryStats(const boost::intrusive_ptr<ExpressionContext>& expCtx,
                             bool applyHmacToIdentifiers = false,
                             std::string hmacKey = {})
        : DocumentSource(kStageName, expCtx),
          _applyHmacToIdentifiers(applyHmacToIdentifiers),
          _hmacKey(hmacKey) {}

    GetNextResult doGetNext() final;

    /**
     * The current partition materialized as a set of Document instances. We pop from the queue and
     * return DocumentSource results.
     */
    std::deque<Document> _materializedPartition;

    /**
     * Iterator over all queryStats partitions. This is incremented when we exhaust the current
     * _materializedPartition.
     */
    QueryStatsStore::PartitionId _currentPartition = -1;

    // When true, apply hmac to field names from returned query shapes.
    bool _applyHmacToIdentifiers;

    /**
     * Key used for SHA-256 HMAC application on field names.
     */
    std::string _hmacKey;
};

}  // namespace mongo
