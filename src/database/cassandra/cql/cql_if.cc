//
// Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
//

#include <assert.h>

#include <tbb/atomic.h>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/unordered_map.hpp>

#include <cassandra.h>

#include <base/logging.h>
#include <base/task.h>
#include <base/timer.h>
#include <base/string_util.h>
#include <io/event_manager.h>
#include <database/gendb_if.h>
#include <database/cassandra/cql/cql_if.h>
#include <database/cassandra/cql/cql_if_impl.h>

#define CQLIF_LOG(_Level, _Msg)                                           \
    do {                                                                  \
        if (LoggingDisabled()) break;                                     \
        log4cplus::Logger logger = log4cplus::Logger::getRoot();          \
        LOG4CPLUS_##_Level(logger, __func__ << ":" << __FILE__ << ":" <<  \
            __LINE__ << ": " << _Msg);                                    \
    } while (false)

#define CQLIF_LOG_ERR(_Msg)                                               \
    do {                                                                  \
        LOG(ERROR, __func__ << ":" << __FILE__ << ":" << __LINE__ << ": " \
            << _Msg);                                                     \
    } while (false)

namespace cass {
namespace cql {
namespace impl {

// CQL Library Shared Pointers to handle library free calls
template<class T>
struct Deleter;

template<>
struct Deleter<CassCluster> {
    void operator()(CassCluster *ptr) {
        if (ptr != NULL) {
            cass_cluster_free(ptr);
        }
    }
};

template<>
struct Deleter<CassSession> {
  void operator()(CassSession* ptr) {
    if (ptr != NULL) {
      cass_session_free(ptr);
    }
  }
};

template<>
struct Deleter<CassFuture> {
  void operator()(CassFuture* ptr) {
    if (ptr != NULL) {
      cass_future_free(ptr);
    }
  }
};

template<>
struct Deleter<CassStatement> {
  void operator()(CassStatement* ptr) {
    if (ptr != NULL) {
      cass_statement_free(ptr);
    }
  }
};

template<>
struct Deleter<const CassResult> {
  void operator()(const CassResult* ptr) {
    if (ptr != NULL) {
      cass_result_free(ptr);
    }
  }
};

template<>
struct Deleter<CassIterator> {
  void operator()(CassIterator* ptr) {
    if (ptr != NULL) {
      cass_iterator_free(ptr);
    }
  }
};

template<>
struct Deleter<const CassPrepared> {
  void operator()(const CassPrepared* ptr) {
    if (ptr != NULL) {
      cass_prepared_free(ptr);
    }
  }
};

template<>
struct Deleter<const CassSchemaMeta> {
  void operator()(const CassSchemaMeta* ptr) {
    if (ptr != NULL) {
      cass_schema_meta_free(ptr);
    }
  }
};

template <class T>
class CassSharedPtr : public boost::shared_ptr<T> {
public:
  explicit CassSharedPtr(T* ptr = NULL)
    : boost::shared_ptr<T>(ptr, Deleter<T>()) {}
};

typedef CassSharedPtr<CassCluster> CassClusterPtr;
typedef CassSharedPtr<CassSession> CassSessionPtr;
typedef CassSharedPtr<CassFuture> CassFuturePtr;
typedef CassSharedPtr<CassStatement> CassStatementPtr;
typedef CassSharedPtr<const CassResult> CassResultPtr;
typedef CassSharedPtr<CassIterator> CassIteratorPtr;
typedef CassSharedPtr<const CassPrepared> CassPreparedPtr;
typedef CassSharedPtr<const CassSchemaMeta> CassSchemaMetaPtr;

// CassString convenience structure
struct CassString {
    CassString() :
        data(NULL),
        length(0) {
    }

    CassString(const char *data) :
        data(data),
        length(strlen(data)) {
    }

    CassString(const char* data, size_t length) :
        data(data),
        length(length) {
    }

    const char* data;
    size_t length;
};

// CassUuid encode and decode
static inline void encode_uuid(char* output, const CassUuid &uuid) {
    uint64_t time_and_version = uuid.time_and_version;
    output[3] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;
    output[2] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;
    output[1] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;
    output[0] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;

    output[5] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;
    output[4] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;

    output[7] = static_cast<char>(time_and_version & 0x00000000000000FFLL);
    time_and_version >>= 8;
    output[6] = static_cast<char>(time_and_version & 0x000000000000000FFLL);

    uint64_t clock_seq_and_node = uuid.clock_seq_and_node;
    for (size_t i = 0; i < 8; ++i) {
        output[15 - i] = static_cast<char>(clock_seq_and_node & 0x00000000000000FFL);
        clock_seq_and_node >>= 8;
    }
}

static inline char* decode_uuid(char* input, CassUuid* output) {
  output->time_and_version  = static_cast<uint64_t>(static_cast<uint8_t>(input[3]));
  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[2])) << 8;
  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[1])) << 16;
  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[0])) << 24;

  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[5])) << 32;
  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[4])) << 40;

  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[7])) << 48;
  output->time_and_version |= static_cast<uint64_t>(static_cast<uint8_t>(input[6])) << 56;

  output->clock_seq_and_node = 0;
  for (size_t i = 0; i < 8; ++i) {
    output->clock_seq_and_node |= static_cast<uint64_t>(static_cast<uint8_t>(input[15 - i])) << (8 * i);
  }
  return input + 16;
}

static const char * DbDataType2CassType(
    const GenDb::DbDataType::type &db_type) {
    switch (db_type) {
      case GenDb::DbDataType::AsciiType:
        return "ascii";
      case GenDb::DbDataType::LexicalUUIDType:
        return "uuid";
      case GenDb::DbDataType::TimeUUIDType:
        return "timeuuid";
      case GenDb::DbDataType::Unsigned8Type:
      case GenDb::DbDataType::Unsigned16Type:
      case GenDb::DbDataType::Unsigned32Type:
        return "int";
      case GenDb::DbDataType::Unsigned64Type:
        return "bigint";
      case GenDb::DbDataType::DoubleType:
        return "double";
      case GenDb::DbDataType::UTF8Type:
        return "text";
      case GenDb::DbDataType::InetType:
        return "inet";
      case GenDb::DbDataType::IntegerType:
        return "varint";
      case GenDb::DbDataType::BlobType:
        return "blob";
      default:
        assert(false && "Invalid data type");
        return "";
    }
}

static std::string DbDataTypes2CassTypes(
    const GenDb::DbDataTypeVec &v_db_types) {
    assert(!v_db_types.empty());
    return std::string(DbDataType2CassType(v_db_types[0]));
}

// Cass Query Printer
class CassQueryPrinter : public boost::static_visitor<> {
 public:
    CassQueryPrinter(std::ostream &os, bool quote_strings) :
        os_(os),
        quote_strings_(quote_strings) {
    }
    CassQueryPrinter(std::ostream &os) :
        os_(os),
        quote_strings_(true) {
    }
    template<typename T>
    void operator()(const T &t) const {
        os_ << t;
    }
    void operator()(const boost::uuids::uuid &tuuid) const {
        os_ << to_string(tuuid);
    }
    // uint8_t must be handled specially because ostream sees
    // uint8_t as a text type instead of an integer type
    void operator()(const uint8_t &tu8) const {
        os_ << (uint16_t)tu8;
    }
    void operator()(const std::string &tstring) const {
        if (quote_strings_) {
            os_ << "'" << tstring << "'";
        } else {
            os_ << tstring;
        }
    }
    // CQL int is 32 bit signed integer
    void operator()(const uint32_t &tu32) const {
        os_ << (int32_t)tu32;
    }
    // CQL bigint is 64 bit signed long
    void operator()(const uint64_t &tu64) const {
        os_ << (int64_t)tu64;
    }
    void operator()(const IpAddress &tipaddr) const {
        os_ << "'" << tipaddr << "'";
    }
    std::ostream &os_;
    bool quote_strings_;
};

//
// CassStatement bind
//
class CassStatementIndexBinder : public boost::static_visitor<> {
 public:
    CassStatementIndexBinder(CassStatement *statement) :
        statement_(statement) {
    }
    void operator()(const boost::blank &tblank, size_t index) const {
        assert(false && "CassStatement bind to boost::blank not supported");
    }
    void operator()(const std::string &tstring, size_t index) const {
        CassError rc(cass_statement_bind_string_n(statement_, index,
            tstring.c_str(), tstring.length()));
        assert(rc == CASS_OK);
    }
    void operator()(const boost::uuids::uuid &tuuid, size_t index) const {
        CassUuid cuuid;
        decode_uuid((char *)&tuuid, &cuuid);
        CassError rc(cass_statement_bind_uuid(statement_, index, cuuid));
        assert(rc == CASS_OK);
    }
    void operator()(const uint8_t &tu8, size_t index) const {
        CassError rc(cass_statement_bind_int32(statement_, index, tu8));
        assert(rc == CASS_OK);
    }
    void operator()(const uint16_t &tu16, size_t index) const {
        CassError rc(cass_statement_bind_int32(statement_, index, tu16));
        assert(rc == CASS_OK);
    }
    void operator()(const uint32_t &tu32, size_t index) const {
        CassError rc(cass_statement_bind_int32(statement_, index,
            (cass_int32_t)tu32));
        assert(rc == CASS_OK);
    }
    void operator()(const uint64_t &tu64, size_t index) const {
        CassError rc(cass_statement_bind_int64(statement_, index,
            (cass_int64_t)tu64));
        assert(rc == CASS_OK);
    }
    void operator()(const double &tdouble, size_t index) const {
        CassError rc(cass_statement_bind_double(statement_, index,
            (cass_double_t)tdouble));
        assert(rc == CASS_OK);
    }
    void operator()(const IpAddress &tipaddr, size_t index) const {
        CassInet cinet;
        if (tipaddr.is_v4()) {
            boost::asio::ip::address_v4 tv4(tipaddr.to_v4());
            cinet = cass_inet_init_v4(tv4.to_bytes().c_array());
        } else {
            boost::asio::ip::address_v6 tv6(tipaddr.to_v6());
            cinet = cass_inet_init_v6(tv6.to_bytes().c_array());
        }
        CassError rc(cass_statement_bind_inet(statement_, index,
            cinet));
        assert(rc == CASS_OK);
    }
    CassStatement *statement_;
};

class CassStatementNameBinder : public boost::static_visitor<> {
 public:
    CassStatementNameBinder(CassStatement *statement) :
        statement_(statement) {
    }
    void operator()(const boost::blank &tblank, const char *name) const {
        assert(false && "CassStatement bind to boost::blank not supported");
    }
    void operator()(const std::string &tstring, const char *name) const {
        CassError rc(cass_statement_bind_string_by_name_n(statement_, name,
            strlen(name), tstring.c_str(), tstring.length()));
        assert(rc == CASS_OK);
    }
    void operator()(const boost::uuids::uuid &tuuid, const char *name) const {
        CassUuid cuuid;
        decode_uuid((char *)&tuuid, &cuuid);
        CassError rc(cass_statement_bind_uuid_by_name(statement_, name,
            cuuid));
        assert(rc == CASS_OK);
    }
    void operator()(const uint8_t &tu8, const char *name) const {
        CassError rc(cass_statement_bind_int32_by_name(statement_, name,
            tu8));
        assert(rc == CASS_OK);
    }
    void operator()(const uint16_t &tu16, const char *name) const {
        CassError rc(cass_statement_bind_int32_by_name(statement_, name,
            tu16));
        assert(rc == CASS_OK);
    }
    void operator()(const uint32_t &tu32, const char *name) const {
        CassError rc(cass_statement_bind_int32_by_name(statement_, name,
            (cass_int32_t)tu32));
        assert(rc == CASS_OK);
    }
    void operator()(const uint64_t &tu64, const char *name) const {
        CassError rc(cass_statement_bind_int64_by_name(statement_, name,
            (cass_int64_t)tu64));
        assert(rc == CASS_OK);
    }
    void operator()(const double &tdouble, const char *name) const {
        CassError rc(cass_statement_bind_double_by_name(statement_, name,
            (cass_double_t)tdouble));
        assert(rc == CASS_OK);
    }
    void operator()(const IpAddress &tipaddr, const char *name) const {
        CassInet cinet;
        if (tipaddr.is_v4()) {
            boost::asio::ip::address_v4 tv4(tipaddr.to_v4());
            cinet = cass_inet_init_v4(tv4.to_bytes().c_array());
        } else {
            boost::asio::ip::address_v6 tv6(tipaddr.to_v6());
            cinet = cass_inet_init_v6(tv6.to_bytes().c_array());
        }
        CassError rc(cass_statement_bind_inet_by_name(statement_, name,
            cinet));
        assert(rc == CASS_OK);
    }
    CassStatement *statement_;
};

static const std::string kQCompactionStrategy(
    "compaction = {'class': "
    "'org.apache.cassandra.db.compaction.LeveledCompactionStrategy'}");
static const std::string kQGCGraceSeconds("gc_grace_seconds = 0");

//
// Cf2CassCreateTableIfNotExists
//

std::string StaticCf2CassCreateTableIfNotExists(const GenDb::NewCf &cf) {
    std::ostringstream query;
    // Table name
    query << "CREATE TABLE IF NOT EXISTS " << cf.cfname_ << " ";
    // Row key
    const GenDb::DbDataTypeVec &rkeys(cf.key_validation_class);
    assert(rkeys.size() == 1);
    query << "(key " << DbDataType2CassType(rkeys[0]) <<
        " PRIMARY KEY";
    // Columns
    const GenDb::NewCf::SqlColumnMap &columns(cf.cfcolumns_);
    assert(!columns.empty());
    BOOST_FOREACH(const GenDb::NewCf::SqlColumnMap::value_type &column,
        columns) {
        query << ", \"" << column.first << "\" " <<
            DbDataType2CassType(column.second);
    }
    query << ") WITH " << kQCompactionStrategy << " AND " <<
        kQGCGraceSeconds;
    return query.str();
}

std::string DynamicCf2CassCreateTableIfNotExists(const GenDb::NewCf &cf) {
    std::ostringstream query;
    // Table name
    query << "CREATE TABLE IF NOT EXISTS " << cf.cfname_ << " (";
    // Row key
    const GenDb::DbDataTypeVec &rkeys(cf.key_validation_class);
    int rk_size(rkeys.size());
    for (int i = 0; i < rk_size; i++) {
        if (i) {
            int key_num(i + 1);
            query << "key" << key_num;
        } else {
            query << "key";
        }
        query << " " << DbDataType2CassType(rkeys[i]) << ", ";
    }
    // Column name
    const GenDb::DbDataTypeVec &cnames(cf.comparator_type);
    int cn_size(cnames.size());
    for (int i = 0; i < cn_size; i++) {
        int cnum(i + 1);
        query << "column" << cnum << " " <<
            DbDataType2CassType(cnames[i]) << ", ";
    }
    // Value
    const GenDb::DbDataTypeVec &values(cf.default_validation_class);
    if (values.size() > 0) {
        query << "value" << " " << DbDataTypes2CassTypes(values) << ", ";
    }
    // Primarry Key
    query << "PRIMARY KEY (";
    std::ostringstream rkey_ss;
    for (int i = 0; i < rk_size; i++) {
        if (i) {
            int key_num(i + 1);
            rkey_ss << ", key" << key_num;
        } else {
            rkey_ss << "key";
        }
    }
    if (rk_size >= 2) {
        query << "(" << rkey_ss.str() << "), ";
    } else {
        query << rkey_ss.str() << ", ";
    }
    for (int i = 0; i < cn_size; i++) {
        int cnum(i + 1);
        if (i) {
            query << ", ";
        }
        query << "column" << cnum;
    }
    query << ")) WITH " << kQCompactionStrategy << " AND " <<
        kQGCGraceSeconds;
    return query.str();
}

//
// Cf2CassInsertIntoTable
//

std::string StaticCf2CassInsertIntoTable(const GenDb::ColList *v_columns) {
    std::ostringstream query;
    // Table
    const std::string &table(v_columns->cfname_);
    query << "INSERT INTO " << table << " (";
    std::ostringstream values_ss;
    values_ss << "VALUES (";
    CassQueryPrinter values_printer(values_ss);
    // Row keys
    const GenDb::DbDataValueVec &rkeys(v_columns->rowkey_);
    int rk_size(rkeys.size());
    for (int i = 0; i < rk_size; i++) {
        if (i) {
            int key_num(i + 1);
            query << ", key" << key_num;
        } else {
            query << "key";
        }
        if (i) {
            values_ss << ", ";
        }
        boost::apply_visitor(values_printer, rkeys[i]);
    }
    // Columns
    int cttl(-1);
    CassQueryPrinter cnames_printer(query, false);
    BOOST_FOREACH(const GenDb::NewCol &column, v_columns->columns_) {
        assert(column.cftype_ == GenDb::NewCf::COLUMN_FAMILY_SQL);
        // Column Name
        query << ", ";
        const GenDb::DbDataValueVec &cnames(*column.name.get());
        assert(cnames.size() == 1);
        // Double quote column name strings
        query << "\"";
        boost::apply_visitor(cnames_printer, cnames[0]);
        query << "\"";
        // Column Values
        values_ss << ", ";
        const GenDb::DbDataValueVec &cvalues(*column.value.get());
        assert(cvalues.size() == 1);
        boost::apply_visitor(values_printer, cvalues[0]);
        // Column TTL
        cttl = column.ttl;
    }
    query << ") ";
    values_ss << ")";
    query << values_ss.str();
    if (cttl > 0) {
        query << " USING TTL " << cttl;
    }
    return query.str();
}

std::string DynamicCf2CassInsertIntoTable(const GenDb::ColList *v_columns) {
    std::ostringstream query;
    // Table
    const std::string &table(v_columns->cfname_);
    query << "INSERT INTO " << table << " (";
    std::ostringstream values_ss;
    // Row keys
    const GenDb::DbDataValueVec &rkeys(v_columns->rowkey_);
    int rk_size(rkeys.size());
    CassQueryPrinter values_printer(values_ss);
    for (int i = 0; i < rk_size; i++) {
        if (i) {
            int key_num(i + 1);
            query << ", key" << key_num;
        } else {
            query << "key";
        }
        boost::apply_visitor(values_printer, rkeys[i]);
        values_ss << ", ";
    }
    // Columns
    const GenDb::NewColVec &columns(v_columns->columns_);
    assert(columns.size() == 1);
    const GenDb::NewCol &column(columns[0]);
    assert(column.cftype_ == GenDb::NewCf::COLUMN_FAMILY_NOSQL);
    // Column Names
    const GenDb::DbDataValueVec &cnames(*column.name.get());
    int cn_size(cnames.size());
    for (int i = 0; i < cn_size; i++) {
        int cnum(i + 1);
        query << ", column" << cnum;
        boost::apply_visitor(values_printer, cnames[i]);
        if (i != cn_size - 1) {
            values_ss << ", ";
        }
    }
    // Column Values
    const GenDb::DbDataValueVec &cvalues(*column.value.get());
    if (cvalues.size() > 0) {
        query << ", value) VALUES (";
        values_ss << ", ";
        boost::apply_visitor(values_printer, cvalues[0]);
    } else {
        query << ") VALUES (";
    }
    values_ss << ")";
    query << values_ss.str();
    if (column.ttl > 0) {
        query << " USING TTL " << column.ttl;
    }
    return query.str();
}

//
// Cf2CassPrepareInsertIntoTable
//

std::string StaticCf2CassPrepareInsertIntoTable(const GenDb::NewCf &cf) {
   std::ostringstream query;
    // Table name
    query << "INSERT INTO " << cf.cfname_ << " ";
    // Row key
    const GenDb::DbDataTypeVec &rkeys(cf.key_validation_class);
    assert(rkeys.size() == 1);
    std::ostringstream values_ss;
    query << "(key";
    values_ss << ") VALUES (?";
    // Columns
    const GenDb::NewCf::SqlColumnMap &columns(cf.cfcolumns_);
    assert(!columns.empty());
    BOOST_FOREACH(const GenDb::NewCf::SqlColumnMap::value_type &column,
        columns) {
        query << ", \"" << column.first << "\"";
        values_ss << ", ?";
    }
    query << values_ss.str();
    query << ") USING TTL ?";
    return query.str();
}

std::string DynamicCf2CassPrepareInsertIntoTable(const GenDb::NewCf &cf) {
    std::ostringstream query;
    // Table name
    query << "INSERT INTO " << cf.cfname_ << " (";
    // Row key
    const GenDb::DbDataTypeVec &rkeys(cf.key_validation_class);
    int rk_size(rkeys.size());
    std::ostringstream values_ss;
    for (int i = 0; i < rk_size; i++) {
        if (i) {
            int key_num(i + 1);
            query << "key" << key_num;
        } else {
            query << "key";
        }
        query << ", ";
        values_ss << "?, ";
    }
    // Column name
    const GenDb::DbDataTypeVec &cnames(cf.comparator_type);
    int cn_size(cnames.size());
    for (int i = 0; i < cn_size; i++) {
        int cnum(i + 1);
        query << "column" << cnum;
        values_ss << "?";
        if (i != cn_size - 1) {
            query << ", ";
            values_ss << ", ";
        }
    }
    // Value
    const GenDb::DbDataTypeVec &values(cf.default_validation_class);
    if (values.size() > 0) {
        query << ", value";
        values_ss << ", ?";
    }
    query << ") VALUES (";
    values_ss << ")";
    query << values_ss.str();
    query << " USING TTL ?";
    return query.str();
}

//
// Cf2CassPrepareBind
//

bool StaticCf2CassPrepareBind(CassStatement *statement,
    const GenDb::ColList *v_columns) {
    CassStatementNameBinder values_binder(statement);
    // Row keys
    const GenDb::DbDataValueVec &rkeys(v_columns->rowkey_);
    int rk_size(rkeys.size());
    size_t idx(0);
    for (; (int) idx < rk_size; idx++) {
        std::string rk_name;
        if (idx) {
            int key_num(idx + 1);
            rk_name = "key" + integerToString(key_num);
        } else {
            rk_name = "key";
        }
        boost::apply_visitor(boost::bind(values_binder, _1, rk_name.c_str()),
            rkeys[idx]);
    }
    // Columns
    int cttl(-1);
    BOOST_FOREACH(const GenDb::NewCol &column, v_columns->columns_) {
        assert(column.cftype_ == GenDb::NewCf::COLUMN_FAMILY_SQL);
        const GenDb::DbDataValueVec &cnames(*column.name.get());
        assert(cnames.size() == 1);
        assert(cnames[0].which() == GenDb::DB_VALUE_STRING);
        std::string cname(boost::get<std::string>(cnames[0]));
        const GenDb::DbDataValueVec &cvalues(*column.value.get());
        assert(cvalues.size() == 1);
        boost::apply_visitor(boost::bind(values_binder, _1, cname.c_str()),
            cvalues[0]);
        // Column TTL
        cttl = column.ttl;
        idx++;
    }
    CassError rc(cass_statement_bind_int32(statement, idx++,
        (cass_int32_t)cttl));
    assert(rc == CASS_OK);
    return true;
}

bool DynamicCf2CassPrepareBind(CassStatement *statement,
    const GenDb::ColList *v_columns) {
    CassStatementIndexBinder values_binder(statement);
    // Row keys
    const GenDb::DbDataValueVec &rkeys(v_columns->rowkey_);
    int rk_size(rkeys.size());
    size_t idx(0);
    for (; (int) idx < rk_size; idx++) {
        boost::apply_visitor(boost::bind(values_binder, _1, idx), rkeys[idx]);
    }
    // Columns
    const GenDb::NewColVec &columns(v_columns->columns_);
    assert(columns.size() == 1);
    const GenDb::NewCol &column(columns[0]);
    assert(column.cftype_ == GenDb::NewCf::COLUMN_FAMILY_NOSQL);
    // Column Names
    const GenDb::DbDataValueVec &cnames(*column.name.get());
    int cn_size(cnames.size());
    for (int i = 0; i < cn_size; i++, idx++) {
        boost::apply_visitor(boost::bind(values_binder, _1, idx), cnames[i]);
    }
    // Column Values
    const GenDb::DbDataValueVec &cvalues(*column.value.get());
    if (cvalues.size() > 0) {
        boost::apply_visitor(boost::bind(values_binder, _1, idx++),
            cvalues[0]);
    }
    CassError rc(cass_statement_bind_int32(statement, idx++,
        (cass_int32_t)column.ttl));
    assert(rc == CASS_OK);
    return true;
}

static std::string CassSelectFromTableInternal(const std::string &table,
    const GenDb::DbDataValueVec &rkeys,
    const GenDb::ColumnNameRange &ck_range) {
    std::ostringstream query;
    // Table
    query << "SELECT * FROM " << table << " WHERE ";
    int rk_size(rkeys.size());
    CassQueryPrinter cprinter(query);
    for (int i = 0; i < rk_size; i++) {
        if (i) {
            int key_num(i + 1);
            query << " AND key" << key_num << "=";
        } else {
            query << "key=";
        }
        boost::apply_visitor(cprinter, rkeys[i]);
    }
    if (!ck_range.IsEmpty()) {
        if (!ck_range.start_.empty()) {
            int ck_start_size(ck_range.start_.size());
            std::ostringstream start_ss;
            start_ss << " >= (";
            CassQueryPrinter start_vprinter(start_ss);
            query << " AND (";
            for (int i = 0; i < ck_start_size; i++) {
                if (i) {
                    query << ", ";
                    start_ss << ", ";
                }
                int cnum(i + 1);
                query << "column" << cnum;
                boost::apply_visitor(start_vprinter, ck_range.start_[i]);
            }
            query << ")";
            start_ss << ")";
            query << start_ss.str();
        }
        if (!ck_range.finish_.empty()) {
            int ck_finish_size(ck_range.finish_.size());
            std::ostringstream finish_ss;
            finish_ss << " <= (";
            CassQueryPrinter finish_vprinter(finish_ss);
            query << " AND (";
            for (int i = 0; i < ck_finish_size; i++) {
                if (i) {
                    query << ", ";
                    finish_ss << ", ";
                }
                int cnum(i + 1);
                query << "column" << cnum;
                boost::apply_visitor(finish_vprinter, ck_range.finish_[i]);
            }
            query << ")";
            finish_ss << ")";
            query << finish_ss.str();
        }
        if (ck_range.count_) {
            query << " LIMIT " << ck_range.count_;
        }
    }
    return query.str();
}

std::string PartitionKey2CassSelectFromTable(const std::string &table,
    const GenDb::DbDataValueVec &rkeys) {
    return CassSelectFromTableInternal(table, rkeys, GenDb::ColumnNameRange());
}

std::string PartitionKeyAndClusteringKeyRange2CassSelectFromTable(
    const std::string &table, const GenDb::DbDataValueVec &rkeys,
    const GenDb::ColumnNameRange &ck_range) {
    return CassSelectFromTableInternal(table, rkeys, ck_range);
}

static GenDb::DbDataValue CassValue2DbDataValue(const CassValue *cvalue) {
    CassValueType cvtype(cass_value_type(cvalue));
    switch (cvtype) {
      case CASS_VALUE_TYPE_ASCII:
      case CASS_VALUE_TYPE_VARCHAR:
      case CASS_VALUE_TYPE_TEXT: {
        CassString ctstring;
        CassError rc(cass_value_get_string(cvalue, &ctstring.data,
            &ctstring.length));
        assert(rc == CASS_OK);
        return std::string(ctstring.data, ctstring.length);
      }
      case CASS_VALUE_TYPE_UUID: {
        CassUuid ctuuid;
        CassError rc(cass_value_get_uuid(cvalue, &ctuuid));
        assert(rc == CASS_OK);
        boost::uuids::uuid u;
        encode_uuid((char *)&u, ctuuid);
        return u;
      }
      case CASS_VALUE_TYPE_DOUBLE: {
        cass_double_t ctdouble;
        CassError rc(cass_value_get_double(cvalue, &ctdouble));
        assert(rc == CASS_OK);
        return (double)ctdouble;
      }
      case CASS_VALUE_TYPE_TINY_INT: {
        cass_int8_t ct8;
        CassError rc(cass_value_get_int8(cvalue, &ct8));
        assert(rc == CASS_OK);
        return (uint8_t)ct8;
      }
      case CASS_VALUE_TYPE_SMALL_INT: {
        cass_int16_t ct16;
        CassError rc(cass_value_get_int16(cvalue, &ct16));
        assert(rc == CASS_OK);
        return (uint16_t)ct16;
      }
      case CASS_VALUE_TYPE_INT: {
        cass_int32_t ct32;
        CassError rc(cass_value_get_int32(cvalue, &ct32));
        assert(rc == CASS_OK);
        return (uint32_t)ct32;
      }
      case CASS_VALUE_TYPE_BIGINT: {
        cass_int64_t ct64;
        CassError rc(cass_value_get_int64(cvalue, &ct64));
        assert(rc == CASS_OK);
        return (uint64_t)ct64;
      }
      case CASS_VALUE_TYPE_INET: {
        CassInet ctinet;
        CassError rc(cass_value_get_inet(cvalue, &ctinet));
        assert(rc == CASS_OK);
        IpAddress ipaddr;
        if (ctinet.address_length == CASS_INET_V4_LENGTH) {
            Ip4Address::bytes_type ipv4;
            memcpy(ipv4.c_array(), ctinet.address, CASS_INET_V4_LENGTH);
            ipaddr = Ip4Address(ipv4);
        } else if (ctinet.address_length == CASS_INET_V6_LENGTH) {
            Ip6Address::bytes_type ipv6;
            memcpy(ipv6.c_array(), ctinet.address, CASS_INET_V6_LENGTH);
            ipaddr = Ip6Address(ipv6);
        } else {
            assert(0);
        }
        return ipaddr;
      }
      case CASS_VALUE_TYPE_UNKNOWN: {
        // null type
        return GenDb::DbDataValue();
      }
      default: {
        CQLIF_LOG_ERR("Unhandled CassValueType: " << cvtype);
        assert(false && "Unhandled value type");
        return GenDb::DbDataValue();
      }
    }
}

static bool PrepareSync(CassSession *session, const char* query,
    CassPreparedPtr *prepared) {
    CQLIF_LOG(DEBUG, "PrepareSync: " << query);
    CassFuturePtr future(cass_session_prepare(session, query));
    cass_future_wait(future.get());

    CassError rc(cass_future_error_code(future.get()));
    if (rc != CASS_OK) {
        CassString err;
        cass_future_error_message(future.get(), &err.data, &err.length);
        CQLIF_LOG_ERR("PrepareSync: " << query << " FAILED: " << err.data);
    } else {
        *prepared = CassPreparedPtr(cass_future_get_prepared(future.get()));
    }
    return rc == CASS_OK;
}

static bool ExecuteQuerySyncInternal(CassSession *session,
    CassStatement *qstatement, CassResultPtr *result,
    CassConsistency consistency) {
    cass_statement_set_consistency(qstatement, consistency);
    CassFuturePtr future(cass_session_execute(session, qstatement));
    cass_future_wait(future.get());

    CassError rc(cass_future_error_code(future.get()));
    if (rc != CASS_OK) {
        CassString err;
        cass_future_error_message(future.get(), &err.data, &err.length);
        CQLIF_LOG_ERR("SyncQuery: FAILED: " << err.data);
    } else {
        if (result) {
            *result = CassResultPtr(cass_future_get_result(future.get()));
        }
    }
    return rc == CASS_OK;
}

static bool ExecuteQuerySync(CassSession *session, const char *query,
    CassConsistency consistency) {
    CQLIF_LOG(DEBUG, "SyncQuery: " << query);
    CassStatementPtr statement(cass_statement_new(query, 0));
    return ExecuteQuerySyncInternal(session, statement.get(), NULL,
        consistency);
}

static bool ExecuteQueryResultSync(CassSession *session, const char *query,
    CassResultPtr *result, CassConsistency consistency) {
    CQLIF_LOG(DEBUG, "SyncQuery: " << query);
    CassStatementPtr statement(cass_statement_new(query, 0));
    return ExecuteQuerySyncInternal(session, statement.get(), result,
        consistency);
}

static bool ExecuteQueryStatementSync(CassSession *session,
    CassStatement *statement, CassConsistency consistency) {
    return ExecuteQuerySyncInternal(session, statement, NULL, consistency);
}

typedef boost::function<void(GenDb::DbOpResult::type)> CassAsyncQueryCallback;

struct CassAsyncQueryContext {
    CassAsyncQueryContext(const char *query_id, CassAsyncQueryCallback cb) :
        query_id_(query_id),
        cb_(cb) {
    }
    std::string query_id_;
    CassAsyncQueryCallback cb_;
};

static GenDb::DbOpResult::type CassError2DbOpResult(CassError rc) {
    switch (rc) {
      case CASS_OK:
        return GenDb::DbOpResult::OK;
      case CASS_ERROR_LIB_NO_HOSTS_AVAILABLE:
      case CASS_ERROR_LIB_REQUEST_QUEUE_FULL:
      case CASS_ERROR_LIB_NO_AVAILABLE_IO_THREAD:
        return GenDb::DbOpResult::BACK_PRESSURE;
      default:
        return GenDb::DbOpResult::ERROR;
    }
}

static void OnExecuteQueryAsync(CassFuture *future, void *data) {
    assert(data);
    std::auto_ptr<CassAsyncQueryContext> ctx(
        boost::reinterpret_pointer_cast<CassAsyncQueryContext>(data));
    CassError rc(cass_future_error_code(future));
    if (rc != CASS_OK) {
        CassString err;
        cass_future_error_message(future, &err.data, &err.length);
        CQLIF_LOG_ERR("AsyncQuery: " << ctx->query_id_ << " FAILED: "
            << err.data);
    }
    GenDb::DbOpResult::type db_rc(CassError2DbOpResult(rc));
    ctx->cb_(db_rc);
}

static void ExecuteQueryAsyncInternal(CassSession *session,
    const char *qid, CassStatement *qstatement,
    CassConsistency consistency, CassAsyncQueryCallback cb) {
    cass_statement_set_consistency(qstatement, consistency);
    CassFuturePtr future(cass_session_execute(session, qstatement));
    std::auto_ptr<CassAsyncQueryContext> ctx(new CassAsyncQueryContext(qid, cb));
    cass_future_set_callback(future.get(), OnExecuteQueryAsync, ctx.release());
}

static void ExecuteQueryAsync(CassSession *session, const char *query,
    CassConsistency consistency, CassAsyncQueryCallback cb) {
    CQLIF_LOG(DEBUG, "AsyncQuery: " << query);
    CassStatementPtr statement(cass_statement_new(query, 0));
    ExecuteQueryAsyncInternal(session, query, statement.get(), consistency,
        cb);
}

static void ExecuteQueryStatementAsync(CassSession *session,
    const char *query_id, CassStatement *qstatement,
    CassConsistency consistency, CassAsyncQueryCallback cb) {
    ExecuteQueryAsyncInternal(session, query_id, qstatement, consistency,
        cb);
}

static bool DynamicCfGetResultSync(CassSession *session, const char *query,
    size_t rk_count, size_t ck_count, CassConsistency consistency,
    GenDb::NewColVec *v_columns) {
    CassResultPtr result;
    bool success(ExecuteQueryResultSync(session, query, &result,
        consistency));
    if (!success) {
        return success;
    }
    // Row iterator
    CassIteratorPtr riterator(cass_iterator_from_result(result.get()));
    while (cass_iterator_next(riterator.get())) {
        const CassRow *row(cass_iterator_get_row(riterator.get()));
        // Iterate over columns
        size_t ccount(cass_result_column_count(result.get()));
        // Clustering key
        GenDb::DbDataValueVec *cnames(new GenDb::DbDataValueVec);
        for (size_t i = rk_count; i < rk_count + ck_count; i++) {
            const CassValue *cvalue(cass_row_get_column(row, i));
            assert(cvalue);
            GenDb::DbDataValue db_value(CassValue2DbDataValue(cvalue));
            cnames->push_back(db_value);
        }
        // Values
        GenDb::DbDataValueVec *values(new GenDb::DbDataValueVec);
        for (size_t i = rk_count + ck_count; i < ccount; i++) {
            const CassValue *cvalue(cass_row_get_column(row, i));
            assert(cvalue);
            GenDb::DbDataValue db_value(CassValue2DbDataValue(cvalue));
            values->push_back(db_value);
        }
        GenDb::NewCol *column(new GenDb::NewCol(cnames, values, 0));
        v_columns->push_back(column);
    }
    return success;
}

static bool StaticCfGetResultSync(CassSession *session, const char *query,
    CassConsistency consistency, GenDb::NewColVec *v_columns) {
    CassResultPtr result;
    bool success(ExecuteQueryResultSync(session, query, &result,
        consistency));
    if (!success) {
        return success;
    }
    // Row iterator
    CassIteratorPtr riterator(cass_iterator_from_result(result.get()));
    while (cass_iterator_next(riterator.get())) {
        const CassRow *row(cass_iterator_get_row(riterator.get()));
        // Iterate over columns
        size_t ccount(cass_result_column_count(result.get()));
        for (size_t i = 0; i < ccount; i++) {
            CassString cname;
            CassError rc(cass_result_column_name(result.get(), i, &cname.data,
                &cname.length));
            assert(rc == CASS_OK);
            const CassValue *cvalue(cass_row_get_column(row, i));
            assert(cvalue);
            GenDb::DbDataValue db_value(CassValue2DbDataValue(cvalue));
            if (db_value.which() == GenDb::DB_VALUE_BLANK) {
                continue;
            }
            GenDb::NewCol *column(new GenDb::NewCol(
                std::string(cname.data, cname.length), db_value, 0));
            v_columns->push_back(column);
        }
    }
    return success;
}

static bool SyncFutureWait(CassFuture *future) {
    cass_future_wait(future);
    CassError rc(cass_future_error_code(future));
    if (rc != CASS_OK) {
        CassString err;
        cass_future_error_message(future, &err.data, &err.length);
        CQLIF_LOG_ERR("SyncWait: FAILED: " << err.data);
    }
    return rc == CASS_OK;
}

static const CassTableMeta * GetCassTableMeta(const CassSchemaMeta *schema_meta,
    const std::string &keyspace, const std::string &table, bool log_error) {
    const CassKeyspaceMeta *keyspace_meta(
        cass_schema_meta_keyspace_by_name(schema_meta,
        keyspace.c_str()));
    if (keyspace_meta == NULL) {
        if (log_error) {
            CQLIF_LOG_ERR("No keyspace schema: Keyspace: " << keyspace <<
                ", Table: " << table);
        }
        return NULL;
    }
    std::string table_lower(table);
    boost::algorithm::to_lower(table_lower);
    const CassTableMeta *table_meta(
        cass_keyspace_meta_table_by_name(keyspace_meta,
        table_lower.c_str()));
    if (table_meta == NULL) {
        if (log_error) {
            CQLIF_LOG_ERR("No table schema: Keyspace: " << keyspace <<
                ", Table: " << table_lower);
        }
        return NULL;
    }
    return table_meta;
}

static bool IsCassTableMetaPresent(CassSession *session,
    const std::string &keyspace, const std::string &table) {
    impl::CassSchemaMetaPtr schema_meta(cass_session_get_schema_meta(
        session));
    if (schema_meta.get() == NULL) {
        CQLIF_LOG(DEBUG, "No schema meta: Keyspace: " << keyspace <<
            ", Table: " << table);
        return false;
    }
    bool log_error(false);
    const CassTableMeta *table_meta(impl::GetCassTableMeta(
        schema_meta.get(), keyspace, table, log_error));
    if (table_meta == NULL) {
        return false;
    }
    return true;
}

static bool GetCassTableClusteringKeyCount(CassSession *session,
    const std::string &keyspace, const std::string &table, size_t *ck_count) {
    impl::CassSchemaMetaPtr schema_meta(cass_session_get_schema_meta(
        session));
    if (schema_meta.get() == NULL) {
        CQLIF_LOG_ERR("No schema meta: Keyspace: " << keyspace <<
            ", Table: " << table);
        return false;
    }
    bool log_error(true);
    const CassTableMeta *table_meta(impl::GetCassTableMeta(
        schema_meta.get(), keyspace, table, log_error));
    if (table_meta == NULL) {
        return false;
    }
    *ck_count = cass_table_meta_clustering_key_count(table_meta);
    return true;
}

static bool GetCassTablePartitionKeyCount(CassSession *session,
    const std::string &keyspace, const std::string &table, size_t *rk_count) {
    impl::CassSchemaMetaPtr schema_meta(cass_session_get_schema_meta(
        session));
    if (schema_meta.get() == NULL) {
        CQLIF_LOG_ERR("No schema meta: Keyspace: " << keyspace <<
            ", Table: " << table);
        return false;
    }
    bool log_error(true);
    const CassTableMeta *table_meta(impl::GetCassTableMeta(
        schema_meta.get(), keyspace, table, log_error));
    if (table_meta == NULL) {
        return false;
    }
    *rk_count = cass_table_meta_partition_key_count(table_meta);
    return true;
}

static log4cplus::LogLevel Cass2log4Level(CassLogLevel clevel) {
    switch (clevel) {
      case CASS_LOG_DISABLED:
        return log4cplus::OFF_LOG_LEVEL;
      case CASS_LOG_CRITICAL:
        return log4cplus::FATAL_LOG_LEVEL;
      case CASS_LOG_ERROR:
        return log4cplus::ERROR_LOG_LEVEL;
      case CASS_LOG_WARN:
        return log4cplus::WARN_LOG_LEVEL;
      case CASS_LOG_INFO:
        return log4cplus::INFO_LOG_LEVEL;
      case CASS_LOG_DEBUG:
        return log4cplus::DEBUG_LOG_LEVEL;
      case CASS_LOG_TRACE:
        return log4cplus::TRACE_LOG_LEVEL;
      default:
        return log4cplus::ALL_LOG_LEVEL;
    }
}

static CassLogLevel Log4Level2CassLogLevel(log4cplus::LogLevel level) {
    switch (level) {
      case log4cplus::OFF_LOG_LEVEL:
        return CASS_LOG_DISABLED;
      case log4cplus::FATAL_LOG_LEVEL:
        return CASS_LOG_CRITICAL;
      case log4cplus::ERROR_LOG_LEVEL:
        return CASS_LOG_ERROR;
      case log4cplus::WARN_LOG_LEVEL:
        return CASS_LOG_WARN;
      case log4cplus::INFO_LOG_LEVEL:
        return CASS_LOG_INFO;
      case log4cplus::DEBUG_LOG_LEVEL:
        return CASS_LOG_DEBUG;
      case log4cplus::TRACE_LOG_LEVEL:
        return CASS_LOG_TRACE;
      default:
        assert(false && "Invalid Log4Level");
        return CASS_LOG_DISABLED;
    }
}

static void CassLibraryLog(const CassLogMessage* message, void *data) {
    if (LoggingDisabled()) {
        return;
    }
    log4cplus::LogLevel log4level(Cass2log4Level(message->severity));
    log4cplus::Logger logger(log4cplus::Logger::getRoot());
    if (logger.isEnabledFor(log4level)) {
        log4cplus::tostringstream buf;
        buf << "CassLibrary: " << message->file << ":" << message->line <<
            " " << message->function << "] " << message->message;
        logger.forcedLog(log4level, buf.str());
    }
}

}  // namespace impl

//
// CqlIf::CqlIfImpl
//
class CqlIf::CqlIfImpl {
 public:
    CqlIfImpl(EventManager *evm,
        const std::vector<std::string> &cassandra_ips,
        int cassandra_port,
        const std::string &cassandra_user,
        const std::string &cassandra_password) :
        evm_(evm),
        cluster_(cass_cluster_new()),
        session_(cass_session_new()),
        reconnect_timer_(TimerManager::CreateTimer(*evm->io_service(),
            "CqlIfImpl Reconnect Timer",
            TaskScheduler::GetInstance()->GetTaskId(kTaskName),
            kTaskInstance)),
        connect_cb_(NULL),
        disconnect_cb_(NULL),
        keyspace_(),
        io_thread_count_(2) {
        // Set session state to INIT
        session_state_ = SessionState::INIT;
        // Set contact points and port
        std::string contact_points(boost::algorithm::join(cassandra_ips, ","));
        cass_cluster_set_contact_points(cluster_.get(), contact_points.c_str());
        cass_cluster_set_port(cluster_.get(), cassandra_port);
        // Set credentials for plain text authentication
        if (!cassandra_user.empty() && !cassandra_password.empty()) {
            cass_cluster_set_credentials(cluster_.get(), cassandra_user.c_str(),
                cassandra_password.c_str());
        }
        // Set number of IO threads to half the number of cores
        cass_cluster_set_num_threads_io(cluster_.get(), io_thread_count_);
        cass_cluster_set_pending_requests_high_water_mark(cluster_.get(), 10000);
        cass_cluster_set_pending_requests_low_water_mark(cluster_.get(), 5000);
        cass_cluster_set_write_bytes_high_water_mark(cluster_.get(), 128000);
        cass_cluster_set_write_bytes_low_water_mark(cluster_.get(), 96000);
    }

    virtual ~CqlIfImpl() {
        assert(session_state_ == SessionState::INIT ||
            session_state_ == SessionState::DISCONNECTED);
        TimerManager::DeleteTimer(reconnect_timer_);
        reconnect_timer_ = NULL;
    }

    bool CreateKeyspaceIfNotExistsSync(const std::string &keyspace,
        const std::string &replication_factor, CassConsistency consistency) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        char buf[512];
        int n(snprintf(buf, sizeof(buf), kQCreateKeyspaceIfNotExists,
            keyspace.c_str(), replication_factor.c_str()));
        if (n < 0 || n >= (int)sizeof(buf)) {
            CQLIF_LOG_ERR("FAILED (" << n << "): Keyspace: " <<
                keyspace << ", RF: " << replication_factor);
            return false;
        }
        return impl::ExecuteQuerySync(session_.get(), buf, consistency);
    }

    bool UseKeyspaceSync(const std::string &keyspace,
        CassConsistency consistency) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        char buf[512];
        int n(snprintf(buf, sizeof(buf), kQUseKeyspace, keyspace.c_str()));
        if (n < 0 || n >= (int)sizeof(buf)) {
            CQLIF_LOG_ERR("FAILED (" << n << "): Keyspace: " <<
                keyspace);
            return false;
        }
        bool success(impl::ExecuteQuerySync(session_.get(), buf,
            consistency));
        if (!success) {
            return false;
        }
        // Update keyspace
        keyspace_ = keyspace;
        return success;
    }

    bool CreateTableIfNotExistsSync(const GenDb::NewCf &cf,
        CassConsistency consistency) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        // There are two types of tables - Static (SQL) and Dynamic (NOSQL)
        // column family. Static column family has more or less fixed rows,
        // and dynamic column family has wide rows
        std::string query;
        switch (cf.cftype_) {
          case GenDb::NewCf::COLUMN_FAMILY_SQL:
            query = impl::StaticCf2CassCreateTableIfNotExists(cf);
            break;
          case GenDb::NewCf::COLUMN_FAMILY_NOSQL:
            query = impl::DynamicCf2CassCreateTableIfNotExists(cf);
            break;
          default:
            return false;
        }
        return impl::ExecuteQuerySync(session_.get(), query.c_str(),
            consistency);
    }

    bool LocatePrepareInsertIntoTable(const GenDb::NewCf &cf) {
        const std::string &table_name(cf.cfname_);
        impl::CassPreparedPtr prepared;
        // Check if the prepared statement exists
        if (GetPrepareInsertIntoTable(table_name, &prepared)) {
            return true;
        }
        bool success(PrepareInsertIntoTableSync(cf, &prepared));
        if (!success) {
            return success;
        }
        // Store the prepared statement into the map
        tbb::mutex::scoped_lock lock(map_mutex_);
        success = (insert_prepared_map_.insert(
            std::make_pair(table_name, prepared))).second;
        assert(success);
        return success;
    }

    bool GetPrepareInsertIntoTable(const std::string &table_name,
        impl::CassPreparedPtr *prepared) const {
        tbb::mutex::scoped_lock lock(map_mutex_);
        CassPreparedMapType::const_iterator it(
            insert_prepared_map_.find(table_name));
        if (it == insert_prepared_map_.end()) {
            return false;
        }
        *prepared = it->second;
        return true;
    }

    bool IsTablePresent(const GenDb::NewCf &cf) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        return impl::IsCassTableMetaPresent(session_.get(), keyspace_,
            cf.cfname_);
    }

    bool IsTableStatic(const std::string &table) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        size_t ck_count;
        assert(impl::GetCassTableClusteringKeyCount(session_.get(), keyspace_,
            table, &ck_count));
        return ck_count == 0;
    }

    bool IsTableDynamic(const std::string &table) {
        return !IsTableStatic(table);
    }

    bool InsertIntoTableSync(std::auto_ptr<GenDb::ColList> v_columns,
        CassConsistency consistency) {
        return InsertIntoTableInternal(v_columns, consistency, true, NULL);
    }

    bool InsertIntoTableAsync(std::auto_ptr<GenDb::ColList> v_columns,
        CassConsistency consistency, impl::CassAsyncQueryCallback cb) {
        return InsertIntoTableInternal(v_columns, consistency, false, cb);
    }

    bool InsertIntoTablePrepareAsync(std::auto_ptr<GenDb::ColList> v_columns,
        CassConsistency consistency, impl::CassAsyncQueryCallback cb) {
        return InsertIntoTablePrepareInternal(v_columns, consistency, false,
            cb);
    }

    bool IsInsertIntoTablePrepareSupported(const std::string &table) {
        return IsTableDynamic(table);
    }

    bool SelectFromTableSync(const std::string &cfname,
        const GenDb::DbDataValueVec &rkey, CassConsistency consistency,
        GenDb::NewColVec *out) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        std::string query(impl::PartitionKey2CassSelectFromTable(cfname,
            rkey));
        if (IsTableStatic(cfname)) {
            return impl::StaticCfGetResultSync(session_.get(),
                query.c_str(), consistency, out);
        } else {
            size_t rk_count;
            assert(impl::GetCassTablePartitionKeyCount(session_.get(),
                keyspace_, cfname, &rk_count));
            size_t ck_count;
            assert(impl::GetCassTableClusteringKeyCount(session_.get(),
                keyspace_, cfname, &ck_count));
            return impl::DynamicCfGetResultSync(session_.get(),
                query.c_str(), rk_count, ck_count, consistency, out);
        }
    }

    bool SelectFromTableClusteringKeyRangeSync(const std::string &cfname,
        const GenDb::DbDataValueVec &rkey,
        const GenDb::ColumnNameRange &ck_range, CassConsistency consistency,
        GenDb::NewColVec *out) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        std::string query(
            impl::PartitionKeyAndClusteringKeyRange2CassSelectFromTable(cfname,
            rkey, ck_range));
        assert(IsTableDynamic(cfname));
        size_t rk_count;
        assert(impl::GetCassTablePartitionKeyCount(session_.get(),
            keyspace_, cfname, &rk_count));
        size_t ck_count;
        assert(impl::GetCassTableClusteringKeyCount(session_.get(),
            keyspace_, cfname, &ck_count));
        return impl::DynamicCfGetResultSync(session_.get(),
            query.c_str(), rk_count, ck_count, consistency, out);
    }

    void ConnectAsync() {
        session_state_ = SessionState::CONNECT_PENDING;
        impl::CassFuturePtr future(cass_session_connect(session_.get(),
            cluster_.get()));
        if (connect_cb_.empty()) {
            connect_cb_ = boost::bind(&CqlIfImpl::ConnectCallbackProcess,
                this, _1);
        }
        cass_future_set_callback(future.get(), ConnectCallback, this);
    }

    bool ConnectSync() {
        impl::CassFuturePtr future(cass_session_connect(session_.get(),
            cluster_.get()));
        bool success(impl::SyncFutureWait(future.get()));
        if (success) {
            session_state_ = SessionState::CONNECTED;
            CQLIF_LOG(INFO, "ConnectSync Done");
        } else {
            CQLIF_LOG_ERR("ConnectSync FAILED");
        }
        return success;
   }

    void DisconnectAsync() {
        // Close all session and pending queries
        session_state_ = SessionState::DISCONNECT_PENDING;
        impl::CassFuturePtr future(cass_session_close(session_.get()));
        if (disconnect_cb_.empty()) {
            disconnect_cb_ = boost::bind(&CqlIfImpl::DisconnectCallbackProcess,
                this, _1);
        }
        cass_future_set_callback(future.get(), DisconnectCallback, this);
    }

    bool DisconnectSync() {
        // Close all session and pending queries
        impl::CassFuturePtr future(cass_session_close(session_.get()));
        bool success(impl::SyncFutureWait(future.get()));
        if (success) {
            session_state_ = SessionState::DISCONNECTED;
            CQLIF_LOG(INFO, "DisconnectSync Done");
        } else {
            CQLIF_LOG_ERR("DisconnectSync FAILED");
        }
        return success;
    }

    void GetMetrics(Metrics *metrics) const {
        CassMetrics cass_metrics;
        cass_session_get_metrics(session_.get(), &cass_metrics);
        // Requests
        metrics->requests.min = cass_metrics.requests.min;
        metrics->requests.max = cass_metrics.requests.max;
        metrics->requests.mean = cass_metrics.requests.mean;
        metrics->requests.stddev = cass_metrics.requests.stddev;
        metrics->requests.median = cass_metrics.requests.median;
        metrics->requests.percentile_75th =
            cass_metrics.requests.percentile_75th;
        metrics->requests.percentile_95th =
            cass_metrics.requests.percentile_95th;
        metrics->requests.percentile_98th =
            cass_metrics.requests.percentile_98th;
        metrics->requests.percentile_99th =
            cass_metrics.requests.percentile_99th;
        metrics->requests.percentile_999th =
            cass_metrics.requests.percentile_999th;
        metrics->requests.mean_rate = cass_metrics.requests.mean_rate;
        metrics->requests.one_minute_rate =
            cass_metrics.requests.one_minute_rate;
        metrics->requests.five_minute_rate =
            cass_metrics.requests.five_minute_rate;
        metrics->requests.fifteen_minute_rate =
            cass_metrics.requests.fifteen_minute_rate;
        // Stats
        metrics->stats.total_connections =
            cass_metrics.stats.total_connections;
        metrics->stats.available_connections =
            cass_metrics.stats.available_connections;
        metrics->stats.exceeded_pending_requests_water_mark =
            cass_metrics.stats.exceeded_pending_requests_water_mark;
        metrics->stats.exceeded_write_bytes_water_mark =
            cass_metrics.stats.exceeded_write_bytes_water_mark;
        // Errors
        metrics->errors.connection_timeouts =
            cass_metrics.errors.connection_timeouts;
        metrics->errors.pending_request_timeouts =
            cass_metrics.errors.pending_request_timeouts;
        metrics->errors.request_timeouts =
            cass_metrics.errors.request_timeouts;
    }

 private:
    typedef boost::function<void(CassFuture *)> ConnectCbFn;
    typedef boost::function<void(CassFuture *)> DisconnectCbFn;

    static void ConnectCallback(CassFuture *future, void *data) {
        CqlIfImpl *impl_ = (CqlIfImpl *)data;
        impl_->connect_cb_(future);
    }

    static void DisconnectCallback(CassFuture *future, void *data) {
        CqlIfImpl *impl_ = (CqlIfImpl *)data;
        impl_->disconnect_cb_(future);
    }

    bool ReconnectTimerExpired() {
        ConnectAsync();
        return false;
    }

    void ReconnectTimerErrorHandler(std::string error_name,
        std::string error_message) {
        CQLIF_LOG_ERR(error_name << " " << error_message);
    }

    void ConnectCallbackProcess(CassFuture *future) {
        CassError code(cass_future_error_code(future));
        if (code != CASS_OK) {
            impl::CassString err;
            cass_future_error_message(future, &err.data, &err.length);
            CQLIF_LOG(INFO, err.data);
            // Start a timer to reconnect
            reconnect_timer_->Start(kReconnectInterval,
                boost::bind(&CqlIfImpl::ReconnectTimerExpired, this),
                boost::bind(&CqlIfImpl::ReconnectTimerErrorHandler, this,
                    _1, _2));
            return;
        }
        session_state_ = SessionState::CONNECTED;
    }

    void DisconnectCallbackProcess(CassFuture *future) {
        CassError code(cass_future_error_code(future));
        if (code != CASS_OK) {
            impl::CassString err;
            cass_future_error_message(future, &err.data, &err.length);
            CQLIF_LOG_ERR(err.data);
        }
        session_state_ = SessionState::DISCONNECTED;
    }

    bool InsertIntoTableInternal(std::auto_ptr<GenDb::ColList> v_columns,
        CassConsistency consistency, bool sync,
        impl::CassAsyncQueryCallback cb) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        std::string query;
        if (IsTableStatic(v_columns->cfname_)) {
            query = impl::StaticCf2CassInsertIntoTable(v_columns.get());
        } else {
            query = impl::DynamicCf2CassInsertIntoTable(v_columns.get());
        }
        if (sync) {
            return impl::ExecuteQuerySync(session_.get(), query.c_str(),
                consistency);
        } else {
            impl::ExecuteQueryAsync(session_.get(), query.c_str(),
                consistency, cb);
            return true;
        }
    }

    bool PrepareInsertIntoTableSync(const GenDb::NewCf &cf,
        impl::CassPreparedPtr *prepared) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        std::string query;
        switch (cf.cftype_) {
          case GenDb::NewCf::COLUMN_FAMILY_SQL:
            query = impl::StaticCf2CassPrepareInsertIntoTable(cf);
            break;
          case GenDb::NewCf::COLUMN_FAMILY_NOSQL:
            query = impl::DynamicCf2CassPrepareInsertIntoTable(cf);
            break;
          default:
            return false;
        }
        return impl::PrepareSync(session_.get(), query.c_str(),
            prepared);
    }

    bool InsertIntoTablePrepareInternal(std::auto_ptr<GenDb::ColList> v_columns,
        CassConsistency consistency, bool sync,
        impl::CassAsyncQueryCallback cb) {
        if (session_state_ != SessionState::CONNECTED) {
            return false;
        }
        impl::CassPreparedPtr prepared;
        bool success(GetPrepareInsertIntoTable(v_columns->cfname_, &prepared));
        if (!success) {
            CQLIF_LOG_ERR("CassPrepared statement NOT found: " <<
                v_columns->cfname_);
            return false;
        }
        impl::CassStatementPtr qstatement(cass_prepared_bind(prepared.get()));
        if (IsTableStatic(v_columns->cfname_)) {
            success = impl::StaticCf2CassPrepareBind(qstatement.get(),
                v_columns.get());
        } else {
            success = impl::DynamicCf2CassPrepareBind(qstatement.get(),
                v_columns.get());
        }
        if (!success) {
            return false;
        }
        if (sync) {
            return impl::ExecuteQueryStatementSync(session_.get(),
                qstatement.get(), consistency);
        } else {
            std::string qid("Prepare: " + v_columns->cfname_);
            impl::ExecuteQueryStatementAsync(session_.get(), qid.c_str(),
                qstatement.get(), consistency, cb);
            return true;
        }
    }

    static const char * kQCreateKeyspaceIfNotExists;
    static const char * kQUseKeyspace;
    static const char * kTaskName;
    static const int kTaskInstance = -1;
    static const int kReconnectInterval = 5 * 1000;

    struct SessionState {
        enum type {
            INIT,
            CONNECT_PENDING,
            CONNECTED,
            DISCONNECT_PENDING,
            DISCONNECTED,
        };
    };

    EventManager *evm_;
    impl::CassClusterPtr cluster_;
    impl::CassSessionPtr session_;
    tbb::atomic<SessionState::type> session_state_;
    Timer *reconnect_timer_;
    ConnectCbFn connect_cb_;
    DisconnectCbFn disconnect_cb_;
    std::string keyspace_;
    int io_thread_count_;
    typedef boost::unordered_map<std::string, impl::CassPreparedPtr>
        CassPreparedMapType;
    CassPreparedMapType insert_prepared_map_;
    mutable tbb::mutex map_mutex_;
};

const char * CqlIf::CqlIfImpl::kQCreateKeyspaceIfNotExists(
    "CREATE KEYSPACE IF NOT EXISTS \"%s\" WITH "
    "replication = { 'class' : 'SimpleStrategy', 'replication_factor' : %s }");
const char * CqlIf::CqlIfImpl::kQUseKeyspace("USE \"%s\"");
const char * CqlIf::CqlIfImpl::kTaskName("CqlIfImpl::Task");

//
// CqlIf
//
CqlIf::CqlIf(EventManager *evm,
             const std::vector<std::string> &cassandra_ips,
             int cassandra_port,
             const std::string &cassandra_user,
             const std::string &cassandra_password) :
    impl_(NULL),
    use_prepared_for_insert_(true) {
    // Setup library logging
    cass_log_set_level(impl::Log4Level2CassLogLevel(
        log4cplus::Logger::getRoot().getLogLevel()));
    cass_log_set_callback(impl::CassLibraryLog, NULL);
    impl_ = new CqlIfImpl(evm, cassandra_ips, cassandra_port,
        cassandra_user, cassandra_password);
    initialized_ = false;
    BOOST_FOREACH(const std::string &cassandra_ip, cassandra_ips) {
        boost::system::error_code ec;
        boost::asio::ip::address cassandra_addr(
            boost::asio::ip::address::from_string(cassandra_ip, ec));
        GenDb::Endpoint endpoint(cassandra_addr, cassandra_port);
        endpoints_.push_back(endpoint);
    }
}

CqlIf::CqlIf() : impl_(NULL) {
}

CqlIf::~CqlIf() {
    if (impl_) {
        delete impl_;
    }
}

// Init/Uninit
bool CqlIf::Db_Init(const std::string& task_id, int task_instance) {
    return impl_->ConnectSync();
}

void CqlIf::Db_Uninit(const std::string& task_id, int task_instance) {
    Db_UninitUnlocked(task_id, task_instance);
}

void CqlIf::Db_UninitUnlocked(const std::string& task_id,
    int task_instance) {
    impl_->DisconnectSync();
}

void CqlIf::Db_SetInitDone(bool init_done) {
    initialized_ = init_done;
}

// Tablespace
bool CqlIf::Db_AddSetTablespace(const std::string &tablespace,
    const std::string &replication_factor) {
    bool success(impl_->CreateKeyspaceIfNotExistsSync(tablespace,
        replication_factor, CASS_CONSISTENCY_QUORUM));
    if (!success) {
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_TABLESPACE);
        return success;
    }
    success = impl_->UseKeyspaceSync(tablespace, CASS_CONSISTENCY_ONE);
    if (!success) {
        IncrementErrors(GenDb::IfErrors::ERR_READ_TABLESPACE);
        return success;
    }
    return success;
}

bool CqlIf::Db_SetTablespace(const std::string &tablespace) {
    bool success(impl_->UseKeyspaceSync(tablespace, CASS_CONSISTENCY_ONE));
    if (!success) {
        IncrementErrors(GenDb::IfErrors::ERR_READ_TABLESPACE);
        return success;
    }
    return success;
}

// Column family
bool CqlIf::Db_AddColumnfamily(const GenDb::NewCf &cf) {
    bool success(
        impl_->CreateTableIfNotExistsSync(cf, CASS_CONSISTENCY_QUORUM));
    if (!success) {
        IncrementTableWriteFailStats(cf.cfname_);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN_FAMILY);
        return success;
    }
    // Locate (add if not exists) INSERT INTO prepare statement
    success = impl_->LocatePrepareInsertIntoTable(cf);
    if (!success) {
        IncrementTableWriteFailStats(cf.cfname_);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN_FAMILY);
        return success;
    }
    IncrementTableWriteStats(cf.cfname_);
    return success;
}

bool CqlIf::Db_UseColumnfamily(const GenDb::NewCf &cf) {
    // Check existence of table
    bool success(impl_->IsTablePresent(cf));
    if (!success) {
        IncrementTableReadFailStats(cf.cfname_);
        IncrementErrors(GenDb::IfErrors::ERR_READ_COLUMN_FAMILY);
        return success;
    }
    IncrementTableReadStats(cf.cfname_);
    return success;
}

// Column
void CqlIf::OnAsyncColumnAddCompletion(GenDb::DbOpResult::type drc,
    std::string cfname, GenDb::GenDbIf::DbAddColumnCb cb) {
    if (drc == GenDb::DbOpResult::OK) {
        IncrementTableWriteStats(cfname);
    } else if (drc == GenDb::DbOpResult::BACK_PRESSURE) {
        IncrementTableWriteBackPressureFailStats(cfname);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN);
    } else {
        IncrementTableWriteFailStats(cfname);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN);
    }
    if (!cb.empty()) {
        cb(drc);
    }
}

bool CqlIf::Db_AddColumn(std::auto_ptr<GenDb::ColList> cl) {
    return Db_AddColumn(cl, GenDb::GenDbIf::DbAddColumnCb());
}

bool CqlIf::Db_AddColumn(std::auto_ptr<GenDb::ColList> cl,
    GenDb::GenDbIf::DbAddColumnCb cb) {
    std::string cfname(cl->cfname_);
    if (!initialized_) {
        IncrementTableWriteFailStats(cfname);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN);
        return false;
    }
    bool success;
    if (use_prepared_for_insert_ &&
        impl_->IsInsertIntoTablePrepareSupported(cfname)) {
        success = impl_->InsertIntoTablePrepareAsync(cl, CASS_CONSISTENCY_ONE,
            boost::bind(&CqlIf::OnAsyncColumnAddCompletion, this, _1, cfname,
            cb));
    } else {
        success = impl_->InsertIntoTableAsync(cl, CASS_CONSISTENCY_ONE,
            boost::bind(&CqlIf::OnAsyncColumnAddCompletion, this, _1, cfname,
            cb));
    }
    if (!success) {
        IncrementTableWriteFailStats(cfname);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN);
        return success;
    }
    return success;
}

bool CqlIf::Db_AddColumnSync(std::auto_ptr<GenDb::ColList> cl) {
    std::string cfname(cl->cfname_);
    bool success(impl_->InsertIntoTableSync(cl, CASS_CONSISTENCY_ONE));
    if (!success) {
        IncrementTableWriteFailStats(cfname);
        IncrementErrors(GenDb::IfErrors::ERR_WRITE_COLUMN);
        return success;
    }
    IncrementTableWriteStats(cfname);
    return success;
}

// Read
bool CqlIf::Db_GetRow(GenDb::ColList *out, const std::string &cfname,
    const GenDb::DbDataValueVec &rowkey) {
    bool success(impl_->SelectFromTableSync(cfname, rowkey,
        CASS_CONSISTENCY_ONE, &out->columns_));
    if (!success) {
        IncrementTableReadFailStats(cfname);
        IncrementErrors(GenDb::IfErrors::ERR_READ_COLUMN);
        return success;
    }
    IncrementTableReadStats(cfname);
    return success;
}

bool CqlIf::Db_GetMultiRow(GenDb::ColListVec *out, const std::string &cfname,
    const std::vector<GenDb::DbDataValueVec> &v_rowkey) {
    BOOST_FOREACH(const GenDb::DbDataValueVec &rkey, v_rowkey) {
        std::auto_ptr<GenDb::ColList> v_columns(new GenDb::ColList);
        // Partition Key
        v_columns->rowkey_ = rkey;
        bool success(impl_->SelectFromTableSync(cfname, rkey,
            CASS_CONSISTENCY_ONE, &v_columns->columns_));
        if (!success) {
            CQLIF_LOG_ERR("SELECT FROM Table: " << cfname << " Partition Key: "
                << GenDb::DbDataValueVecToString(rkey) << " FAILED");
            IncrementTableReadFailStats(cfname);
            IncrementErrors(GenDb::IfErrors::ERR_READ_COLUMN);
            return false;
        }
        out->push_back(v_columns.release());
    }
    IncrementTableReadStats(cfname, v_rowkey.size());
    return true;
}

bool CqlIf::Db_GetMultiRow(GenDb::ColListVec *out, const std::string &cfname,
    const std::vector<GenDb::DbDataValueVec> &v_rowkey,
    const GenDb::ColumnNameRange &crange) {
    BOOST_FOREACH(const GenDb::DbDataValueVec &rkey, v_rowkey) {
        std::auto_ptr<GenDb::ColList> v_columns(new GenDb::ColList);
        // Partition Key
        v_columns->rowkey_ = rkey;
        bool success(impl_->SelectFromTableClusteringKeyRangeSync(cfname,
            rkey, crange, CASS_CONSISTENCY_ONE, &v_columns->columns_));
        if (!success) {
            CQLIF_LOG_ERR("SELECT FROM Table: " << cfname << " Partition Key: "
                << GenDb::DbDataValueVecToString(rkey) <<
                " Clustering Key Range: " << crange.ToString() << " FAILED");
            IncrementTableReadFailStats(cfname);
            IncrementErrors(GenDb::IfErrors::ERR_READ_COLUMN);
            return false;
        }
        out->push_back(v_columns.release());
    }
    IncrementTableReadStats(cfname, v_rowkey.size());
    return true;
}

// Queue
bool CqlIf::Db_GetQueueStats(uint64_t *queue_count,
        uint64_t *enqueues) const {
    //return impl_->Db_GetQueueStats(queue_count, enqueues);
    return true;
}

void CqlIf::Db_SetQueueWaterMark(bool high, size_t queue_count,
        GenDb::GenDbIf::DbQueueWaterMarkCb cb) {
    //impl_->Db_SetQueueWaterMark(high, queue_count, cb);
}

void CqlIf::Db_ResetQueueWaterMarks() {
    //impl_->Db_ResetQueueWaterMarks();
}

// Stats
bool CqlIf::Db_GetStats(std::vector<GenDb::DbTableInfo> *vdbti,
        GenDb::DbErrors *dbe) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.GetDiffs(vdbti, dbe);
    return true;
}

bool CqlIf::Db_GetCumulativeStats(std::vector<GenDb::DbTableInfo> *vdbti,
        GenDb::DbErrors *dbe) const {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.GetCumulative(vdbti, dbe);
    return true;
}

void CqlIf::Db_GetCqlMetrics(Metrics *metrics) const {
    impl_->GetMetrics(metrics);
}

void CqlIf::Db_GetCqlStats(DbStats *db_stats) const {
    Metrics metrics;
    impl_->GetMetrics(&metrics);
    db_stats->requests_one_minute_rate = metrics.requests.one_minute_rate;
    db_stats->stats = metrics.stats;
    db_stats->errors = metrics.errors;
}

void CqlIf::IncrementTableWriteStats(const std::string &table_name) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableWrite(table_name);
}

void CqlIf::IncrementTableWriteStats(const std::string &table_name,
    uint64_t num_writes) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableWrite(table_name, num_writes);
}

void CqlIf::IncrementTableWriteFailStats(const std::string &table_name) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableWriteFail(table_name);
}

void CqlIf::IncrementTableWriteFailStats(const std::string &table_name,
    uint64_t num_writes) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableWriteFail(table_name, num_writes);
}

void CqlIf::IncrementTableWriteBackPressureFailStats(
    const std::string &table_name) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableWriteBackPressureFail(table_name);
}

void CqlIf::IncrementTableReadStats(const std::string &table_name) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableRead(table_name);
}

void CqlIf::IncrementTableReadStats(const std::string &table_name,
    uint64_t num_reads) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableRead(table_name, num_reads);
}

void CqlIf::IncrementTableReadFailStats(const std::string &table_name) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableReadFail(table_name);
}

void CqlIf::IncrementTableReadFailStats(const std::string &table_name,
    uint64_t num_reads) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementTableReadFail(table_name, num_reads);
}

void CqlIf::IncrementErrors(GenDb::IfErrors::Type err_type) {
    tbb::mutex::scoped_lock lock(stats_mutex_);
    stats_.IncrementErrors(err_type);
}

// Connection
std::vector<GenDb::Endpoint> CqlIf::Db_GetEndpoints() const {
    return endpoints_;
}

}  // namespace cql
}  // namespace cass
