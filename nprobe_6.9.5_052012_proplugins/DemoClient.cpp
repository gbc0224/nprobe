/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <poll.h>

#include <iostream>

#include <boost/lexical_cast.hpp>
#include <protocol/TBinaryProtocol.h>
#include <transport/TSocket.h>
#include <transport/TTransportUtils.h>

#include "Hbase.h"

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

using namespace apache::hadoop::hbase::thrift;

namespace {

typedef std::vector<std::string> StrVec;
typedef std::map<std::string,std::string> StrMap;
typedef std::vector<ColumnDescriptor> ColVec;
typedef std::map<std::string,ColumnDescriptor> ColMap;
typedef std::vector<TCell> CellVec;
typedef std::map<std::string,TCell> CellMap;


static void
printRow(const std::vector<TRowResult> &rowResult)
{
  for (size_t i = 0; i < rowResult.size(); i++) {
    std::cout << "row: " << rowResult[i].row << ", cols: ";
    for (CellMap::const_iterator it = rowResult[i].columns.begin();
         it != rowResult[i].columns.end(); ++it) {
      std::cout << it->first << " => " << it->second.value << "; ";
    }
    std::cout << std::endl;
  }
}

static void
printVersions(const std::string &row, const CellVec &versions)
{
  std::cout << "row: " << row << ", values: ";
  for (CellVec::const_iterator it = versions.begin(); it != versions.end(); ++it) {
    std::cout << (*it).value << "; ";
  }
  std::cout << std::endl;
}

}
int gbc(){
    std::cout << "row:  values: ";
}
int
main(int argc, char** argv)
{
  bool isFramed = false;
  boost::shared_ptr<TTransport> socket(new TSocket("localhost", 9090));
  boost::shared_ptr<TTransport> transport;

  if (isFramed) {
    transport.reset(new TFramedTransport(socket));
  } else {
    transport.reset(new TBufferedTransport(socket));
  }
  boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

  const std::map<Text, Text>  dummyAttributes; // see HBASE-6806 HBASE-4658
  HbaseClient client(protocol);
  try {
    transport->open();

    std::string t[]= {"T1","T2","T3","T4","T5","T6","T7","T8"};

    //
    // Scan all tables, look for the demo table and delete it.
    //
    std::cout << "scanning tables..." << std::endl;
    StrVec tables;
    client.getTableNames(tables);
    int i;
    for(i=0; i<8; i++)
        {
    for (StrVec::const_iterator it = tables.begin(); it != tables.end(); ++it) {
      if (t[i] == *it) {
        if (client.isTableEnabled(*it)) {
          std::cout << "    disabling table: " << *it << std::endl;
          client.disableTable(*it);
        }
        std::cout << "    deleting table: " << *it << std::endl;
        client.deleteTable(*it);
      }
    }
}
return 0;

    transport->close();
  } catch (const TException &tx) {
    std::cerr << "ERROR: " << tx.what() << std::endl;
  }
}
