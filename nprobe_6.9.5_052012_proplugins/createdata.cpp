#include "nprobe.h"
#include "Hbase.h"
#include "fastbit.pb.h"
#include <grpc++/grpc++.h>
#include "fastbit.grpc.pb.h"
using namespace profastbit;
using namespace std;
using namespace grpc;
#include <iostream>
#include <memory>
#include <string>
#include <exception>
#define MY_IP_PORT1 "127.0.0.1:8000"
#define MY_IP_PORT2 "127.0.0.1:9000"

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

prodata create_data(V9V10TemplateElementId **elem, time_t now,
                    u_int8_t final_flush)
{
    int i, j, fb_idx;
    prodata prodata;
    prodata.set_dump_dir(readWriteGlobals->fastbit_actual_dump_dir);
    prodata.set_num_entries(readWriteGlobals->fastbit.num_entries);
    for (i = 0; i < TEMPLATE_LIST_LEN; i++)
    {
        prodata.add_fastbit_dump_switch(
            readWriteGlobals->fastbit_dump_switch[i]);
    }
    TemplateElementId* TemplateElementId; //moban
    fb_element* fb_element; //shuju
    for (i = 0, fb_idx = 0; i < TEMPLATE_LIST_LEN; i++)
    {
        if (elem[i] != NULL && readWriteGlobals->fastbit_dump_switch[i] == 1)
        {
            TemplateElementId = prodata.add_templateelement(); //mobantianjia
            TemplateElementId->set_templateelementlen(
                elem[i]->templateElementLen);
            TemplateElementId->set_netflowelementname(
                elem[i]->netflowElementName);
            if (elem[i]->templateElementLen == 16)
            {
                for (j = 0; j < 4; j++)
                {
                    fb_element = prodata.add_fb_element(); //shujutianjia
                    fb_element->add_fb_element_data(
                        readWriteGlobals->fastbit.fb_element[fb_idx++],
                        readWriteGlobals->fastbit.num_entries * 4);
                }
            }
            else
            {
                fb_element = prodata.add_fb_element(); //shujutianjia
                if (elem[i]->templateElementLen == 1)
                {
                    fb_element->add_fb_element_data(
                        readWriteGlobals->fastbit.fb_element[fb_idx++],
                        readWriteGlobals->fastbit.num_entries);
                }
                else if (elem[i]->templateElementLen == 2)
                {
                    fb_element->add_fb_element_data(
                        readWriteGlobals->fastbit.fb_element[fb_idx++],
                        readWriteGlobals->fastbit.num_entries * 2);
                }
                else if (elem[i]->templateElementLen == 4)
                {
                    fb_element->add_fb_element_data(
                        readWriteGlobals->fastbit.fb_element[fb_idx++],
                        readWriteGlobals->fastbit.num_entries * 4);
                }
            }
        }
    }
    prodata.set_fb_elementlen(fb_idx);
    return prodata;
}
class dumpClient
{
public:
    explicit dumpClient(std::shared_ptr<Channel> channel)
        : stub_(dump_fastbit::NewStub(channel)) {}

    // Assambles the client's payload, sends it and presents the response back
    // from the server.
    int dumptofast(prodata data)
    {
        // Data we are sending to the server.

        // Container for the data we expect from the server.
        datareply reply;//返回参数

        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;//附加信息

        // The producer-consumer queue we use to communicate asynchronously with the
        // gRPC runtime.
        CompletionQueue cq;//任务队列

        // Storage for the status of the RPC upon completion.
        Status status;

        // stub_->AsyncSayHello() perform the RPC call, returning an instance we
        // store in "rpc". Because we are using the asynchronous API, we need the
        // hold on to the "rpc" instance in order to get updates on the ongoig RPC.
        std::unique_ptr<ClientAsyncResponseReader<datareply> > rpc(
            stub_->Asyncdumptofast(&context, data, &cq));//远程访问存根
        // Request that, upon completion of the RPC, "reply" be updated with the
        // server's response; "status" with the indication of whether the operation
        // was successful. Tag the request with the integer 1.
        rpc->Finish(&reply, &status, (void*)1);//用一个唯一的标签，寻求回答和最终的状态
        void* got_tag;
        bool ok = false;
        // Block until the next result is available in the completion queue "cq".
        cq.Next(&got_tag, &ok);

        // Verify that the result from "cq" corresponds, by its tag, our previous
        // request.
        GPR_ASSERT(got_tag == (void*)1);
        // ... and that the request was completed successfully. Note that "ok"
        // corresponds solely to the request for updates introduced by Finish().
        GPR_ASSERT(ok);
        // Act upon the status of the actual RPC.
        if (status.ok())
        {
            return reply.ret();
        }
        else
        {
            return 0;
        }
    }
private:
    // Out of the passed in Channel comes the stub, stored here, our view of the
    // server's exposed services.
    std::unique_ptr<dump_fastbit::Stub> stub_;
};
extern "C" int senddata(V9V10TemplateElementId **elem, time_t now,
                        u_int8_t final_flush,char *MY_IP_PORT)
{
    prodata prodata = create_data(elem, now, final_flush);
    dumpClient dumpclient(
        grpc::CreateChannel(MY_IP_PORT,
                            grpc::InsecureChannelCredentials()));
    int reply = dumpclient.dumptofast(prodata);
    cout << "dumpclient received: " << reply << endl;
    return 0;
}
namespace
{

typedef std::vector<std::string> StrVec;
typedef std::map<std::string,std::string> StrMap;
typedef std::vector<ColumnDescriptor> ColVec;
typedef std::map<std::string,ColumnDescriptor> ColMap;
typedef std::vector<TCell> CellVec;
typedef std::map<std::string,TCell> CellMap;

static void
printRow(const std::vector<TRowResult> &rowResult)
{
    for (size_t i = 0; i < rowResult.size(); i++)
    {
        std::cout << "row: " << rowResult[i].row << ", cols: ";
        for (CellMap::const_iterator it = rowResult[i].columns.begin();
                it != rowResult[i].columns.end(); ++it)
        {
            std::cout << it->first << " => " << it->second.value << "; ";
        }
        std::cout << std::endl;
    }
}
static void
printVersions(const std::string &row, const CellVec &versions)
{
    std::cout << "row: " << row << ", values: ";
    for (CellVec::const_iterator it = versions.begin(); it != versions.end(); ++it)
    {
        std::cout << (*it).value << "; ";
    }
    std::cout << std::endl;
}
}
extern "C" int test_table()
{
    char buf[8][1024];
    int i;
    bool isFramed = false;
    bool tmptable = false;
    boost::shared_ptr<TTransport> socket(new TSocket("localhost", 9090));
    boost::shared_ptr<TTransport> transport;
    if (isFramed)
    {
        transport.reset(new TFramedTransport(socket));
    }
    else
    {
        transport.reset(new TBufferedTransport(socket));
    }
    boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

    const std::map<Text, Text>  dummyAttributes; // see HBASE-6806 HBASE-4658
    HbaseClient client(protocol);
    try
    {
        transport->open();
        std::string t[]= {"T1","T2","T3","T4","T5","T6","T7","T8"};
        StrVec tables;
        client.getTableNames(tables);

        for(i=0; i<8; i++)
        {
            tmptable = false;
            StrVec::const_iterator it = tables.begin();
            for (StrVec::const_iterator it = tables.begin(); it != tables.end(); ++it)
            {
                if (t[i] == *it)
                {
                    tmptable = true;
                }
            }
            if(!tmptable)//创建表
            {
                ColVec columns;
                columns.push_back(ColumnDescriptor());
                columns.back().name = "PROTOCOL";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "INPUT_SNMP";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "OUTPUT_SNMP";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "IN_PKTS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "IN_BYTES";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "SRC_TOS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "SRC_AS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "DST_AS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "TCP_FLAGS";
                std::cout << "creating table: " << t[i] << std::endl;
                try
                {
                    client.createTable(t[i], columns);
                }
                catch (const AlreadyExists &ae)
                {
                    std::cerr << "WARN: " << ae.message << std::endl;
                }
            }
        }
    }
    catch (const TException &tx)
    {
        std::cerr << "ERROR: " << tx.what() << std::endl;
    }
    return 0;
}
extern "C" int save_hbase(int numFlows,unsigned int first)
{
    char buf[8][1024];
    int i;
    bool isFramed = false;
    bool tmptable = false;
    boost::shared_ptr<TTransport> socket(new TSocket("localhost", 9090));
    boost::shared_ptr<TTransport> transport;
    if (isFramed)
    {
        transport.reset(new TFramedTransport(socket));
    }
    else
    {
        transport.reset(new TBufferedTransport(socket));
    }
    boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

    const std::map<Text, Text>  dummyAttributes; // see HBASE-6806 HBASE-4658
    HbaseClient client(protocol);
    try
    {
        transport->open();
        std::string t[]= {"T1","T2","T3","T4","T5","T6","T7","T8"};
        StrVec tables;
        client.getTableNames(tables);

        /*for(i=0; i<8; i++)
        {
            tmptable = false;
            StrVec::const_iterator it = tables.begin();
            for (StrVec::const_iterator it = tables.begin(); it != tables.end(); ++it)
            {
                if (t[i] == *it)
                {
                    tmptable = true;
                }
            }
            if(!tmptable)//创建表
            {
                ColVec columns;
                columns.push_back(ColumnDescriptor());
                columns.back().name = "PROTOCOL";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "INPUT_SNMP";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "OUTPUT_SNMP";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "IN_PKTS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "IN_BYTES";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "SRC_TOS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "SRC_AS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "DST_AS";
                columns.push_back(ColumnDescriptor());
                columns.back().name = "TCP_FLAGS";
                std::cout << "creating table: " << t[i] << std::endl;
                try
                {
                    client.createTable(t[i], columns);
                }
                catch (const AlreadyExists &ae)
                {
                    std::cerr << "WARN: " << ae.message << std::endl;
                }
            }
        }*/
        std::vector<Mutation> mutations;
        sprintf(buf[0], "[%u][%u][%u][%u][%d]",ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                first);
        sprintf(buf[1], "[%u][%u][%u][%u][%d]",ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                first);
        sprintf(buf[2], "[%u][%u][%u][%u][%d]",ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                first);
        sprintf(buf[3], "[%u][%u][%u][%u][%d]",ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                first);
        sprintf(buf[4], "[%u][%u][%u][%u][%d]",ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                first);
        sprintf(buf[5], "[%u][%u][%u][%u][%d]",ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                first);
        sprintf(buf[6], "[%u][%u][%u][%u][%d]",ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                first);
        sprintf(buf[7], "[%u][%u][%u][%u][%d]",ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstport),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcaddr),
                ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dstaddr),
                ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].srcport),
                first);
        std::string row[]= {buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]};
        std::vector<TRowResult> rowResult;
        mutations.clear();
        mutations.push_back(Mutation());
        mutations.back().column = "PROTOCOL:";
        mutations.back().value = boost::lexical_cast<std::string>((int)readWriteGlobals->theV5Flow.flowRecord[numFlows].proto);
        mutations.push_back(Mutation());
        mutations.back().column = "INPUT_SNMP:";
        mutations.back().value = boost::lexical_cast<std::string>(ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].input));
        mutations.push_back(Mutation());
        mutations.back().column = "OUTPUT_SNMP:";
        mutations.back().value = boost::lexical_cast<std::string>(ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].output));
        mutations.push_back(Mutation());
        mutations.back().column = "IN_PKTS:";
        mutations.back().value = boost::lexical_cast<std::string>(ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dPkts));
        mutations.push_back(Mutation());
        mutations.back().column = "IN_BYTES:";
        mutations.back().value = boost::lexical_cast<std::string>(ntohl(readWriteGlobals->theV5Flow.flowRecord[numFlows].dOctets));
        mutations.push_back(Mutation());
        mutations.back().column = "SRC_TOS:";
        mutations.back().value = boost::lexical_cast<std::string>((int)readWriteGlobals->theV5Flow.flowRecord[numFlows].tos);
        mutations.push_back(Mutation());
        mutations.back().column = "SRC_AS:";
        mutations.back().value = boost::lexical_cast<std::string>(ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].src_as));
        mutations.push_back(Mutation());
        mutations.back().column = "DST_AS:";
        mutations.back().value = boost::lexical_cast<std::string>(ntohs(readWriteGlobals->theV5Flow.flowRecord[numFlows].dst_as));
        mutations.push_back(Mutation());
        mutations.back().column = "TCP_FLAGS:";
        mutations.back().value = boost::lexical_cast<std::string>((int)readWriteGlobals->theV5Flow.flowRecord[numFlows].tcp_flags);
        for(i=0; i<8; i++)
        {
            client.mutateRow(t[i], row[i], mutations, dummyAttributes);
        }
        //client.getRow(rowResult, t, row, dummyAttributes);
        //printRow(rowResult);
    }
    catch (const TException &tx)
    {
        std::cerr << "ERROR: " << tx.what() << std::endl;
    }
    return 0;
}
