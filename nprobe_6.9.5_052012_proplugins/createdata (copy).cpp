#include "nprobe.h"
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
prodata create_data(V9V10TemplateElementId **elem, time_t now,
		u_int8_t final_flush) {
	int i, j, fb_idx;
	prodata prodata;
	prodata.set_dump_dir(readWriteGlobals->fastbit_actual_dump_dir);
	prodata.set_num_entries(readWriteGlobals->fastbit.num_entries);
	for (i = 0; i < TEMPLATE_LIST_LEN; i++) {
		prodata.add_fastbit_dump_switch(
				readWriteGlobals->fastbit_dump_switch[i]);
	}
	TemplateElementId* TemplateElementId; //moban
	fb_element* fb_element; //shuju
	for (i = 0, fb_idx = 0; i < TEMPLATE_LIST_LEN; i++) {
		if (elem[i] != NULL && readWriteGlobals->fastbit_dump_switch[i] == 1) {
			TemplateElementId = prodata.add_templateelement(); //mobantianjia
			TemplateElementId->set_templateelementlen(
					elem[i]->templateElementLen);
			TemplateElementId->set_netflowelementname(
					elem[i]->netflowElementName);
			if (elem[i]->templateElementLen == 16) {
				for (j = 0; j < 4; j++) {
					fb_element = prodata.add_fb_element(); //shujutianjia
					fb_element->add_fb_element_data(
							readWriteGlobals->fastbit.fb_element[fb_idx++],
							readWriteGlobals->fastbit.num_entries * 4);
				}
			} else {
				fb_element = prodata.add_fb_element(); //shujutianjia
				if (elem[i]->templateElementLen == 1) {
					fb_element->add_fb_element_data(
							readWriteGlobals->fastbit.fb_element[fb_idx++],
							readWriteGlobals->fastbit.num_entries);
				} else if (elem[i]->templateElementLen == 2) {
					fb_element->add_fb_element_data(
							readWriteGlobals->fastbit.fb_element[fb_idx++],
							readWriteGlobals->fastbit.num_entries * 2);
				} else if (elem[i]->templateElementLen == 4) {
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
class dumpClient {
 public:
  explicit dumpClient(std::shared_ptr<Channel> channel)
      : stub_(dump_fastbit::NewStub(channel)) {}

  // Assambles the client's payload, sends it and presents the response back
  // from the server.
  int dumptofast(prodata data) {
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
    if (status.ok()) {
      return 1;
    } else {
      return 0;
    }
  }
 private:
  // Out of the passed in Channel comes the stub, stored here, our view of the
  // server's exposed services.
  std::unique_ptr<dump_fastbit::Stub> stub_;
};
extern "C" int senddata(V9V10TemplateElementId **elem, time_t now,
		u_int8_t final_flush,char *MY_IP_PORT) {
	prodata prodata = create_data(elem, now, final_flush);
	dumpClient dumpclient(
			grpc::CreateChannel(MY_IP_PORT,
					grpc::InsecureChannelCredentials()));
	int reply = dumpclient.dumptofast(prodata);
	cout << "dumpclient received: " << reply << endl;
	return 0;
}

