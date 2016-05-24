#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include "fastbit.grpc.pb.h"
#include <grpc++/grpc++.h>
#include <pthread.h>
using namespace grpc;
using namespace profastbit;
using namespace std;
#include <thread>
#include <iostream>
#include <memory>
#include <string>
#include<queue>
#include <exception>
#define MY_IP_PORT1 "127.0.0.1:6000"
#define MY_IP_PORT2 "127.0.0.1:7000"
#define MY_IP_PORT3 "127.0.0.1:8000"
#define MY_IP_PORT4 "127.0.0.1:9000"
#define BUFSIZE 1024
#define BACKLOG 2
#define MY_IP "127.0.0.1"
int receivenum,bufnum,num;
char buf [1024000];
char receivebuf[1024000];
char cmd[256];
int fastbit_add_values(const char * colname,const char * coltype,void *vals,int nelem,int start);
int fastbit_flush_buffer(const char *dir);
int receive_data(prodata receive_data);
queue<prodata> sourcedata;
void* HandleRpcs(void* arg);
class ServerImpl final {
 public:
 ServerImpl(){
 }
  ~ServerImpl() {
    server_->Shutdown();
    cq_->Shutdown();
  }
   std::unique_ptr<ServerCompletionQueue> cq_;
   dump_fastbit::AsyncService service_;
    std::unique_ptr<Server> server_;
};
class CallData {
   public:
    CallData(dump_fastbit::AsyncService* service, ServerCompletionQueue* cq)
        : service_(service), cq_(cq), responder_(&ctx_), status_(CREATE) {
      Proceed();
    }
    void Proceed() {
      if (status_ == CREATE) {//请求一个 RPC 提供唯一的标签初始化调用
        status_ = PROCESS;
        service_->Requestdumptofast(&ctx_, &request_, &responder_, cq_, cq_,
                                  this);
      } else if (status_ == PROCESS) {//真实处理过程
        new CallData(service_, cq_);
        //pthread_mutex_t taglock;
        //pthread_mutex_init(&taglock,NULL);   //初始化锁
        //pthread_mutex_lock(&taglock);
        int dumpnum =receive_data(request_);
        //pthread_mutex_unlock(&taglock);
        //pthread_mutex_destroy(&taglock);
        reply_.set_ret(dumpnum);
        status_ = FINISH;
        responder_.Finish(reply_, Status::OK, this);
      } else {
        GPR_ASSERT(status_ == FINISH);
        delete this;
      }
    }
    dump_fastbit::AsyncService* service_;
    ServerCompletionQueue* cq_;
    ServerContext ctx_;
	prodata request_;
    datareply reply_;
    ServerAsyncResponseWriter<datareply> responder_;
    enum CallStatus { CREATE, PROCESS, FINISH };
    CallStatus status_;
};
void* HandleRpcs(void* arg) {
    ServerImpl *Server2 = (ServerImpl*) arg ;
    new CallData(&(Server2->service_), (Server2->cq_).get());
    void* tag;
    bool ok;
    while (true) {
      (Server2->cq_)->Next(&tag, &ok);
      GPR_ASSERT(ok);
      static_cast<CallData*>(tag)->Proceed();
    }
}
void Run() {//构建一个服务器导出异步服务
    ServerImpl* server=new ServerImpl();
    std::string server_address("0.0.0.0:6000");
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterAsyncService(&(server->service_));
    server->cq_ = builder.AddCompletionQueue();
    server->server_ = builder.BuildAndStart();
    std::cout << "Server listening on " << server_address << std::endl;
    pthread_t thdId[3];
	pthread_create(&thdId[0], NULL, HandleRpcs,(void *)server);
	//pthread_create(&thdId[1], NULL, HandleRpcs,(void *)server);
	//pthread_create(&thdId[2], NULL, HandleRpcs,(void *)server);
	int iRet = 0;
	pthread_join(thdId[0],(void **)&iRet);  //接收子线程的返回值*/
	//pthread_join(thdId[1],(void **)&iRet);  //接收子线程的返回值*/
	//pthread_join(thdId[2],(void **)&iRet);  //接收子线程的返回值*/
}
class dumpServiceImpl final : public dump_fastbit::Service {//service
  Status dumptofast(ServerContext* context, const prodata* request,
		  datareply* reply) override {
	  //pthread_mutex_lock(&dirlock);
	// cout<<" pthread_mutex_lock "<<endl;
	sourcedata.push(*request);
	//cout<<sourcedata.front()<<endl;
	//const prodata* aaa=sourcedata.front();
	//sourcedata.pop();
	//int dumpnum =receive_data(aaa);
	//pthread_mutex_unlock(&dirlock);
	//cout<<" pthread_mutex_unlock "<<endl;
	int dumpnum =1;
	  reply->set_ret(dumpnum);
	  if(dumpnum > 0){
		  return Status::OK;
	  }else{
		  return Status::CANCELLED;
	  }
  }
};
void* dump(void* args){//同步调用处理任务接口
	while(1){
		if(!sourcedata.empty()){
		prodata aaa=sourcedata.front();
		sleep(2);
		cout<<sourcedata.size()<<endl;
		sourcedata.pop();
		receive_data(aaa);
		}
	}
}
void* RunServer(void* MY_IP_PORT) {//同步调用服务端
  std::string server_address((char*)MY_IP_PORT);
  dumpServiceImpl service;
    ServerBuilder builder;
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&service);
    // Finally assemble the server.
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}
int receive_data(prodata receive_data){//
	//puts("...............START...............");
	//printf("receive_data->ByteSize() =%d\n",receive_data->ByteSize());
	int idtemplateelement,fb_idx,iterations;//列名下标，数据数组下标
	TemplateElementId templateelement;
	fb_element  fb_element;
	//printf("receive_data->fb_elementlen() =%d\n",receive_data->fb_elementlen());
	char *fb_type = NULL;
	for (idtemplateelement=0,fb_idx=0;(idtemplateelement< receive_data.templateelement_size()) && (fb_idx<receive_data.fb_elementlen());idtemplateelement++){
		templateelement = receive_data.templateelement(idtemplateelement);
		if (templateelement.templateelementlen() == 1){
			fb_type = (char*)"byte",iterations=1;
		}else if (templateelement.templateelementlen() == 2){
			fb_type = (char*)"ushort",iterations=1;
		}else if (templateelement.templateelementlen() == 4 ){
			fb_type = (char*)"uint",iterations=1;
		}else if (templateelement.templateelementlen() == 16){
			fb_type = (char*)"uint",iterations=4;
		}
		//printf("netflowelementname =%s fb_type = %s  iterations =%d\n",templateelement.netflowelementname().c_str(),fb_type,iterations);
		while(iterations--){
			fb_element = receive_data.fb_element(fb_idx++);
			if(fb_element.fb_element_data_size()>0){
				if((int)fb_element.fb_element_data(0).length()>0){
					//printf("fb_element.fb_element_data(0).length()= %d \n",(int)fb_element.fb_element_data(0).length());
					char *data;
					int len = (int)fb_element.fb_element_data(0).length();
					data = (char *)malloc((len+1)*sizeof(char));
					fb_element.fb_element_data(0).copy(data,len,0);
					int mm ;
					for(mm =0;mm<8;mm++){
						//printf("data[%d] = %d\n",mm,data[mm]);
					}
					fastbit_add_values(templateelement.netflowelementname().c_str(),fb_type,data,receive_data.num_entries(),0);
				}
			}
		}
	}
	if(access(receive_data.dump_dir().c_str(), F_OK) !=0){
		snprintf(cmd, sizeof(cmd), "mkdir -p %s",receive_data.dump_dir().c_str());
		int ret = system(cmd);
	}
    int dumpnum = fastbit_flush_buffer(receive_data.dump_dir().c_str());
	return dumpnum;
}
int fastbit_add_values(const char * colname,const char * coltype,void *vals,int nelem,int start){
	void * libm_handle = NULL;
	int (*cosf_method)();
	int (*myadd)(char *colname,char *coltype,
		   void *vals, int nelem, int start);
	typedef int (*add_t)(const char *colname,const char *coltype,
		   void *vals, int nelem, int start);
	char *errorInfo;
	int result;
	libm_handle = dlopen("libfastbit.so", RTLD_LAZY );
	if (!libm_handle){
		// 如果返回 NULL 句柄,通过dlerror方法可以取得无法访问对象的原因
		printf("Open Error:%s.\n",dlerror());
		return 0;
		}
// 使用 dlsym 函数，尝试解析新打开的对象文件中的符号。您将会得到一个有效的指向该符号的指针，或者是得到一个 NULL 并返回一个错误
	add_t add = (add_t)dlsym(libm_handle,"fastbit_add_values");
	//char *,char *,void *, int , int
	errorInfo = dlerror();// 调用dlerror方法，返回错误信息的同时，内存中的错误信息被清空
	if (errorInfo != NULL){
		printf("Dlsym Error:%s.\n",errorInfo);
		return 0;
		}
// 执行“cosf”方法
	result = add(colname,coltype,vals,nelem,start);
	//colname,coltype,vals,nelem,start
	//printf("fastbit_add_values result = %d \n",result);
	// 调用 ELF 对象中的目标函数后，通过调用 dlclose 来关闭对它的访问
	dlclose(libm_handle);
	return result;
}
int fastbit_flush_buffer(const char *dir){
	void * libm_handle = NULL;
	typedef int (*add_t)(const char *dir);
	char *errorInfo;
	int result;
	libm_handle = dlopen("libfastbit.so", RTLD_LAZY );
	if (!libm_handle){
		// 如果返回 NULL 句柄,通过dlerror方法可以取得无法访问对象的原因
		printf("Open Error:%s.\n",dlerror());
		return 0;
		}
// 使用 dlsym 函数，尝试解析新打开的对象文件中的符号。您将会得到一个有效的指向该符号的指针，或者是得到一个 NULL 并返回一个错误
	add_t add = (add_t)dlsym(libm_handle,"fastbit_flush_buffer");
	//char *,char *,void *, int , int
	errorInfo = dlerror();// 调用dlerror方法，返回错误信息的同时，内存中的错误信息被清空
	if (errorInfo != NULL){
		printf("Dlsym Error:%s.\n",errorInfo);
		return 0;
		}
// 执行“cosf”方法
	result = add(dir);
	//colname,coltype,vals,nelem,start
	printf("fastbit_flush_buffer result = %d \n",result);
	// 调用 ELF 对象中的目标函数后，通过调用 dlclose 来关闭对它的访问
	dlclose(libm_handle);
	return result;
}
int main(int argc,char *argv[]){
	/*pthread_t thdId[4];
	pthread_mutex_init(&dirlock,NULL);   //初始化锁
	pthread_create(&thdId[1], NULL, RunServer, (void *)MY_IP_PORT1);
	pthread_create(&thdId[2], NULL, dump, NULL);
	int iRet = 0;
	pthread_join(thdId[1],(void **)&iRet);  //接收子线程的返回值*/
    Run();
	return 0;
}
