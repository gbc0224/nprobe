#include "createdate.h"
#include "test.pb.h"
using namespace test;
extern "C" char * create_date(V9V10TemplateElementId **elem, int now, int final_flush){
	/*fastbit infastbit;
	infastbit.set_num_entries(10);
	infastbit.set_max_num_entries(100);
	infastbit.set_fb_element_len(1000);
	fb_element_meta* infb = infastbit.add_fb_element();
	//fb_element_meta * userInfo = buddyInfo->mutable_userinfo()
	infb->set_id(1);
	infb->add_data(3378);
	infb->add_data(3379);
	infb->add_data(3380);
	std::string str;
	infastbit.SerializeToString(&str);
	fastbit outfastbit;
	outfastbit.ParseFromString(str);
	int length = infastbit.ByteSize();
	int BUFFERSIZE = infastbit.ByteSize();
	char* buf = new char[BUFFERSIZE];
	infastbit.SerializeToArray(buf,BUFFERSIZE);*/
	char * buf ={"abcd"};
	return buf;
}
int main(){
	return 0;
}