#include "nprobe.h"
#ifdef __cplusplus
extern "C" {
#endif
	int create_pthread();
	int test_table();
	int save_hbase(int numFlows,unsigned int first);
	int senddata(V9V10TemplateElementId **elem, time_t now, u_int8_t final_flush,char* MY_IP_PORT);
#ifdef __cplusplus
}
#endif
