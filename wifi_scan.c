#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<errno.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<linux/wireless.h>
typedef struct stream_descr{
	char *end;
	char *current;
}stream_descr;
#define IW_HEADER_TYPE_NULL 0
#define IW_HEADER_TYPE_CHAR 2
#define IW_HEADER_TYPE_UINT 4
#define IW_HEADER_TYPE_FREQ 5
#define IW_HEADER_TYPE_ADDR 6
#define IW_HEADER_TYPE_POINT 8
#define IW_HEADER_TYPE_PARAM 9
#define IW_HEADER_TYPE_QUAL 10
static const char standard_ioctl_hdr[]={
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_CHAR,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_FREQ,
	IW_HEADER_TYPE_FREQ,
	IW_HEADER_TYPE_UINT,
	IW_HEADER_TYPE_UINT,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_ADDR,
	IW_HEADER_TYPE_ADDR,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_PARAM,
	IW_HEADER_TYPE_PARAM
};
static const int event_type_size[]={
	IW_EV_LCP_LEN,
	0,
	IW_EV_CHAR_LEN,
	0,
	IW_EV_UINT_LEN,
	IW_EV_FREQ_LEN,
	IW_EV_ADDR_LEN,
	0,
	IW_EV_POINT_LEN,
	IW_EV_PARAM_LEN,
	IW_EV_QUAL_LEN
};
void iw_init_event_stream(struct stream_descr* stream,char* data,int len){
	memset((char*)stream,'\0',sizeof(struct stream_descr));
	stream->current=data;
	stream->end=data+len;
}
int iw_extract_event_stream(struct stream_descr* stream,struct iw_event* iwe){
	int event_type=0;
	unsigned int event_len=1;
	unsigned cmd_index;
	if((stream->current+IW_EV_LCP_LEN)>stream->end)
		return 0;
	memcpy((char*)iwe,stream->current,sizeof(iwe->cmd+iwe->len));
	cmd_index=iwe->cmd-SIOCIWFIRST;
	event_type=standard_ioctl_hdr[cmd_index];
	event_len=event_type_size[event_type];
	if(event_len<=IW_EV_LCP_LEN){
		stream->current+=iwe->len;
		return 2;
	}
	event_len-=IW_EV_LCP_LEN;
	memcpy((char*)iwe,stream->current,event_len);
	if(event_type==IW_HEADER_TYPE_POINT){
		iwe->u.data.pointer=stream->current+IW_EV_LCP_LEN+event_len;
		stream->current+=iwe->len;
	}else
		stream->current+=iwe->len;
	return 1;
}
static inline int print_scanning_token(struct iw_event* event){
	if(event->cmd==SIOCGIWESSID){
		if((event->u.essid.flags & IW_ENCODE_INDEX)>1){
			printf("ESSID: %30s   flag: %d	NWID: %X\n",event->u.essid.pointer,(event->u.essid.flags&IW_ENCODE_INDEX),event->u.nwid.value);
			if(event->u.essid.flags&IW_ENCODE_OPEN)
				printf("Encryption mode:open\n");
			else if(event->u.essid.flags&IW_ENCODE_RESTRICTED)
				printf("Encrytion mode:restricted\n");
			else 
				printf("Encryption mode:unknown\n");
		}else
			printf("ESSID: %30s\n",event->u.essid.pointer);
	}
}
int main(void){
	struct iwreq w={0};
	unsigned char buf[IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA];
	int s=socket(AF_INET,SOCK_DGRAM,0);
	strncpy(w.ifr_name,"wlan0",IFNAMSIZ);
	ioctl(s,SIOCSIWSCAN,&w);
	while(1){
		system("sudo systemctl restart dhcpcd");
		system("sleep 2");
		w.u.data.pointer=buf;
		w.u.data.flags=0;
		w.u.data.length=sizeof buf;
		strncpy(w.ifr_name,"wlan0",IFNAMSIZ);
		if(ioctl(s,SIOCGIWSCAN,&w)<0){
			fprintf(stderr,"failed to read scan data:%s\n\n",strerror(errno));
			return -2;
		}
		if(w.u.data.length){
			struct iw_event iwe={0};
			struct stream_descr stream={0};
			int ret;
			iw_init_event_stream(&stream,buf,w.u.data.length);
			do{
				ret=iw_extract_event_stream(&stream,&iwe);
				print_scanning_token(&iwe);
			}while(ret>0);
			printf("\n");
		}else
				printf("no result\n");
	}
	return 0;
}

