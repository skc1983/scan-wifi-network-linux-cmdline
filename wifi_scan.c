#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<linux/types.h>
#include<linux/socket.h>
#include<sys/time.h>
#include<net/if.h>
#include<errno.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<linux/wireless.h>
typedef struct stream_descr{
	char *end;
	char *current;
	char *value;
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
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_NULL,
	IW_HEADER_TYPE_NULL,
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
static const unsigned int standard_ioctl_num=sizeof(standard_ioctl_hdr);
static const char standard_event_hdr[]={
	IW_HEADER_TYPE_ADDR,
	IW_HEADER_TYPE_QUAL,
	IW_HEADER_TYPE_POINT,
	IW_HEADER_TYPE_ADDR,
	IW_HEADER_TYPE_ADDR
};
static const unsigned int standard_event_num=sizeof(standard_event_hdr);
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
	char *pointer;
	unsigned cmd_index;
	if((stream->current+IW_EV_LCP_LEN)>stream->end)
		return 0;
	memcpy((char*)iwe,stream->current,IW_EV_LCP_LEN);
	if(iwe->len<=IW_EV_LCP_LEN)
		return -1;
	if(iwe->cmd<=SIOCIWLAST){
		cmd_index=iwe->cmd-SIOCIWFIRST;
		if(cmd_index<standard_ioctl_num)
			event_type=standard_ioctl_hdr[cmd_index];
	}else{
		cmd_index=iwe->cmd-IWEVFIRST;
		if(cmd_index<standard_event_num)
			event_type=standard_event_hdr[cmd_index];
	}
	event_len=event_type_size[event_type];
	if(event_len<=IW_EV_LCP_LEN){
		stream->current+=iwe->len;
		return 2;
	}
	event_len-=IW_EV_LCP_LEN;
	if(stream->value!=NULL)
		pointer=stream->value;
	else
		pointer=stream->current+IW_EV_LCP_LEN;
	if((pointer+event_len)>stream->end){
		stream->current+=iwe->len;
		return -2;
	}
	memcpy((char*)iwe+IW_EV_LCP_LEN,stream->current,event_len);
	pointer+=event_len;
	if(event_type==IW_HEADER_TYPE_POINT){
		if((iwe->len-(event_len+IW_EV_LCP_LEN))>0)
			iwe->u.data.pointer=pointer;
		else
			iwe->u.data.pointer=NULL;
		stream->current+=iwe->len;
	}else{
		if((pointer+event_len)<=(stream->current+iwe->len))
			stream->value=pointer;
		else{
			stream->value=NULL;
			stream->current+=iwe->len;
		}
	}
	return 1;
}
static inline int print_scanning_token(struct iw_event* event){
	if(event->cmd==SIOCGIWESSID){
		if((event->u.essid.flags & IW_ENCODE_INDEX)>1)
			printf("ESSID: %s   flag: %d\n",event->u.essid.pointer,(event->u.essid.flags&IW_ENCODE_INDEX));
		else
			printf("ESSID: %s\n",event->u.essid.pointer);
	}
}
int main(void){
	struct iwreq w={0};
	unsigned char buf[IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA+IW_SCAN_MAX_DATA];
	struct timeval tv={0};
	long int timeout=5000000;
	int s=socket(AF_INET,SOCK_DGRAM,0);
	tv.tv_sec=0;
	tv.tv_usec=25000;
	w.u.param.flags=IW_SCAN_DEFAULT;
	w.u.param.value=0;
	strncpy(w.ifr_name,"wlan0",IFNAMSIZ);
	ioctl(s,SIOCSIWSCAN,&w);
	timeout-=tv.tv_usec;
	while(1){
		system("sudo systemctl restart dhcpcd");
		system("sleep 2");
		while(1){
			fd_set rfds;
			int last_fd;
			int ret;
			FD_ZERO(&rfds);
			last_fd=-1;
			ret=select(last_fd+1,&rfds,NULL,NULL,&tv);
			if(ret==0){
				w.u.data.pointer=buf;
				w.u.data.flags=0;
				w.u.data.length=sizeof buf;
				strncpy(w.ifr_name,"wlan0",IFNAMSIZ);
				if(ioctl(s,SIOCGIWSCAN,&w)<0){
					if(errno==EAGAIN){
						tv.tv_sec=0;
						tv.tv_usec=10000;
						timeout-=tv.tv_usec;
						if(timeout>0)
							continue;
					}
					fprintf(stderr,"failed to read scan data:%s\n\n",strerror(errno));
						return -2;
				}else
					break;
			}
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
	close(s);
	return 0;
}
