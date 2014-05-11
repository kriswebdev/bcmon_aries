#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module */
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for get_user and put_user */
#include <osl.h>

#include "bcmon.h"

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
   uint32_t ts_sec;         /* timestamp seconds */
   uint32_t ts_usec;        /* timestamp microseconds */
   uint32_t incl_len;       /* number of octets of packet saved in file */
   uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


// ugly kernel file i/o

struct file* file_open(const char* path, int flags, int rights) {
    struct file* filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if(IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file* file) {
    filp_close(file, NULL);
}

int file_write(struct file* file, unsigned long long offset, unsigned char* data, unsigned int size) {
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_sync(struct file* file) {
    vfs_fsync(file, 0);
    return 0;
}

// end of file i/o

unsigned long long foffset;
struct file* pFile;

void pcap_dump(uchar *buf, uint nbytes) {

	pcap_hdr_t fheader;
	pcaprec_hdr_t frame;

	// Write PCAP file header at first call
	if(foffset == 0) { // globals are initialized at 0
		pFile = file_open ("/data/tmp/out.pcap" , O_CREAT | O_WRONLY, 0); // open for writing in binary mode
				
		fheader.magic_number      =       0xa1b2c3d4;
		fheader.version_major     =       2;
		fheader.version_minor     =       4;
		fheader.thiszone          =       0;
		fheader.sigfigs           =       0;
		fheader.snaplen           =       65535;
		fheader.network           =       127; /* RADIOTAP */
	
		//fwrite (&fheader, 1, sizeof(fheader) , pFile);
		file_write (pFile, 0, (unsigned char *)&fheader, sizeof(pcap_hdr_t)); foffset+=sizeof(pcap_hdr_t);
	}
		

	// Write FRAME PCAP header
	frame.ts_sec=(uint32_t)foffset;
	frame.ts_usec=0;
	frame.incl_len=(uint32_t)nbytes; //!!	
	frame.orig_len=(uint32_t)nbytes; // !!
	file_write (pFile, foffset, (unsigned char *)&frame, sizeof(pcaprec_hdr_t)); foffset+=sizeof(pcaprec_hdr_t);
	
	// Write FRAME itself
	file_write (pFile, foffset, (unsigned char *)buf, nbytes); foffset+=nbytes;
		
	file_sync(pFile);
		
	//fclose(pFile); // sorry!
   
   return;
}


struct sk_buff* bcmon_decode_skb(struct sk_buff* skb)
{
	char radio_tap_header[15];
	char* data;
	unsigned int data_offset;
	unsigned int pkt_len;
	int rssi;
	char my_byte;

	data = skb->data;
	pkt_len = *(unsigned short*)data;
	skb_trim(skb, pkt_len);
	data_offset = 12+ 0x1e + 6;
	if(pkt_len<24)
		return 0;
	my_byte = data[12+12];
	if ((my_byte==5) || (my_byte==1))
		return 0;
	if (my_byte & 4)
		data_offset += 2;
	rssi = data[0x12];

	((unsigned int*)radio_tap_header)[0] = 0x000f0000; // it_version, it_pad, it_len
	((unsigned int*)radio_tap_header)[1] = 0x2a;
	radio_tap_header[8] = 0x10; // flags: FRAME_INC_FCS
	// TODO: extract frequency from packet
	((unsigned short*)(radio_tap_header+10))[0] = 2437; // frequency
	((unsigned short*)(radio_tap_header+10))[1] = 0x0080; // G2_SPEC
	radio_tap_header[14] = rssi;

	skb_pull(skb,data_offset);
	skb_push(skb,sizeof(radio_tap_header));
	//DHD_TRACE(("%s: sizeof(radio_tap_header)=%d\n", __FUNCTION__,sizeof(radio_tap_header)));
	memcpy(skb->data,radio_tap_header,sizeof(radio_tap_header));

	return skb;
}

void bcmon_loaded(void) {
	return;

}

EXPORT_SYMBOL(bcmon_loaded);

