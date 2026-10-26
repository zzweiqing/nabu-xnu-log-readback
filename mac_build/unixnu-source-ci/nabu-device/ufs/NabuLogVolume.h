/* Strict read-only GPT/FAT proof for a preallocated XNU2LOG.BIN in ESP.
 * Supported deliberately: LUN0 4K, GPT entries <=128 x128, FAT32 4K clusters,
 * two mirrored FATs, <=1 MiB per FAT, <=1024 directories. Fail closed otherwise.
 * The writer never updates a FAT, directory, GPT, or the config block.
 */
#ifndef NABU_LOG_VOLUME_H
#define NABU_LOG_VOLUME_H
#include "NabuLogFormat.h"
typedef int (*nb_log_read_fn)(void *,uint64_t,uint32_t,uint8_t *);
/* Coarse, non-secret reason for a refused volume. The writer reports the last
 * value verbatim in an IOLog line so a stopped writer names its failing gate
 * instead of only "writer stopped". No allocation token is included. */
enum nb_volume_failure {
  NBV_OK=0, NBV_LUN_BLOCKS, NBV_GPT_HEADER_READ, NBV_GPT_HEADER,
  NBV_GPT_HEADER_CRC, NBV_GPT_ENTRIES_READ, NBV_GPT_ENTRIES_CRC,
  NBV_GPT_ENTRY, NBV_GPT_ESP_ENTRY, NBV_ESP_BOOT_READ, NBV_ESP_BPB,
  NBV_ESP_GEOMETRY, NBV_FAT_MIRROR, NBV_ROOT_FILE, NBV_ROOT_FILE_ENTRY,
  NBV_FILE_CHAIN, NBV_FILE_ALIAS, NBV_CONFIG_READ, NBV_CONFIG
};
struct nb_log_volume {
  nb_log_read_fn read; void *context;
  uint64_t lun_blocks, esp_first, esp_blocks, file_first;
  uint32_t fat_first, fat_blocks, data_first, clusters, root, file_cluster;
  uint8_t token[16], fat[1024*1024], scratch[4096], entries[128*128];
  uint32_t directories[1024], reads;
  uint32_t failure; uint64_t failure_lba; uint32_t failure_blocks;
};
static inline const char *nb_volume_failure_name(uint32_t failure) {
  switch(failure) {
    case NBV_OK: return "ok";
    case NBV_LUN_BLOCKS: return "lun-blocks";
    case NBV_GPT_HEADER_READ: return "gpt-header-read";
    case NBV_GPT_HEADER: return "gpt-header";
    case NBV_GPT_HEADER_CRC: return "gpt-header-crc";
    case NBV_GPT_ENTRIES_READ: return "gpt-entries-read";
    case NBV_GPT_ENTRIES_CRC: return "gpt-entries-crc";
    case NBV_GPT_ENTRY: return "gpt-entry";
    case NBV_GPT_ESP_ENTRY: return "gpt-esp-entry";
    case NBV_ESP_BOOT_READ: return "esp-boot-read";
    case NBV_ESP_BPB: return "esp-bpb";
    case NBV_ESP_GEOMETRY: return "esp-geometry";
    case NBV_FAT_MIRROR: return "fat-mirror";
    case NBV_ROOT_FILE: return "root-file";
    case NBV_ROOT_FILE_ENTRY: return "root-file-entry";
    case NBV_FILE_CHAIN: return "file-chain";
    case NBV_FILE_ALIAS: return "file-alias";
    case NBV_CONFIG_READ: return "config-read";
    case NBV_CONFIG: return "config";
    default: return "unknown";
  }
}
static inline int nb_volume_fail(struct nb_log_volume *v,uint32_t failure) {
  v->failure=failure; return 0;
}
static inline int nb_vread(struct nb_log_volume *v,uint64_t lba,uint32_t n,uint8_t *p) {
  if(!n || lba>=v->lun_blocks || n>v->lun_blocks-lba || ++v->reads>8192) {
    v->failure_lba=lba; v->failure_blocks=n; return 0;
  }
  if(!v->read(v->context,lba,n,p)) {v->failure_lba=lba; v->failure_blocks=n; return 0;}
  return 1;
}
static inline uint32_t nb_fat(struct nb_log_volume *v,uint32_t c) {
  return nb_le32(v->fat+4*c)&0x0fffffff;
}
static inline int nb_cluster_ok(struct nb_log_volume *v,uint32_t c) { return c>=2 && c<v->clusters+2; }
static inline int nb_dir_read(struct nb_log_volume *v,uint32_t c) {
  return nb_cluster_ok(v,c) && nb_vread(v,v->esp_first+v->data_first+c-2,1,v->scratch);
}
static inline uint32_t nb_entry_cluster(const uint8_t *e) {
  return ((uint32_t)e[20]<<16)|((uint32_t)e[21]<<24)|e[26]|((uint32_t)e[27]<<8);
}
static inline int nb_find_root_file(struct nb_log_volume *v) {
  uint32_t c=v->root; unsigned found=0;
  for(unsigned step=0;step<64;step++) {
    if(!nb_dir_read(v,c)) return 0;
    for(unsigned at=0;at<4096;at+=32) {
      uint8_t *e=v->scratch+at;
      if(!e[0]) return found==1;
      if(e[0]==0xe5 || e[11]==15) continue;
      if(nb_equal(e,NB_LOG_NAME,11)) {
        if(e[11]!=0x20 || nb_le32(e+28)!=NB_LOG_FILE_BYTES || ++found!=1) return 0;
        v->file_cluster=nb_entry_cluster(e);
      }
    }
    c=nb_fat(v,c); if(c>=0x0ffffff8) return found==1;
  }
  return 0;
}
static inline int nb_no_aliases(struct nb_log_volume *v) {
  const uint32_t first=v->file_cluster,last=first+NB_LOG_FILE_BYTES/4096;
  /* No FAT chain outside this file may lead into one of its clusters. */
  for(uint32_t c=2;c<v->clusters+2;c++) {
    uint32_t next=nb_fat(v,c);
    if(next>=first && next<last && !(c>=first && c<last-1 && next==c+1)) return 0;
  }
  unsigned head=0,tail=1; v->directories[0]=v->root;
  while(head<tail) {
    uint32_t initial=v->directories[head++],c=initial;
    for(unsigned i=0;i<head-1;i++) if(v->directories[i]==initial) return 0;
    unsigned done=0;
    for(uint32_t step=0;step<v->clusters && !done;step++) {
      if(!nb_dir_read(v,c)) return 0;
      for(unsigned at=0;at<4096;at+=32) {
        uint8_t *e=v->scratch+at;
        if(!e[0]) {done=1;break;}
        if(e[0]==0xe5 || e[11]==15 || (e[11]&8) || e[0]=='.') continue;
        uint32_t start=nb_entry_cluster(e);
        int target=initial==v->root && nb_equal(e,NB_LOG_NAME,11);
        if(start>=first && start<last && !target) return 0;
        if(e[11]&16) {
          if(!nb_cluster_ok(v,start) || tail==1024) return 0;
          v->directories[tail++]=start;
        }
      }
      if(done) break;
      c=nb_fat(v,c); if(c>=0x0ffffff8) {done=1;break;}
    }
    if(!done) return 0;
  }
  return 1;
}
static inline int nb_volume_open(struct nb_log_volume *v,nb_log_read_fn read,void *ctx,
                                 uint64_t lun_blocks,const uint8_t token[16]) {
  static const uint8_t esp_type[16]={0x28,0x73,0x2a,0xc1,0x1f,0xf8,0xd2,0x11,0xba,0x4b,0,0xa0,0xc9,0x3e,0xc9,0x3b};
  v->read=read;v->context=ctx;v->lun_blocks=lun_blocks;v->reads=0;
  v->esp_first=0;v->file_cluster=0;
  v->failure=NBV_OK;v->failure_lba=0;v->failure_blocks=0;
  if(lun_blocks<8 || lun_blocks>0xffffffffULL) return nb_volume_fail(v,NBV_LUN_BLOCKS);
  if(!nb_vread(v,1,1,v->scratch)) return nb_volume_fail(v,NBV_GPT_HEADER_READ);
  uint8_t *p=v->scratch;
  uint32_t hdr=nb_le32(p+12),count=nb_le32(p+80),esz=nb_le32(p+84),crc=nb_le32(p+16);
  uint64_t table=nb_le64(p+72),usable_first=nb_le64(p+40),usable_last=nb_le64(p+48);
  if(!nb_equal(p,"EFI PART",8) || nb_le32(p+8)!=0x10000 || hdr<92 || hdr>4096 || nb_le32(p+20) ||
     nb_le64(p+24)!=1 || nb_le64(p+32)!=lun_blocks-1 || usable_first<2 ||
     usable_last>=lun_blocks-1 || usable_first>usable_last || !count || count>128 || esz!=128 ||
     table<2 || table>=usable_first || ((uint64_t)count*128+4095)/4096>usable_first-table)
    return nb_volume_fail(v,NBV_GPT_HEADER);
  nb_put32(p+16,0); if(nb_crc(p,hdr)!=crc) return nb_volume_fail(v,NBV_GPT_HEADER_CRC);
  uint32_t array_crc=nb_le32(p+88),blocks=(count*128+4095)/4096;
  if(!nb_vread(v,table,blocks,v->entries)) return nb_volume_fail(v,NBV_GPT_ENTRIES_READ);
  if(nb_crc(v->entries,count*128)!=array_crc) return nb_volume_fail(v,NBV_GPT_ENTRIES_CRC);
  for(unsigned i=0;i<count;i++) {
    const uint8_t *e=v->entries+128*i;
    uint8_t zero[16]={0}; if(nb_equal(e,zero,16)) continue;
    uint64_t first=nb_le64(e+32),last=nb_le64(e+40);
    if(first<usable_first || last>usable_last || first>last) return nb_volume_fail(v,NBV_GPT_ENTRY);
    for(unsigned j=0;j<i;j++) {
      const uint8_t *other=v->entries+128*j;
      if(!nb_equal(other,zero,16) && first<=nb_le64(other+40) && nb_le64(other+32)<=last)
        return nb_volume_fail(v,NBV_GPT_ENTRY);
    }
    if(nb_equal(e,esp_type,16)) {
      if(v->esp_first || !nb_equal(e+56,"e\0s\0p\0\0\0",8)) return nb_volume_fail(v,NBV_GPT_ESP_ENTRY);
      v->esp_first=first;v->esp_blocks=last-first+1;
    }
  }
  if(!v->esp_first) return nb_volume_fail(v,NBV_GPT_ESP_ENTRY);
  if(!nb_vread(v,v->esp_first,1,p)) return nb_volume_fail(v,NBV_ESP_BOOT_READ);
  /* 4K sectors and clusters are the measured nabu ESP geometry, not a guessed fallback. */
  uint32_t bps=p[11]|((uint32_t)p[12]<<8),reserved=p[14]|((uint32_t)p[15]<<8);
  uint32_t total=nb_le32(p+32),fat=nb_le32(p+36),flags=p[40]|((uint32_t)p[41]<<8);
  if(bps!=4096 || p[13]!=1 || p[16]!=2 || !reserved || !fat || fat>256 ||
     total!=v->esp_blocks || reserved+2ULL*fat>=total || flags ||
     p[17] || p[18] || p[19] || p[20] || p[22] || p[23] || p[42] || p[43] ||
     p[510]!=0x55 || p[511]!=0xaa || !nb_equal(p+82,"FAT32",5)) return nb_volume_fail(v,NBV_ESP_BPB);
  v->fat_first=reserved;v->fat_blocks=fat;v->data_first=reserved+2*fat;
  v->clusters=total-v->data_first;v->root=nb_le32(p+44);
  if(v->clusters<65525 || (v->clusters+2ULL)*4>fat*4096ULL || !nb_cluster_ok(v,v->root))
    return nb_volume_fail(v,NBV_ESP_GEOMETRY);
  /* Both mirrors must agree before any data block can become writable. */
  for(unsigned i=0;i<fat;i++) {
    if(!nb_vread(v,v->esp_first+reserved+i,1,v->fat+4096*i) ||
       !nb_vread(v,v->esp_first+reserved+fat+i,1,p) || !nb_equal(p,v->fat+4096*i,4096))
      return nb_volume_fail(v,NBV_FAT_MIRROR);
  }
  if(!nb_find_root_file(v)) return nb_volume_fail(v,NBV_ROOT_FILE);
  if(!nb_cluster_ok(v,v->file_cluster)) return nb_volume_fail(v,NBV_ROOT_FILE_ENTRY);
  unsigned n=NB_LOG_FILE_BYTES/4096;
  if(n>v->clusters+2-v->file_cluster) return nb_volume_fail(v,NBV_FILE_CHAIN);
  for(unsigned i=0;i<n;i++) {
    uint32_t next=nb_fat(v,v->file_cluster+i);
    if(i+1<n ? next!=v->file_cluster+i+1 : next<0x0ffffff8) return nb_volume_fail(v,NBV_FILE_CHAIN);
  }
  if(!nb_no_aliases(v)) return nb_volume_fail(v,NBV_FILE_ALIAS);
  v->file_first=v->esp_first+v->data_first+v->file_cluster-2;
  if(v->file_first<v->esp_first || n>v->esp_first+v->esp_blocks-v->file_first)
    return nb_volume_fail(v,NBV_CONFIG_READ);
  if(!nb_vread(v,v->file_first,1,p)) return nb_volume_fail(v,NBV_CONFIG_READ);
  if(!nb_config_valid(p,token)) return nb_volume_fail(v,NBV_CONFIG);
  nb_copy(v->token,token,16); return 1;
}
static inline int nb_volume_write_allowed(const struct nb_log_volume *v,uint64_t lba,uint32_t n) {
  /* Config at relative block 0 is immutable. Everything else is an A/B slot. */
  return n && lba>v->file_first && lba-v->file_first<NB_LOG_FILE_BYTES/4096 &&
    n<=NB_LOG_FILE_BYTES/4096-(lba-v->file_first);
}
#endif
