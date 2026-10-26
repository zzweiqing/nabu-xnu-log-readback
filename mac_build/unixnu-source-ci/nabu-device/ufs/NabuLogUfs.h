/* Included in NativeUfs.cpp after the host primitives, only for logging builds.
 * All disk operations run on this ordinary thread. No panic hook, misc write,
 * reset, USB, or general-purpose writable block service is introduced.
 *
 * Every pre-commit stop names its gate in an IOLog line. The lines never
 * contain the allocation token or any token byte. They are ordinary console
 * output: if the journal cannot be committed they are visible on screen (or in
 * a boot recording) but are not themselves persisted by this writer.
 */
#include "NabuLogCore.h"
#include "NabuLogVolume.h"
#include "NabuLogBuild.h"
static struct nb_log_volume nabu_log_volume;
static uint8_t nabu_log_payload[NB_LOG_CAPACITY] __attribute__((aligned(4096)));
static uint8_t nabu_log_headers[2][4096],nabu_log_header[4096];
static const char *nabu_log_io_reason="none";
static IOReturn nabu_log_io_result;
static uint32_t nabu_log_io_scsi;
extern "C" {
volatile unsigned nabu_log_writer_state=0,nabu_log_writer_rounds=0,nabu_log_writer_failures=0;
}
/* 1 success, 0 bounded contention, -1 transport/gate failure. The existing root
 * read path stays read-only. Only this function can emit the bounded WRITE(10). */
static int nabuLogIo(bool write,uint64_t lba,uint32_t blocks,uint8_t *data,bool sync=false)
{
  if(!gHost.ready || gHost.poisoned || !gHost.lock || lba>=nabu_log_lun_blocks ||
     blocks>nabu_log_lun_blocks-lba || blocks>kDataMax/4096) {nabu_log_io_reason="host";return -1;}
  if(write && !nb_volume_write_allowed(&nabu_log_volume,lba,blocks)) {nabu_log_io_reason="write-gate";return -1;}
  if(!sync && (!blocks || !data)) {nabu_log_io_reason="bad-args";return -1;}
  if(!IOLockTryLock(gHost.lock)) {nabu_log_io_reason="busy";return 0;}
  uint8_t cdb[10]={0};uint32_t scsi=0;IOReturn result;
  if(sync) {
    cdb[0]=0x35;
    result=hostScsiDir(0,cdb,10,0,0,1000000,&scsi);
  } else {
    cdb[0]=write?0x2a:0x28;cdb[1]=write?0x08:0; /* FUA on log writes */
    cdb[2]=(uint8_t)(lba>>24);cdb[3]=(uint8_t)(lba>>16);cdb[4]=(uint8_t)(lba>>8);cdb[5]=(uint8_t)lba;
    cdb[7]=(uint8_t)(blocks>>8);cdb[8]=(uint8_t)blocks;
    if(write) nb_copy(gHost.virt+kDataOffset,data,blocks*4096);
    result=hostScsiDir(0,cdb,10,write?1:2,blocks*4096,1000000,&scsi);
    if(!write && result==kIOReturnSuccess) nb_copy(data,gHost.virt+kDataOffset,blocks*4096);
  }
  IOLockUnlock(gHost.lock);
  nabu_log_io_result=result;nabu_log_io_scsi=scsi;
  nabu_log_io_reason=result==kIOReturnSuccess?"ok":"transport";
  return result==kIOReturnSuccess?1:-1;
}
/* Counter-based pacing must not wait for an unproved timer interrupt. Yield
 * the CPU on each pass so root I/O can finish; both time and work are bounded. */
static void nabuLogPause(unsigned milliseconds)
{
  uint64_t deadline;
  clock_interval_to_deadline(milliseconds,kMillisecondScale,&deadline);
  unsigned budget=milliseconds>1000?1000000:milliseconds*1000;
  do {
    thread_yield_internal(0);
  } while(budget-- && mach_absolute_time()<deadline);
}
static int nabuLogRead(void *,uint64_t lba,uint32_t blocks,uint8_t *data)
{
  /* The metadata verifier never blocks behind a mutex held by a stopped CPU.
   * Bound the retries by both iterations and monotonic time: before timer
   * services are proved, IOSleep may not space the attempts at all, and a
   * count-only budget could then be consumed within microseconds. */
  uint64_t deadline;
  clock_interval_to_deadline(50,kMillisecondScale,&deadline);
  for(unsigned attempt=0;attempt<1000;attempt++) {
    int result=nabuLogIo(false,lba,blocks,data);
    if(result) return result==1;
    if(mach_absolute_time()>=deadline) break;
    nabuLogPause(1);
  }
  return 0;
}
static int nabuLogHex(char c) {
  if(c>='0' && c<='9') return c-'0';
  if(c>='a' && c<='f') return c-'a'+10;
  if(c>='A' && c<='F') return c-'A'+10;
  return -1;
}
enum {
  NB_TOKEN_OK=0, NB_TOKEN_FLAG_ABSENT, NB_TOKEN_MISSING, NB_TOKEN_BAD_HEX
};
static const char *nabuLogTokenReason(int reason) {
  switch(reason) {
    case NB_TOKEN_OK: return "ok";
    case NB_TOKEN_FLAG_ABSENT: return "nabu-log-absent-or-not-1";
    case NB_TOKEN_MISSING: return "nabu-log-token-absent";
    case NB_TOKEN_BAD_HEX: return "nabu-log-token-not-32-hex";
    default: return "unknown";
  }
}
/* The allocation token is deliberately never printed: a refusal only reports
 * which boot argument was absent or malformed.
 *
 * PE_parse_boot_argn() cannot carry this value: for an argument name that does
 * not begin with '_' it parses the right-hand side as a number, so a 32-digit
 * hex token that starts with a digit becomes an integer in the caller's buffer
 * and the hex decode below then fails.  Read the raw boot-argument string and
 * match the token itself as text. */
static int nabuLogTokenParse(uint8_t token[16]) {
  unsigned enabled=0;
  if(!PE_parse_boot_argn("nabu-log",&enabled,sizeof(enabled)) || enabled!=1)
    return NB_TOKEN_FLAG_ABSENT;
  static const char key[]="nabu-log-token=";
  const char *args=PE_boot_args();
  const char *value=nullptr;
  for(const char *p=args; p && *p; ) {
    while(*p==' ') p++;
    if(!*p) break;
    const char *start=p;
    bool match=true;
    for(unsigned i=0;i<sizeof(key)-1;i++,p++) {
      if(*p!=key[i]) {match=false;break;}
    }
    if(match) {value=p;break;}
    while(*p && *p!=' ') p++;
    if(p==start) break;
  }
  if(value==nullptr)
    return NB_TOKEN_MISSING;
  for(unsigned i=0;i<16;i++) {
    int a=nabuLogHex(value[2*i]),b=nabuLogHex(value[2*i+1]);
    if(a<0 || b<0) return NB_TOKEN_BAD_HEX;
    token[i]=(uint8_t)(a*16+b);
  }
  if(value[32] && value[32]!=' ') return NB_TOKEN_BAD_HEX;
  return NB_TOKEN_OK;
}
static __attribute__((unused)) bool nabuLogToken(uint8_t token[16]) {
  return nabuLogTokenParse(token)==NB_TOKEN_OK;
}
static bool nabuLogWindowsClear(void) {
  const char *keys[4]={"native-ufs-os-lba","native-ufs-os-sectors","native-ufs-systemos-lba","native-ufs-systemos-sectors"};
  uint32_t n[4]={0};
  for(unsigned i=0;i<4;i++) if(!PE_parse_boot_argn(keys[i],n+i,sizeof(n[i])) || !n[i]) {
    IOLog("NABULOG2: writer stop reason=boot-windows detail=missing-%s\n",keys[i]);
    return false;
  }
  const uint64_t first=nabu_log_volume.esp_first*4096,end=(nabu_log_volume.esp_first+nabu_log_volume.esp_blocks)*4096;
  for(unsigned i=0;i<4;i+=2) {
    uint64_t a=(uint64_t)n[i]*4096,b=a+(uint64_t)n[i+1]*512;
    if(a<end && first<b) {
      IOLog("NABULOG2: writer stop reason=boot-windows detail=esp-overlap esp=%u..%u window=%u..%u\n",
            (unsigned)first,(unsigned)end,(unsigned)a,(unsigned)b);
      return false;
    }
  }
  return true;
}
static int nabuLogSlot(unsigned slot,uint8_t *header) {
  uint64_t base=nabu_log_volume.file_first+1+(uint64_t)slot*(NB_LOG_SLOT_BYTES/4096);
  if(!nabuLogRead(nullptr,base,1,header)) return -1;
  if(!nb_slot_valid(header,nabu_log_volume.token)) return 0;
  uint32_t length=nb_le32(header+72),blocks=(length+4095)/4096;
  for(unsigned at=0;at<blocks;) {
    unsigned n=blocks-at>16?16:blocks-at;
    if(!nabuLogRead(nullptr,base+1+at,n,nabu_log_payload+at*4096)) return -1;
    at+=n;
  }
  return nb_crc(nabu_log_payload,length)==nb_le32(header+76);
}
static void nabuLogThread(void *,wait_result_t)
{
  uint8_t token[16],boot[16];
  const char *stop_reason="unspecified";
  {
    int gate=nabuLogTokenParse(token);
    if(gate!=NB_TOKEN_OK) {
      IOLog("NABULOG2: writer thread token gate detail=%s\n",nabuLogTokenReason(gate));
      stop_reason="token-gate";goto stop;
    }
  }
  nabu_log_writer_state=1;
  IOLog("NABULOG2: writer entered; counter-paced scheduling; opening volume\n");
  thread_yield_internal(0); /* root bring-up may still own the transport */
  {
    bool opened=false;
    uint64_t open_deadline;
    clock_interval_to_deadline(30000,kMillisecondScale,&open_deadline);
    unsigned attempts=0;
    stop_reason="volume-open";
    for(;attempts<30;attempts++) {
      if(nb_volume_open(&nabu_log_volume,nabuLogRead,nullptr,nabu_log_lun_blocks,token)) {opened=true;break;}
      IOLog("NABULOG2: volume open failed attempt=%u reason=%s lba=%u blocks=%u reads=%u poisoned=%u ready=%u\n",
            attempts+1,nb_volume_failure_name(nabu_log_volume.failure),
            (unsigned)nabu_log_volume.failure_lba,nabu_log_volume.failure_blocks,
            nabu_log_volume.reads,gHost.poisoned?1u:0u,gHost.ready?1u:0u);
      if(gHost.poisoned || !gHost.ready) {stop_reason="transport-unavailable";break;}
      if(mach_absolute_time()>=open_deadline) {stop_reason="open-deadline";break;}
      nabuLogPause(1000);
    }
    if(!opened) goto stop;
    IOLog("NABULOG2: volume verified attempts=%u reads=%u esp=%u..%u file_first=%u\n",
          attempts+1,nabu_log_volume.reads,(unsigned)nabu_log_volume.esp_first,
          (unsigned)(nabu_log_volume.esp_first+nabu_log_volume.esp_blocks),
          (unsigned)nabu_log_volume.file_first);
    if(!nabuLogWindowsClear()) {stop_reason="boot-windows";goto stop;}
  }
  {
    int valid[2]={0,0};
    for(unsigned i=0;i<2;i++) {
      valid[i]=nabuLogSlot(i,nabu_log_headers[i]);
      if(valid[i]<0) {
        IOLog("NABULOG2: slot read failed slot=%u\n",i);
        stop_reason="slot-read";goto stop;
      }
    }
    uint64_t sequence=0;unsigned newest=1;
    for(unsigned i=0;i<2;i++) if(valid[i] && nb_le64(nabu_log_headers[i]+24)>sequence) {sequence=nb_le64(nabu_log_headers[i]+24);newest=i;}
    /* Do not initialise over two damaged, previously committed headers. */
    if(!valid[0] && !valid[1]) {
      uint8_t zero[4096]={0};
      if(!nb_equal(zero,nabu_log_headers[0],4096) || !nb_equal(zero,nabu_log_headers[1],4096)) {
        IOLog("NABULOG2: refusing to overwrite two non-zero invalid slots\n");
        stop_reason="damaged-slots";goto stop;
      }
    }
    uint64_t ticks=mach_absolute_time();
    nb_put64(boot,ticks);nb_put64(boot+8,sequence+1);
    IOLog("NABULOG2: RAM console capture; validated preallocated ESP file; periodic writer ready\n");
    nabu_log_writer_state=2;
    uint64_t last_end=~0ULL,last_lost=~0ULL;
    unsigned snapshot_stalls=0,copy_stalls=0;
    for(;;) {
      struct nb_log_snapshot snapshot;
      if(!nabu_capture_snapshot(&snapshot)) {
        if(snapshot_stalls++==300)
          IOLog("NABULOG2: capture snapshot unavailable for ~30s; writer still retries\n");
        nabuLogPause(100);continue;
      }
      snapshot_stalls=0;
      if(sequence==~0ULL) {stop_reason="sequence-exhausted";goto stop;}
      if(snapshot.end==last_end && snapshot.lost==last_lost) {nabuLogPause(1000);continue;}
      bool complete=true;
      for(unsigned at=0;at<snapshot.length;at+=1024) {
        unsigned n=snapshot.length-at>1024?1024:snapshot.length-at;
        if(!nabu_capture_copy(snapshot.first+at,n,nabu_log_payload+at)) {complete=false;break;}
      }
      if(!complete) {
        if(copy_stalls++==300)
          IOLog("NABULOG2: capture copy rejected for ~30s end=%u lost=%u; writer still retries\n",
                (unsigned)snapshot.end,(unsigned)snapshot.lost);
        nabuLogPause(100);continue;
      }
      copy_stalls=0;
      unsigned padded=(snapshot.length+4095)&~4095u;
      nb_zero(nabu_log_payload+snapshot.length,padded-snapshot.length);
      nb_zero(nabu_log_header,4096);nb_copy(nabu_log_header,"NABULOG2",8);
      nb_put32(nabu_log_header+8,2);nb_put32(nabu_log_header+12,4096);
      nb_put32(nabu_log_header+16,1);nb_put32(nabu_log_header+20,NB_LOG_CAPACITY);
      nb_put64(nabu_log_header+24,sequence+1);nb_copy(nabu_log_header+32,boot,16);
      nb_put64(nabu_log_header+48,snapshot.end);nb_put64(nabu_log_header+56,snapshot.lost);
      nb_put64(nabu_log_header+64,snapshot.first);nb_put32(nabu_log_header+72,snapshot.length);
      nb_put32(nabu_log_header+76,nb_crc(nabu_log_payload,snapshot.length));
      nb_put64(nabu_log_header+88,snapshot.first);nb_copy(nabu_log_header+96,token,16);
      nb_copy(nabu_log_header+112,nabu_log_build_id,32);
      nb_put32(nabu_log_header+80,nb_header_crc(nabu_log_header,80));
      unsigned slot=newest^1u;
      uint64_t base=nabu_log_volume.file_first+1+(uint64_t)slot*(NB_LOG_SLOT_BYTES/4096);
      int result=1;const char *phase="payload";uint64_t fail_lba=base+1;unsigned fail_blocks=0;
      if(!nabu_log_writer_rounds)
        IOLog("NABULOG2: first commit attempt slot=%u bytes=%u\n",slot,snapshot.length);
      for(unsigned at=0;at<padded/4096 && result==1;) {
        unsigned n=padded/4096-at>16?16:padded/4096-at;
        fail_lba=base+1+at;fail_blocks=n;
        result=nabuLogIo(true,fail_lba,n,nabu_log_payload+at*4096);at+=n;
      }
      /* The old active slot remains intact if payload/sync/header fails. */
      if(result==1) {phase="sync";result=nabuLogIo(false,0,0,nullptr,true);}
      if(result==1) {phase="header";fail_lba=base;fail_blocks=1;result=nabuLogIo(true,base,1,nabu_log_header);}
      if(result==1) {phase="sync";fail_lba=0;fail_blocks=0;result=nabuLogIo(false,0,0,nullptr,true);}
      if(result<0) {
        IOLog("NABULOG2: commit failed slot=%u phase=%s lba=%u blocks=%u io=%s result=%x scsi=%x; old slot preserved\n",
              slot,phase,(unsigned)fail_lba,fail_blocks,nabu_log_io_reason,
              (unsigned)nabu_log_io_result,nabu_log_io_scsi);
        stop_reason="commit-write";goto stop;
      }
      if(result==1) {
        bool first=nabu_log_writer_rounds==0;
        newest=slot;sequence++;last_end=snapshot.end;last_lost=snapshot.lost;nabu_log_writer_rounds++;
        if(first) IOLog("NABULOG2: first snapshot committed slot=%u bytes=%u\n",slot,snapshot.length);
      }
      nabuLogPause(1000);
    }
  }
stop:
  nabu_log_writer_state=3;nabu_log_writer_failures++;
  IOLog("NABULOG2: writer stopped reason=%s; RAM capture continues; no fallback write window\n",stop_reason);
  thread_terminate(current_thread());
}
static void nabuLogStart(void) {
  uint8_t token[16];
  if(nabu_log_writer_state) {
    IOLog("NABULOG2: start skipped reason=already-started state=%u\n",nabu_log_writer_state);
    return;
  }
  int gate=nabuLogTokenParse(token);
  if(gate!=NB_TOKEN_OK) {
    IOLog("NABULOG2: start skipped reason=token-gate detail=%s\n",nabuLogTokenReason(gate));
    return;
  }
  thread_t thread=nullptr;
  nabu_log_writer_state=1;
  if(kernel_thread_start(nabuLogThread,nullptr,&thread)==KERN_SUCCESS) {
    thread_deallocate(thread);
    IOLog("NABULOG2: writer thread created lun_blocks=%u\n",(unsigned)nabu_log_lun_blocks);
  }
  else {
    nabu_log_writer_state=3;nabu_log_writer_failures++;
    IOLog("NABULOG2: writer thread start failed; RAM capture continues\n");
  }
}
