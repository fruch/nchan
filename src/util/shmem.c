#include <nchan_module.h>
#include "shmem.h"
#include "assert.h"
#include <util/ngx_nchan_hacked_slab.h>

#define DEBUG_SHM_ALLOC 1

#define DEBUG_SHM_STRINGS 1
#define DEBUG_SHM_STRINGS_PADDING 0000

#define SHPOOL(shmem) ((ngx_slab_pool_t *)(shmem)->zone->shm.addr)

//#define DEBUG_LEVEL NGX_LOG_WARN
#define DEBUG_LEVEL NGX_LOG_DEBUG

#define DBG(fmt, args...) ngx_log_error(DEBUG_LEVEL, ngx_cycle->log, 0, "SHMEM:" fmt, ##args)
#define ERR(fmt, args...) ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "SHMEM:" fmt,  ##args)

//#include <valgrind/memcheck.h>

#if DEBUG_SHM_STRINGS
typedef struct {
  size_t       pad;
  size_t       backup_len;
  ngx_str_t    str;
} shm_padded_str_t;
#endif

//shared memory
shmem_t *shm_create(ngx_str_t *name, ngx_conf_t *cf, size_t shm_size, ngx_int_t (*init)(ngx_shm_zone_t *, void *), void *privdata) {

  ngx_shm_zone_t    *zone;
  shmem_t           *shm;

  shm_size = ngx_align(shm_size, ngx_pagesize);
  if (shm_size < 8 * ngx_pagesize) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "The push_max_reserved_memory value must be at least %udKiB", (8 * ngx_pagesize) >> 10);
    shm_size = 8 * ngx_pagesize;
  }
  /*
  if(nchan_shm_zone && nchan_shm_zone->shm.size != shm_size) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "Cannot change memory area size without restart, ignoring change");
  }
  */
  ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Using %udKiB of shared memory for nchan", shm_size >> 10);

  shm = ngx_alloc(sizeof(*shm), ngx_cycle->log);
  zone = ngx_shared_memory_add(cf, name, shm_size, &ngx_nchan_module);
  if (zone == NULL || shm == NULL) {
    return NULL;
  }
  shm->zone = zone;

  zone->init = init;
  zone->data = (void *) 1;
  return shm;
}

void shm_set_allocd_pages_tracker(shmem_t *shm, ngx_atomic_uint_t *ptr) {
  nchan_slab_set_reserved_pages_tracker(SHPOOL(shm), ptr);
}

ngx_int_t shm_init(shmem_t *shm) {
  ngx_slab_pool_t    *shpool = SHPOOL(shm);
  #if (DEBUG_SHM_ALLOC == 1)
  ngx_log_error(DEBUG_LEVEL, ngx_cycle->log, 0, "nchan_shpool start %p size %i", shpool->start, (u_char *)shpool->end - (u_char *)shpool->start);
  #endif
  nchan_slab_init(shpool);
  
  return NGX_OK;
}

ngx_int_t shm_reinit(shmem_t *shm) {
  ngx_slab_pool_t    *shpool = SHPOOL(shm);
  nchan_slab_init(shpool);
  
  return NGX_OK;
}

void shmtx_lock(shmem_t *shm) {
  ngx_shmtx_lock(&SHPOOL(shm)->mutex);
}
void shmtx_unlock(shmem_t *shm) {
  ngx_shmtx_unlock(&SHPOOL(shm)->mutex);
}

ngx_int_t shm_destroy(shmem_t *shm) {
  //VALGRIND_DESTROY_MEMPOOL(SHPOOL(shm));
  ngx_free(shm);
  
  return NGX_OK;
}
void *shm_alloc(shmem_t *shm, size_t size, const char *label) {
  void         *p;
#if FAKESHARD  
  p = ngx_alloc(size, ngx_cycle->log);
#else
  p = nchan_slab_alloc(SHPOOL(shm), size);  
#endif
  if(p == NULL) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "shpool alloc failed");
  }

  #if (DEBUG_SHM_ALLOC == 1)
  if (p != NULL) {
    ngx_log_error(DEBUG_LEVEL, ngx_cycle->log, 0, "shpool alloc addr %p size %ui label %s", p, size, label == NULL ? "none" : label);
  }
  #endif
  return p;
}

void *shm_calloc(shmem_t *shm, size_t size, const char *label) {
  void *p = shm_alloc(shm, size, label);
  if(p != NULL) {
    ngx_memzero(p, size);
  }
  return p;
}

void shm_free(shmem_t *shm, void *p) {
#if FAKESHARD
  ngx_free(p);
#else
  nchan_slab_free(SHPOOL(shm), p);
#endif
#if (DEBUG_SHM_ALLOC == 1)
  ngx_log_error(DEBUG_LEVEL, ngx_cycle->log, 0, "shpool free addr %p", p);
#endif
}



//copypasta because these should only be used for debugging

void *shm_locked_alloc(shmem_t *shm, size_t size, const char *label) {
  void         *p;
#if FAKESHARD  
  p = ngx_alloc(size, ngx_cycle->log);
#else
  p = nchan_slab_alloc_locked(SHPOOL(shm), size);  
#endif
  if(p == NULL) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "shpool alloc failed");
  }

  #if (DEBUG_SHM_ALLOC == 1)
  if (p != NULL) {
    ngx_log_error(DEBUG_LEVEL, ngx_cycle->log, 0, "shpool alloc addr %p size %ui label %s", p, size, label == NULL ? "none" : label);
  }
  #endif
  return p;
}

void *shm_locked_calloc(shmem_t *shm, size_t size, const char *label) {
  void *p = shm_locked_alloc(shm, size, label);
  if(p != NULL) {
    ngx_memzero(p, size);
  }
  return p;
}

void shm_locked_free(shmem_t *shm, void *p) {
#if FAKESHARD
  ngx_free(p);
#else
  nchan_slab_free_locked(SHPOOL(shm), p);
#endif
#if (DEBUG_SHM_ALLOC == 1)
  ngx_log_error(DEBUG_LEVEL, ngx_cycle->log, 0, "shpool free addr %p", p);
#endif
}

#if DEBUG_SHM_STRINGS
static void verify_shm_string(shm_padded_str_t *padded) {
  if(padded->pad != DEBUG_SHM_STRINGS_PADDING) {
    ERR("wrong starting padding for string %p, was $i", &padded->str, padded->pad);
    assert(padded->pad == DEBUG_SHM_STRINGS_PADDING);
  }
  
  u_char    *pt = padded->str.data;
  assert(pt[padded->str.len]=='>');
  
  assert(padded->str.len == padded->backup_len);
}
#endif

void shm_verify_immutable_string(shmem_t *shm, ngx_str_t *str) {
#if DEBUG_SHM_STRINGS
  verify_shm_string(container_of(str, shm_padded_str_t, str));
#endif
}

void shm_free_immutable_string(shmem_t *shm, ngx_str_t *str) {
#if DEBUG_SHM_STRINGS
  shm_padded_str_t *padded = container_of(str, shm_padded_str_t, str);
  verify_shm_string(padded);
  shm_free(shm, padded);
#else
  shm_free(shm, (void *)str);
#endif
}

ngx_str_t *shm_copy_immutable_string(shmem_t *shm, ngx_str_t *str_in) {
  ngx_str_t    *str;
  size_t        sz;
#if DEBUG_SHM_STRINGS
  shm_padded_str_t *padded;
  sz = sizeof(*padded) + str_in->len + 4;
  if((padded = shm_alloc(shm, sz, "string")) == NULL) {
    return NULL;
  }
  padded->pad = DEBUG_SHM_STRINGS_PADDING;
  str = &padded->str;
  str->data = (u_char *)&padded[1];
  str->len = padded->backup_len = str_in->len;
  str->data[str->len] = '>';
#else
  sz = sizeof(*str) + str_in->len;
  if((str = shm_alloc(shm, sz, "string")) == NULL) {
    return NULL;
  }
  str->data=(u_char *)&str[1];
  str->len=str_in->len;
#endif
  ngx_memcpy(str->data, str_in->data, str_in->len);
  return str;
}
