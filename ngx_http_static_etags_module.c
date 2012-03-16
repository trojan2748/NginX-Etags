/*
 *  Copyright 2012 Adam Landas (adamlandas@gmail.com) )
 *
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>
#include <ngx_md5.h>

typedef struct {
    ngx_flag_t     INode;
    ngx_flag_t     MTime;
    ngx_flag_t     Size;
    ngx_flag_t     MD5;
} etag_out;

typedef struct {
    ngx_uint_t  FileETag;
    ngx_flag_t  toggle;
    ngx_str_t   etag_format;
    etag_out    *etag_options;
} ngx_http_static_etags_loc_conf_t;


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static void * ngx_http_static_etags_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_static_etags_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_static_etags_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_static_etags_header_filter(ngx_http_request_t *r);
static char * ngx_conf_set_etag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_static_etags_commands[] = {
    { ngx_string( "FileETag" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_etag,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_static_etags_loc_conf_t, FileETag ),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_static_etags_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_static_etags_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_static_etags_create_loc_conf,  /* create location configuration */
    ngx_http_static_etags_merge_loc_conf,   /* merge location configuration */
};

ngx_module_t  ngx_http_static_etags_module = {
    NGX_MODULE_V1,
    &ngx_http_static_etags_module_ctx,  /* module context */
    ngx_http_static_etags_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void * ngx_http_static_etags_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_static_etags_loc_conf_t    *conf;

    conf = ngx_pcalloc( cf->pool, sizeof( ngx_http_static_etags_loc_conf_t ) );
    if ( NULL == conf ) {
        return NGX_CONF_ERROR;
    }
    conf->FileETag   = NGX_CONF_UNSET_UINT;
    return conf;
}

static char * ngx_http_static_etags_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_static_etags_loc_conf_t *prev = parent;
    ngx_http_static_etags_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value( conf->FileETag, prev->FileETag, 0 );

    if ( conf->FileETag != 0 && conf->FileETag != 1 ) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
            "FileETag must be 'on' or 'off'");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_static_etags_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_static_etags_header_filter;

    return NGX_OK;
}

static int ngx_http_static_etags_md5(unsigned int size, char *file, char *md5sum, ngx_log_t *log);

static int ngx_http_static_etags_md5(unsigned int size, char *file, char *md5sum, ngx_log_t *log) {
   FILE             *fp = NULL;
   char             data[4096];
   int              ret;
   int              j;
   int              chunk_size = 4096;
   int              chunks = 0;
   int              left_over = 0;
   unsigned int     fileLen;
   ngx_md5_t        md5;
   unsigned char    digest[16];
   u_char           hex[] = "0123456789abcdef";


   ngx_md5_init(&md5);

   fp = fopen((char *) file, "rb");
   if (fp == NULL)
     return (int ) 1;
   fseek(fp, 0, SEEK_END);
   fileLen = ftell(fp);
   fseek(fp, 0, SEEK_SET);
  
   ngx_md5_init(&md5);
   chunks = fileLen / chunk_size;
   left_over = fileLen % chunk_size;
   for (j = 0; j < chunks; j++) {
     ret = fread(&data, chunk_size, 1 ,fp);
     ngx_md5_update(&md5, data, chunk_size);
   }

   if(left_over) {
     ret = fread(&data, left_over, 1 ,fp);
     ngx_md5_update(&md5, data, left_over);
   }
   ngx_log_error(NGX_LOG_ERR, log, 0, " ");

   fclose(fp);
   ngx_md5_final(digest, &md5);

   ngx_memzero(md5sum, 33);
   md5sum[32] = '\0';
   for ( j = 0 ; j < 16; j++ ) {
     md5sum[2*j] = hex[digest[j] >> 4];
     md5sum[2*j+1] = hex[digest[j] & 0xf];
   }

   return (int ) 0;
}

static ngx_int_t ngx_http_static_etags_header_filter(ngx_http_request_t *r) {
    char                                new_string[100];
    char                                buffer[30];
    int                                 status;
    ngx_log_t                          *log;
    u_char                             *p;
    size_t                              root;
    ngx_str_t                           path;
    ngx_http_static_etags_loc_conf_t   *loc_conf;
    struct stat                         stat_result;
    log = r->connection->log;
    
    loc_conf = ngx_http_get_module_loc_conf( r, ngx_http_static_etags_module );


    if ( 1 == loc_conf->FileETag ) {
        p = ngx_http_map_uri_to_path( r, &path, &root, 0 );
        status = stat( (char *) path.data, &stat_result );
        if ( NULL == p ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if ( 0 == status) {
          ngx_memzero(&new_string, 100);
          strcat(new_string, "\"");

          if (loc_conf->etag_options->MD5) {
            int       ret;
            char      md5sum[33];
            ret = ngx_http_static_etags_md5((unsigned int) stat_result.st_size, (char *) path.data, (char *) &md5sum, (ngx_log_t *) log);
            if (ret) {
              ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MD5ERROR Return: %s", md5sum);
              return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
              strcat(new_string, (char *) md5sum);
          }
          if (loc_conf->etag_options->Size) {
            sprintf(buffer, "%x", (unsigned int) stat_result.st_size);
            strcat(new_string, (char *) buffer);
          }
          if (loc_conf->etag_options->MTime) {
            sprintf(buffer, "%x", (unsigned int ) stat_result.st_mtime);
            strcat(new_string, (char *) buffer);
          }
          if (loc_conf->etag_options->INode) {
            sprintf(buffer, "%x", (unsigned int ) stat_result.st_ino);
            strcat(new_string, (char *) buffer);
          }

          strcat(new_string, "\"");     
          r->headers_out.etag = ngx_list_push(&r->headers_out.headers);

          if (r->headers_out.etag == NULL) {
              return NGX_ERROR;
          }

          ngx_table_elt_t *header;

          int nelts = r->headers_in.headers.part.nelts;
          header = r->headers_in.headers.part.elts;
          int i;
          for (i = 0; i < nelts; i++) {
            if (ngx_strncmp(header[i].key.data, "If-None-Match", strlen ("If-None-Match")) == 0) {
              if(ngx_strncmp(header[i].value.data, new_string, strlen (new_string)) == 0) {
                r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
                r->headers_out.status_line.len = 0;
                r->headers_out.content_type.len = 0;
                ngx_http_clear_content_length(r);
                ngx_http_clear_accept_ranges(r);

                return ngx_http_next_header_filter(r);
               }
            }
          }

          r->headers_out.etag->hash = 1;
          r->headers_out.etag->key.len = sizeof("Etag") - 1;
          r->headers_out.etag->key.data = (u_char *) "Etag";
          r->headers_out.etag->value.len = strlen( new_string );
          r->headers_out.etag->value.data = (u_char *) new_string;
        }
        else {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Could not stat(): %s", path.data);
          return NGX_HTTP_INTERNAL_SERVER_ERROR;

        }
    }

    return ngx_http_next_header_filter(r);
}



static char * ngx_conf_set_etag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
   ngx_flag_t                        option_set;
   ngx_uint_t                        option_c;
   ngx_uint_t                        i;
   ngx_str_t                         *cur_option;
   ngx_str_t                         *value = cf->args->elts;
   etag_out                          *etag_out_format;
   ngx_http_static_etags_loc_conf_t  *loc_conf = conf;

   etag_out_format = ngx_pcalloc(cf->pool, sizeof(etag_out));
   if (etag_out_format == NULL) {
     return NGX_CONF_ERROR;
   }
   else {
     loc_conf->etag_options = etag_out_format;
   }

   loc_conf->etag_options = etag_out_format;

   option_c = cf->args->nelts;
     loc_conf->FileETag = 1;
   if (option_c == 1) {
     etag_out_format->Size = 1;
     etag_out_format->MTime = 1;
     etag_out_format->INode = 1;
   }
   else {
     for (i = 1 ; i < option_c ; i++) {
        cur_option = &value[i];
        if(ngx_strncmp(cur_option->data, "Size", 4) == 0) {
          option_set = 1;
          etag_out_format->Size = 1;
        }
        else if(ngx_strncmp(cur_option->data, "MTime", 5) == 0) {
          option_set = 1;
          etag_out_format->MTime = 1;
        }
        else if(ngx_strncmp(cur_option->data, "INode", 5) == 0) {
          option_set = 1;
          etag_out_format->INode = 1;
        }
        else if(ngx_strncmp(cur_option->data, "MD5", 3) == 0) {
          option_set = 1;
          etag_out_format->MD5 = 1;
        }

        else {
          ngx_log_error(NGX_LOG_ERR, cf->log, 0,
            "FileETag: '%s' is not a valid option.", cur_option->data);
          return NGX_CONF_ERROR;
        }
     }
   }

   return NGX_CONF_OK;
}

