#ifndef _AMAP_LIB_H
#define _AMAP_LIB_H

void amap_error(char *string, ...);
void amap_warn(char *string, ...);

amap_struct_responses *amap_lib_init(char *fn);
char **amap_lib_identify(char *data, int datalen, int proto, amap_struct_responses *response);

amap_struct_options *amap_main_init();
int amap_main(amap_struct_options *opt, int argc, char *argv[]);

#endif
