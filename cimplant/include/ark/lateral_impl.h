#ifndef ARK_LATERAL_IMPL_H
#define ARK_LATERAL_IMPL_H

#include "ark/pb_modules.h"

/* Returns 1 if result buffer filled (success may still be 0). */
int ark_lateral_winrm(const ark_lateral_config *cfg, char *output, size_t output_cap, int *success);
int ark_lateral_psexec(const ark_lateral_config *cfg, char *output, size_t output_cap, int *success);
int ark_lateral_wmi(const ark_lateral_config *cfg, char *output, size_t output_cap, int *success);
int ark_lateral_dcom(const ark_lateral_config *cfg, char *output, size_t output_cap, int *success);

#endif
