#ifndef _LINUX_EXTFUSE_H
#define _LINUX_EXTFUSE_H

typedef enum {
        OPCODE = 0,
        NODEID,
        NUM_IN_ARGS,
        NUM_OUT_ARGS,
        IN_PARAM_0_SIZE,
        IN_PARAM_0_VALUE,
        IN_PARAM_1_SIZE,
        IN_PARAM_1_VALUE,
        IN_PARAM_2_SIZE,
        IN_PARAM_2_VALUE,
        OUT_PARAM_0,
        OUT_PARAM_1,
} extfuse_arg_t;

#endif /* _LINUX_EXTFUSE_H */
