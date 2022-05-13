/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Samuel Kalbfleisch
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"

#include <cstdio>
#include <iostream>
#include <memory>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
bool init_plugin(void *);
void uninit_plugin(void *);
}

static hwaddr base;
static std::string path;
static void *self;

void before_block_exec(CPUState *env, TranslationBlock *tb) {
    // panda_in_kernel_code_linux doesn't work for my VM; maybe something to do with highmem configuration in the kernel's .config?
    /*
     * We wait for userspace to be booted (i.e. init to be run) before overwriting the physical memory.
     * I have noticed the following during the boot process with 134 MiB of RAM and trying to overwrite 5 MiB starting
     * at 128 MiB (with working memmap option to the kernel):
     * When overriding the physical memory in after_machine_init callback (or a little bit later), the memory is later
     * overridden presumably by qemu (maybe BIOS emulation or driver code?), as neither @panda.hook_phys_mem_write nor
     * PANDA_CB_MMIO_BEFORE_WRITE were able to catch these writes.
     */
    if (panda_in_kernel(env))
        return;
    panda_unregister_callbacks(self);

    std::FILE *file = std::fopen(path.c_str(), "r");
    if (file) {
        const std::size_t buf_size = 1048576; // 1 MiB
        const std::unique_ptr<uint8_t[]> buf(new uint8_t[buf_size]); // https://stackoverflow.com/a/35798248/1543768; on C++20, std::make_unique_default_init would be better
        std::size_t pos = 0;
        std::size_t nread;
        while ((nread = std::fread(buf.get(), 1, buf_size, file)) > 0) {
            LOG_DEBUG("writing to %" PRIu64, hwaddr(base + pos));
            if (panda_physical_memory_rw(base + pos, buf.get(), nread, true) != MEMTX_OK) {
                std::fclose(file);
                LOG_ERROR("error writing to memory, memory partially written");
                return;
            }
            pos += nread;
        }
        if (std::ferror(file)) { // "fread does not distinguish between end-of-file and error, and callers must use feof and ferror to determine which occurred." https://en.cppreference.com/w/c/io/fread
            std::fclose(file);
            LOG_ERROR("couldn't read file, memory partially written");
            return;
        }
        LOG_DEBUG("wrote until pos %" PRIu64, base + pos);
        std::fclose(file);
        LOG_INFO("successfully written file to memory");
    } else {
        LOG_ERROR("couldn't open file %s", path.c_str());
    }
}

bool init_plugin(void *self_) {
    self = self_;
    panda_arg_list *args = panda_get_args(PLUGIN_NAME);
    base = panda_parse_uint64(args, "base", 0);
    const char *path_cstr = panda_parse_string(args, "path", NULL);
    if (!path_cstr) {
        LOG_ERROR("path not given but required");
        return false;
    }
    path = std::string(path_cstr);
    panda_free_args(args);

    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    path.clear();
    path.shrink_to_fit(); // alternatively, use std::unique_ptr
}
