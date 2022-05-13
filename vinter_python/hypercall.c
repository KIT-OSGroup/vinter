// This file is licensed under GNU General Public License, version 2, because it reuses code from PANDA (https://github.com/panda-re/panda).
// You should have received a copy of the GNU General Public License
// along with this software.  If not, see <http://www.gnu.org/licenses/>.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// according to intel manual:
// "No existing or future CPU will return processor identification or feature information if the initial EAX value
// is in the range 40000000H to 4FFFFFFFH."
#define CPUID_HYPERCALL_MAGIC 0x40000000

// based on https://github.com/panda-re/panda/blob/d2ee3d1bde15623813bcae1708eaa7d759cedd96/panda/plugins/recctrl/utils/recctrlu.c,
// we only support x64

static inline int hypercall(char* first, char* second) {
	int magic = CPUID_HYPERCALL_MAGIC;
	int ret = -1;

	asm __volatile__(
	"mov %1, %%eax \t\n\
	 mov %2, %%rbx \t\n\
	 mov %3, %%rcx \t\n\
	 cpuid \t\n\
	 mov %%eax, %0 \t\n\
	"
	: "=g"(ret) /* output operand */
	: "g" (magic), "g" (first), "g" (second) /* input operands */
	: "rax", "rbx", "rcx" /* clobbered registers */ // rax instead of eax because in panda we write the return value to rax (and not eax)
	);

	return ret;
}

int main(int argc, char** argv) {
	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: hypercall <type> [<content>]\n");
		return 1;
	}

	int ret = hypercall(argv[1], argc == 3 ? argv[2] : "");
	//printf("hypercall returned %d\n", ret);

	return ret;
}
