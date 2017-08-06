#include <stdio.h>

int main (int argc, char *argv[])
{
	long eax=1,ebx=2;

	__asm__("nop;nop;nop");

	__asm__ __volatile__ ("add %0,%2"
		: "=b"((long)ebx)
		: "a"((long)eax), "q"(ebx)
		: "2"
	);

	__asm__("nop;nop;nop");

	printf("ebx=%x\n", ebx);

	return 0;
}
