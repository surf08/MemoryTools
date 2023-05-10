#include <Windows.h>
#include <Psapi.h>

uintptr_t FindPattern(const char *module, const char *pattern, const char *mask)
{
	MODULEINFO mInfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(module), &mInfo, sizeof(MODULEINFO));
	uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
	uintptr_t size = (uintptr_t)mInfo.SizeOfImage;
	uintptr_t patternLength = (uintptr_t)strlen(pattern);
	bool found;
	for (uintptr_t i = 0; i < size - patternLength; i++)
	{
		found = true;
		for (uintptr_t j = 0; j < patternLength; j++)
			found &= mask[j] == '?' || pattern[j] == *(char *)(base + i + j);
		if (found)
			return base + i;
	}
	return 0;
}

bool VMTHook(void *instance, void **oldfunc, void *newfunc, uintptr_t offset)
{
	uintptr_t vtable = *((uintptr_t *)instance) + sizeof(uintptr_t) * offset;
	*oldfunc = (void *)(*((uintptr_t *)vtable));
	uintptr_t oldProtect;
	if (VirtualProtect((LPVOID)vtable, sizeof(vtable), PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		*((uintptr_t *)vtable) = (uintptr_t)newfunc;
		if (VirtualProtect((LPVOID)vtable, sizeof(vtable), oldProtect, &oldProtect))
			return true;
	}
	return false;
}