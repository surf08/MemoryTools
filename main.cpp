DWORD FindPattern(const char *module, const char *pattern, const char *mask)
{
	MODULEINFO mInfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), GetModuleHandle(module), &mInfo, sizeof(MODULEINFO));
	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	DWORD size = (DWORD)mInfo.SizeOfImage;
	DWORD patternLength = (DWORD)strlen(pattern);
	bool found;
	for (DWORD i = 0; i < size - patternLength; i++)
	{
		found = true;
		for (DWORD j = 0; j < patternLength; j++)
			found &= mask[j] == '?' || pattern[j] == *(char *)(base + i + j);
		if (found)
			return base + i;
	}
	return 0;
}

bool VMTHook(void *instance, void **origin, void *target, uintptr_t offset)
{
	uintptr_t vtable = *((uintptr_t *)instance) + sizeof(uintptr_t) * offset;
	*origin = (void *)(*((uintptr_t *)vtable));
	DWORD oldProtect;
	if (VirtualProtect((LPVOID)vtable, sizeof(vtable), PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		*((uintptr_t *)vtable) = (uintptr_t)target;
		if (VirtualProtect((LPVOID)vtable, sizeof(vtable), oldProtect, &oldProtect))
			return true;
	}
	return false;
}