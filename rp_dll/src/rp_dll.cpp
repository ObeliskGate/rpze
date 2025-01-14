#include "SharedMemory.h"
#include "rp_dll.h"
#include "InsertHook.h"
#include "RpDllException.h"

void init(InitArgs args)
{
	DWORD tmp;
	VirtualProtect(reinterpret_cast<void*>(0x400000), 
		0x394000, 
		PAGE_EXECUTE_READWRITE,
		&tmp);

	FILE* _;
	if (args == 1)
	{
		AllocConsole();
		freopen_s(&_, "CONOUT$", "w", stdout);
		freopen_s(&_, "CONOUT$", "w", stderr);
		freopen_s(&_, "CONIN$", "r", stdin);
		std::ios::sync_with_stdio();
		std::println("console set");
	}
	else
	{
		if (freopen_s(&_, ERR_FILE_NAME, "w", stderr))
		{
			MessageBoxA(nullptr, "failed to set error log file", "rp_dll", MB_OK);
			dllExit();
			std::terminate();
		}
		std::ios::sync_with_stdio();
		std::println(std::cerr, "error log file set");
	}
	SharedMemory::getInstance();
	MH_Initialize();
}

void doAsPhaseCode(volatile PhaseCode& phaseCode, const SharedMemory* pSharedMemory)
{
	while (true)
	{
		switch (phaseCode)
		{
		case PhaseCode::CONTINUE:
			return;
		case PhaseCode::WAIT:
			while (phaseCode == PhaseCode::WAIT) {}
			continue;
		case PhaseCode::RUN_CODE:
			{
#ifndef NDEBUG
				std::println("start run code");
#endif
				auto p = std::bit_cast<void(*)()>(pSharedMemory->shm().getAsmBuffer<>());
				p();
				pSharedMemory->shm().executeResult = ExecuteResult::SUCCESS;
				phaseCode = PhaseCode::WAIT;
#ifndef NDEBUG
				std::println("run code success");
#endif
				continue;
			}
		case PhaseCode::JUMP_FRAME:
			if (pSharedMemory->shm().syncMethod == SyncMethod::MUTEX &&
				pSharedMemory->shm().jumpingSyncMethod == SyncMethod::MUTEX)
				pSharedMemory->waitMutex();
			doWhenJmpFrame(phaseCode);
			if (pSharedMemory->shm().syncMethod == SyncMethod::MUTEX &&
				pSharedMemory->shm().jumpingSyncMethod == SyncMethod::MUTEX)
				pSharedMemory->releaseMutex();
#ifndef NDEBUG
			std::println("end jmp frame");
#endif

			continue;
		case PhaseCode::READ_MEMORY:
#ifndef NDEBUG
			std::println("read memory");
#endif
			pSharedMemory->readMemory();
			phaseCode = PhaseCode::WAIT;
#ifndef NDEBUG
			std::println("read memory success");
#endif
			continue;
		case PhaseCode::WRITE_MEMORY:
			pSharedMemory->writeMemory();
			phaseCode = PhaseCode::WAIT;
			continue;

		case PhaseCode::READ_MEMORY_PTR:
			{
#ifndef NDEBUG
				std::println("read memory ptr");
#endif
				*pSharedMemory->shm().getReadWriteBuffer<uint32_t>() = 
					reinterpret_cast<uint32_t>(&pSharedMemory->shm());
				pSharedMemory->shm().executeResult = ExecuteResult::SUCCESS;
				phaseCode = PhaseCode::WAIT;
				continue;
			}
		}
	}
}

void doWhenJmpFrame(volatile PhaseCode& phaseCode)
{
	auto pSharedMemory = SharedMemory::getInstance();
	while (phaseCode == PhaseCode::JUMP_FRAME)
	{
		mainHook<1>(pSharedMemory);
		__asm
		{
			mov edi, ds:[0x6a9ec0]
			inc dword ptr [edi + 0x838] // mjClock++
			mov esi, [edi + 0x768]
			mov edx, 0x41BAD0 // Board::ProcessDeleteQueue
			call edx
			mov ecx, esi
			mov edx, [esi]
			call [edx + 0x58] // Board::Update
			mov esi, edi
			push dword ptr [esi + 0x820]
			mov edx, 0x445680 // EffectSystem::ProcessDeleteQueue
			call edx
			mov eax, esi
			mov edx, 0x4524F0 // LawnApp::CheckForGameEnd
			call edx
		}
		if (!(time(nullptr) % 5))
		{
			MSG msg;
			while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}
}

bool closableHook(const SharedMemory* pSharedMemory, HookPosition hook)
{
	return (pSharedMemory->shm().globalState == HookState::NOT_CONNECTED ||
		pSharedMemory->shm().hookStateArr[getHookIndex(hook)] == HookState::NOT_CONNECTED);
}

static void* pTrampoline = nullptr;
void __fastcall hookUpdateApp(DWORD lawnAppAddr)
{
	try 
	{
		auto p = std::bit_cast<decltype(&hookUpdateApp)>(pTrampoline);
		p(lawnAppAddr);
	} 
	catch (const std::exception& e) 
	{
		auto& shm = SharedMemory::getInstance()->shm();
		shm.error = ShmError::CAUGHT_CPP_EXCEPTION;
		std::string str;
		if (auto p = dynamic_cast<const RpDllBaseException*>(&e))
			str = p->whatWhenNotCaught();
		else
			str = printStlException(e);
		std::println(std::cerr, "Uncaught exception: {}", str);
		auto copySize = std::min(str.size(), Shm::BUFFER_SIZE - 1) + 1; // for \0
		memcpy(const_cast<char*>(shm.getReadWriteBuffer<char>()), str.c_str(), copySize);
 		dllExit();
		std::terminate();
	}
}

void initInThread(const SharedMemory* pSharedMemory)
{
	pSharedMemory->waitMutex();
#ifndef NDEBUG
	std::println("start init");
#endif

	auto pUpdateApp = readMemory<void*>(0x6a9ec0, 0x0, 0x180).value();
	if (MH_CreateHook(pUpdateApp, 
			reinterpret_cast<void*>(&hookUpdateApp), &pTrampoline) != MH_OK)
		throw std::runtime_error("LawnApp::UpdateApp create hook failed");
	
	if (MH_EnableHook(pUpdateApp) != MH_OK)
		throw std::runtime_error("LawnApp::UpdateApp enable hook failed");
	
#ifndef NDEBUG
	std::println("LawnApp::UpdateApp hooked, trampoline: {}", pTrampoline);
#endif
	InsertHook::addInsert(reinterpret_cast<void*>(0x407b52), 
	[pSharedMemory](const HookContext& reg) // Board::Board
	{
		pSharedMemory->shm().isBoardPtrValid = false;
		pSharedMemory->shm().boardPtr = *reinterpret_cast<uint32_t*>(reg.esp + 8); // stack is (... pBoard rta -1) now	
	});
InsertHook::addReplace(reinterpret_cast<void*>(0x42B8B0), reinterpret_cast<void*>(0x42b967),
	[pSharedMemory](const HookContext&) -> std::optional<uint32_t>
	{
		if (closableHook(pSharedMemory, HookPosition::CHALLENGE_I_ZOMBIE_SCORE_BRAIN))
			return {};
		return 0;
	});
InsertHook::addReplace(reinterpret_cast<void*>(0x42A6C0), reinterpret_cast<void*>(0x42a889),
	[pSharedMemory](const HookContext&) -> std::optional<uint32_t>
	{
		if (closableHook(pSharedMemory, HookPosition::CHALLENGE_I_ZOMBIE_PLACE_PLANTS))
			return {};
		return 0;
	});

InsertHook::addInsert(reinterpret_cast<void*>(0x5A4760), 
[pSharedMemory](HookContext&)
	{
		pSharedMemory->shm().error = ShmError::CAUGHT_SEH;
		dllExit();
	});
#ifndef NDEBUG
InsertHook::addInsert(reinterpret_cast<void*>(0x420150),
	[](HookContext& reg)
	{
		throw RpDllException("test at dll");
	});
#endif

}

void dllExit()
{
	fclose(stderr);
	SharedMemory::deleteInstance();
	InsertHook::deleteAll();
	MH_Uninitialize();
}

