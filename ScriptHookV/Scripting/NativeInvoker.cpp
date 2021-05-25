#include "NativeInvoker.h"
#include "ScriptEngine.h"
#include "..\Hooking\Hooking.h"
#include "..\Utility\Versioning.h"
#include "NativeHashMap.h"
#include <array>

uint64_t NativeInvoker::Helper::g_hash;
NativeArgStack NativeInvoker::Helper::g_Args;
NativeReturnStack NativeInvoker::Helper::g_Returns;
scrNativeCallContext NativeInvoker::Helper::g_context(&NativeInvoker::Helper::g_Returns, &NativeInvoker::Helper::g_Args);

void(*scrNativeCallContext::SetVectorResults)(scrNativeCallContext*) = "83 79 18 00 48 8B D1 74 4A FF 4A 18"_Scan.as<decltype(SetVectorResults)>();

#pragma pack(push)
#pragma pack(4)		// _unknown 4 bytes
// https://www.unknowncheats.me/forum/grand-theft-auto-v/144028-reversal-thread-81.html#post1931323
struct NativeRegistration {
	uint64_t nextRegBase;
	uint64_t nextRegKey;
	NativeHandler handlers[7];
	uint32_t numEntries1;
	uint32_t numEntries2;
	uint32_t _unknown;
	uint64_t hashes[7];

	/*
		// decryption
		key = this ^ nextRegKey  // only lower 32 bits
		nextReg = nextRegBase ^ key<<32 ^ key

		// encryption
		key = this ^ nextRegKey  // only lower 32 bits
		nextRegBase = nextReg ^ key<<32 ^ key
		
		only lower 32 bits of this^nextRegKey are used, higher 32 bits are ignored.
		thus, higher 32 bit of nexRegBase must contain the info of (masked) higher address of next registration.
		the first two members of struct are named as Base/Key respectively in that sense.
	*/
	inline NativeRegistration* getNextRegistration() {
		uint32_t key = static_cast<uint32_t>(reinterpret_cast<uint64_t>(this) ^ nextRegKey);
		return reinterpret_cast<NativeRegistration*>(nextRegBase ^ (static_cast<uint64_t>(key) << 32) ^ key);
	}

	inline void setNextRegistration(NativeRegistration* nextReg, uint64_t nextKey) {
		nextRegKey = nextKey;
		uint32_t key = static_cast<uint32_t>(reinterpret_cast<uint64_t>(this) ^ nextRegKey);
		nextRegBase = reinterpret_cast<uint64_t>(nextReg) ^ (static_cast<uint64_t>(key) << 32) ^ key;
	}

	inline uint32_t getNumEntries() {
		return static_cast<uint32_t>(reinterpret_cast<uint64_t>(&numEntries1)) ^ numEntries1 ^ numEntries2;
	}

	inline uint64_t getHash(uint32_t index) {
		uint32_t key = static_cast<uint32_t>(reinterpret_cast<uint64_t>(&hashes[2 * index]) ^ hashes[2 * index + 1]);
		return hashes[2 * index] ^ (static_cast<uint64_t>(key) << 32) ^ key;
	}
};
#pragma pack(pop)

static NativeRegistration ** registrationTable;
static std::unordered_map<uint64_t, NativeHandler> foundHashCache;
static int g_HashVersion = 0;

bool NativeInvoker::InitializeNativeRegistration()
{
	auto location = "4C 8D 05 ? ? ? ? 4D 8B 08 4D 85 C9 74 11"_Scan.add(9).as<uintptr_t>();
	if (!location) {
		LOG_ERROR("failed to find registrationTable");
		return false;
	}
	registrationTable = reinterpret_cast<decltype(registrationTable)>(location + *(int32_t*)location + 4);
	if (!registrationTable) {
		LOG_ERROR("failed to read registrationTable");
		return false;
	}
	static auto& versionTool = GTAVersion::GetInstance();
	g_HashVersion = versionTool.GameVersionToHashVersion(g_GameVersion);
	return true;
}

NativeHandler NativeInvoker::GetNativeHandler(uint64_t oldHash)
{
	if (g_IsRetail)
	{
		LOG_ERROR("retail currently does not support NativeInvoker::GetNativeHandler");
		return nullptr;
	}

	auto cachePair = foundHashCache.find(oldHash);
	if (cachePair != foundHashCache.end()) {
		return cachePair->second;
	}

	NativeHandler handler = nullptr;
	uint64_t newHash = GetNewHashFromOldHash( oldHash );

	if ( newHash == 0 ) {
		LOG_DEBUG("Failed to GetNewHashFromOldHash(%llX)", oldHash);
		handler = nullptr;
	} else {
		NativeRegistration* table = registrationTable[newHash & 0xFF];
		for (; table; table = table->getNextRegistration()) {
			bool found = false;
			for (uint32_t i = 0; i < table->getNumEntries(); i++) {
				if (newHash == table->getHash(i)) {
					handler = table->handlers[i];
					found = true;
					break;
				}
			}
			if (found) break;
		}
	}
	foundHashCache[oldHash] = handler;
	return handler;
}


uint64_t NativeInvoker::GetNewHashFromOldHash( uint64_t oldHash ) {

	if (g_HashVersion == 0) {
		// no need for conversion
		return oldHash;
	}

	// Algorithm Explained

	// natives.h uses constant oldHashes to represent functions. One oldHash is expected to be mapped to the same function in all game versions.
	// In order to use the same oldHash in all version of games, where hash of the same function changed from version to version,
	// Alexander Blade maintains a hashmap that stores a complete 2-D hash list version by version.

	// The oldHash is expected to be the oldest hash of a function, but in reality it may not exist at hashVer=0 or until latest, or may be even not the actual oldest hash.
	// That is why we need to search from the hashVer=0 to the latest.
	// Once we found the first occurrence of oldHash (of function Fn_i), we should locate the Fn_i line that stores hashes of different hashVers,
	// then search all the way down to the exact hashVersion of the running game.

	// optimized implementation
	// scan row by row at column 0. If nothing found, try column 1, etc
	// if firstly found old hash at (i,j), get the non-zero hash at (i, x) where x->searchDepth(as close as possible) && j<x<=searchDepth
	for (int i = 0; i < fullHashMapCount; i++) {
		for (int j = 0; j <= g_HashVersion; j++) {
			if (fullHashMap[i][j] == oldHash) {
				// found
				for(int k = g_HashVersion; k > j; k--) {		// search from latest hash to oldest hash. faster for the most cases
					uint64_t newHash = fullHashMap[i][k];
					if (newHash == 0)
						continue;
					return newHash;
				}
				// all 0 except the first one. No need for conversion
				return oldHash;
			}
		}
	}
	return 0;
}



DECLSPEC_NOINLINE void NativeInvoker::Helper::CallNative(scrNativeCallContext *cxt, uint64_t hash)
{
	if (auto handler = GetNativeHandler(hash))
	{
		handler(cxt);

		cxt->FixVectors();
	}
	else
	{
		static std::vector<uint64_t> failed;
		if (!Utility::DoesVectorContain(failed, hash))
		{
			LOG_ERROR("Failed to find native handler for 0x%016llX", hash);
			failed.push_back(hash);
		}
	}
}